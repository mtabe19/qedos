//! Single-threaded epoll (mio) event loop.
//!
//! Each client connection is a state machine:
//!
//! ```text
//! Handshake -> ReadHead -> (Exchange | Flush) -> ReadHead ...
//! ```
//!
//! Backpressure: the client-bound buffer (`out`) and the backend-bound buffer
//! (`up_out`) are capped at [`CAP`]; a side is only read while the opposite
//! buffer has room, so a slow client throttles the backend (SSE-safe).
//!
//! Edge-triggered epoll: `drive` loops until no step makes progress, and
//! connections that exhaust their per-event work budget are re-queued, so no
//! wake-up can be lost.

use crate::config::Config;
use crate::tls;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use openssl::ssl::{ErrorCode, HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslStream};
use pg_http::{
    parse_request, parse_response, reason_phrase, ChunkDecoder, ChunkError, Framing, Method, ParseError, Request,
    MAX_HEAD_BYTES,
};
use pg_policy::{decide, Decision};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Cap on each direction's in-flight buffer.
const CAP: usize = 64 * 1024;
const READ_CHUNK: usize = 16 * 1024;
const WORK_BUDGET: u32 = 64;
const LISTENER: Token = Token(0);

#[derive(Debug)]
pub struct End(pub &'static str);

type R<T> = Result<T, End>;

#[derive(Default, Clone)]
pub struct Metrics {
    pub accepted: u64,
    pub rejected_cap: u64,
    pub active: u64,
    pub tls_established: u64,
    pub hs_ok: u64,
    pub hs_fail: u64,
    pub policy_violations: u64,
    pub requests: u64,
    pub fwd: u64,
    pub local: u64,
    pub rejects: u64,
    pub backend_fail: u64,
}

pub struct Shared {
    pub cfg: Config,
    pub ssl_ctx: SslContext,
    pub registry: Registry,
    pub m: Metrics,
    pub now: Instant,
    pub access_log: bool,
    pub tls_log: bool,
    requeue: Vec<usize>,
}

enum Tls {
    /// TCP accepted, no byte seen yet: no OpenSSL state is allocated.
    Pending(Option<TcpStream>),
    Handshake(Option<MidHandshakeSslStream<TcpStream>>),
    Ready(SslStream<TcpStream>),
}

enum Phase {
    Handshake,
    ReadHead,
    Exchange(Box<Exchange>),
    /// Writing a locally generated response, then close or go back to ReadHead.
    Flush { close: bool },
}

enum ReqBody {
    Done,
    Length(u64),
    Chunked(ChunkDecoder),
}

enum Resp {
    Head(Vec<u8>),
    Length(u64),
    Chunked(ChunkDecoder),
    UntilClose,
    Done,
}

struct Exchange {
    up: TcpStream,
    connected: bool,
    up_out: Vec<u8>,
    req: ReqBody,
    resp: Resp,
    head_request: bool,
    client_ka: bool,
    head_sent: bool,
    reusable: bool,
    status: u16,
    log_line: Option<String>,
}

pub struct Conn {
    id: u64,
    slot: usize,
    peer: SocketAddr,
    tls: Tls,
    phase: Phase,
    rbuf: Vec<u8>,
    out: Vec<u8>,
    last: Instant,
    group: &'static str,
    /// True once `tls_established` was incremented for this connection.
    counted: bool,
}

enum Rd {
    Data(usize),
    Block,
    Eof,
}

fn tls_read(s: &mut SslStream<TcpStream>, buf: &mut [u8]) -> R<Rd> {
    match s.ssl_read(buf) {
        Ok(0) => Ok(Rd::Eof),
        Ok(n) => Ok(Rd::Data(n)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Ok(Rd::Block),
            ErrorCode::ZERO_RETURN => Ok(Rd::Eof),
            ErrorCode::SYSCALL if e.io_error().is_none() => Ok(Rd::Eof),
            _ => Err(End("tls read error")),
        },
    }
}

fn tcp_read(s: &mut TcpStream, buf: &mut [u8]) -> R<Rd> {
    loop {
        match s.read(buf) {
            Ok(0) => return Ok(Rd::Eof),
            Ok(n) => return Ok(Rd::Data(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Rd::Block),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(End("backend read error")),
        }
    }
}

fn is_hop(name: &[u8]) -> bool {
    const HOP: [&[u8]; 10] = [
        b"connection", b"keep-alive", b"proxy-connection", b"proxy-authenticate", b"proxy-authorization",
        b"te", b"trailer", b"upgrade", b"transfer-encoding", b"content-length",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

fn drop_on_request(name: &[u8]) -> bool {
    is_hop(name)
        || name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"expect")
        || name.eq_ignore_ascii_case(b"forwarded")
        || name.eq_ignore_ascii_case(b"x-real-ip")
        || name.eq_ignore_ascii_case(b"via")
        || (name.len() >= 12 && name[..12].eq_ignore_ascii_case(b"x-forwarded-"))
}

fn drop_on_response(name: &[u8]) -> bool {
    is_hop(name)
        || name.eq_ignore_ascii_case(b"server")
        || name.eq_ignore_ascii_case(b"strict-transport-security")
        || name.eq_ignore_ascii_case(b"x-content-type-options")
}

const SEC_HEADERS: &str = "Strict-Transport-Security: max-age=63072000\r\nX-Content-Type-Options: nosniff\r\n";

impl Conn {
    pub fn new(sh: &mut Shared, id: u64, slot: usize, peer: SocketAddr, tcp: TcpStream) -> Conn {
        Conn {
            id,
            slot,
            peer,
            tls: Tls::Pending(Some(tcp)),
            phase: Phase::Handshake,
            rbuf: Vec::new(),
            out: Vec::new(),
            last: sh.now,
            group: "",
            counted: false,
        }
    }

    pub fn is_counted(&self) -> bool {
        self.counted
    }

    fn touch(&mut self, sh: &Shared) {
        self.last = sh.now;
    }

    fn timeout(&self, cfg: &Config) -> Duration {
        let s = match &self.phase {
            Phase::Handshake => cfg.t_handshake,
            Phase::ReadHead => {
                if self.rbuf.is_empty() {
                    cfg.t_idle
                } else {
                    cfg.t_head
                }
            }
            Phase::Flush { .. } => cfg.t_head,
            Phase::Exchange(ex) => {
                if ex.head_sent {
                    cfg.t_response_idle
                } else if !ex.connected {
                    cfg.t_backend_connect
                } else if !matches!(ex.req, ReqBody::Done) {
                    cfg.t_head
                } else {
                    cfg.t_response_idle
                }
            }
        };
        Duration::from_secs(s)
    }

    pub fn expired(&self, sh: &Shared) -> bool {
        sh.now.duration_since(self.last) > self.timeout(&sh.cfg)
    }

    pub fn on_timeout(&mut self, sh: &mut Shared) -> R<()> {
        if let Phase::Exchange(ex) = &self.phase {
            if !ex.head_sent {
                let status = 504;
                self.fail_exchange(sh, status)?;
                return self.drive(sh);
            }
        }
        Err(End("timeout"))
    }

    // ---------------------------------------------------------------- drive

    pub fn drive(&mut self, sh: &mut Shared) -> R<()> {
        for _ in 0..WORK_BUDGET {
            let mut prog = self.flush_out()?;
            prog |= match self.phase {
                Phase::Handshake => self.step_handshake(sh)?,
                Phase::ReadHead => self.step_read_head(sh)?,
                Phase::Exchange(_) => self.step_exchange(sh)?,
                Phase::Flush { close } => {
                    if self.out.is_empty() {
                        if close {
                            return Err(End("done"));
                        }
                        self.phase = Phase::ReadHead;
                        self.touch(sh);
                        true
                    } else {
                        false
                    }
                }
            };
            if prog {
                self.touch(sh);
            } else {
                return Ok(());
            }
        }
        sh.requeue.push(self.slot);
        Ok(())
    }

    fn flush_out(&mut self) -> R<bool> {
        let s = match &mut self.tls {
            Tls::Ready(s) => s,
            _ => return Ok(false),
        };
        let mut prog = false;
        while !self.out.is_empty() {
            match s.ssl_write(&self.out) {
                Ok(n) => {
                    self.out.drain(..n);
                    prog = true;
                }
                Err(e) => match e.code() {
                    ErrorCode::WANT_WRITE | ErrorCode::WANT_READ => break,
                    _ => return Err(End("tls write error")),
                },
            }
        }
        if self.out.is_empty() && self.out.capacity() > 4 * CAP {
            self.out = Vec::new();
        }
        Ok(prog)
    }

    fn read_client(&mut self, buf: &mut [u8]) -> R<Rd> {
        match &mut self.tls {
            Tls::Ready(s) => tls_read(s, buf),
            _ => Ok(Rd::Block),
        }
    }

    // ------------------------------------------------------------ handshake

    fn step_handshake(&mut self, sh: &mut Shared) -> R<bool> {
        let result = match &mut self.tls {
            Tls::Pending(t) => {
                // Do not allocate TLS state until the peer has sent something.
                let tcp = t.as_mut().ok_or(End("handshake state"))?;
                let mut b = [0u8; 1];
                match tcp.peek(&mut b) {
                    Ok(0) => return Err(End("closed before handshake")),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(true),
                    Err(_) => return Err(End("socket error before handshake")),
                }
                let tcp = t.take().ok_or(End("handshake state"))?;
                let ssl = Ssl::new(&sh.ssl_ctx).map_err(|_| End("ssl new"))?;
                // NB: a complete handshake can finish inside this very call
                // (client Finished already queued); handled like any other.
                ssl.accept(tcp)
            }
            Tls::Handshake(m) => m.take().ok_or(End("handshake state"))?.handshake(),
            _ => return Ok(false),
        };
        match result {
            Ok(s) => {
                let group = tls::negotiated_group(s.ssl());
                let version = s.ssl().version_str();
                let cipher = s.ssl().current_cipher().map(|c| c.name().to_string());
                // Defence in depth for LAW_002/LAW_003: the TLS config already
                // forbids anything else, but we re-verify what was *actually*
                // negotiated before any application data is processed.
                let ok = group.as_deref() == Some(tls::REQUIRED_GROUP)
                    && version == "TLSv1.3"
                    && cipher.as_deref() == Some(tls::REQUIRED_CIPHER);
                if !ok {
                    sh.m.policy_violations += 1;
                    eprintln!("POLICY_VIOLATION id={} group={:?} version={} cipher={:?}", self.id, group, version, cipher);
                    return Err(End("negotiated parameters violate policy"));
                }
                self.group = tls::REQUIRED_GROUP;
                if sh.tls_log {
                    eprintln!(
                        "TLS id={} peer={} version={} cipher={} group={} resumed={}",
                        self.id,
                        self.peer,
                        version,
                        cipher.as_deref().unwrap_or("?"),
                        self.group,
                        s.ssl().session_reused()
                    );
                }
                sh.m.hs_ok += 1;
                sh.m.tls_established += 1;
                self.counted = true;
                self.tls = Tls::Ready(s);
                self.phase = Phase::ReadHead;
                Ok(true)
            }
            Err(HandshakeError::WouldBlock(m)) => {
                self.tls = Tls::Handshake(Some(m));
                Ok(false)
            }
            Err(HandshakeError::Failure(m)) => {
                sh.m.hs_fail += 1;
                if sh.tls_log {
                    eprintln!("TLS_FAIL id={} peer={} err={}", self.id, self.peer, m.error());
                }
                Err(End("tls handshake failure"))
            }
            Err(HandshakeError::SetupFailure(_)) => {
                sh.m.hs_fail += 1;
                Err(End("tls setup failure"))
            }
        }
    }

    // ------------------------------------------------------------- read head

    fn step_read_head(&mut self, sh: &mut Shared) -> R<bool> {
        let mut prog = false;
        let mut tmp = [0u8; 4096];
        loop {
            if !self.rbuf.is_empty() {
                match parse_request(&self.rbuf) {
                    Ok(None) => {}
                    Ok(Some(req)) => {
                        self.dispatch(sh, req)?;
                        return Ok(true);
                    }
                    Err(e) => {
                        self.reject_parse(sh, e);
                        return Ok(true);
                    }
                }
            }
            match self.read_client(&mut tmp)? {
                Rd::Data(n) => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    prog = true;
                }
                Rd::Block => return Ok(prog),
                Rd::Eof => return Err(End("client closed")),
            }
        }
    }

    fn reject_parse(&mut self, sh: &mut Shared, e: ParseError) {
        sh.m.rejects += 1;
        if sh.access_log {
            eprintln!("ACCESS id={} peer={} group={} parse_error={:?} status={}", self.id, self.peer, self.group, e, e.status());
        }
        self.rbuf = Vec::new();
        self.respond_local(sh, e.status(), "text/plain", None, true, false);
    }

    /// Queue a locally generated response and move to `Flush`.
    fn respond_local(&mut self, _sh: &mut Shared, status: u16, ctype: &str, body: Option<&[u8]>, close: bool, head_only: bool) {
        let default_body;
        let body: &[u8] = match body {
            Some(b) => b,
            None => {
                default_body = format!("{} {}\n", status, reason_phrase(status));
                default_body.as_bytes()
            }
        };
        let mut h = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}",
            status,
            reason_phrase(status),
            ctype,
            body.len(),
            SEC_HEADERS
        );
        if close {
            h.push_str("Connection: close\r\n");
        }
        h.push_str("\r\n");
        self.out.extend_from_slice(h.as_bytes());
        if !head_only {
            self.out.extend_from_slice(body);
        }
        self.phase = Phase::Flush { close };
    }

    fn dispatch(&mut self, sh: &mut Shared, req: Request) -> R<()> {
        sh.m.requests += 1;
        let target = req.target.slice(&self.rbuf).to_vec();
        let has_body = !matches!(req.framing, Framing::None);
        let head_only = req.method == Method::Head;
        let log_path = {
            let p = target.split(|&b| b == b'?').next().unwrap_or(&[]);
            String::from_utf8_lossy(&p[..p.len().min(200)]).into_owned()
        };
        let decision = decide(&sh.cfg.routes, req.method, &target);
        let close_after = !req.keep_alive || has_body;
        match decision {
            Decision::Reject(status) => {
                sh.m.rejects += 1;
                if sh.access_log {
                    eprintln!("ACCESS id={} peer={} group={} {} {} -> {} (policy)", self.id, self.peer, self.group, req.method.as_str(), log_path, status);
                }
                self.rbuf.drain(..req.head_len);
                self.respond_local(sh, status, "text/plain", None, close_after || status == 400, head_only);
            }
            Decision::Health => {
                sh.m.local += 1;
                if sh.access_log {
                    eprintln!("ACCESS id={} peer={} group={} {} {} -> 200 (local)", self.id, self.peer, self.group, req.method.as_str(), log_path);
                }
                self.rbuf.drain(..req.head_len);
                self.respond_local(sh, 200, "application/json", Some(b"{\"status\":\"ok\"}\n"), close_after, head_only);
            }
            Decision::Forward { backend, max_body } => {
                let too_big = match req.framing {
                    Framing::Length(n) => n > max_body,
                    Framing::Chunked => max_body == 0,
                    _ => false,
                };
                if too_big {
                    sh.m.rejects += 1;
                    self.rbuf.drain(..req.head_len);
                    self.respond_local(sh, 413, "text/plain", None, true, head_only);
                    return Ok(());
                }
                let be = &sh.cfg.backends[backend.0 as usize];
                let mut up = match TcpStream::connect(be.addr) {
                    Ok(s) => s,
                    Err(_) => {
                        sh.m.backend_fail += 1;
                        self.rbuf.drain(..req.head_len);
                        self.respond_local(sh, 502, "text/plain", None, true, head_only);
                        return Ok(());
                    }
                };
                let _ = up.set_nodelay(true);
                if sh.registry.register(&mut up, Token((self.slot + 1) * 2 + 1), Interest::READABLE | Interest::WRITABLE).is_err() {
                    sh.m.backend_fail += 1;
                    self.rbuf.drain(..req.head_len);
                    self.respond_local(sh, 502, "text/plain", None, true, head_only);
                    return Ok(());
                }
                // ---- build upstream head (only validated, re-serialised fields)
                let mut h: Vec<u8> = Vec::with_capacity(512);
                let _ = write!(
                    h,
                    "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nX-Forwarded-For: {}\r\nX-Forwarded-Proto: https\r\n",
                    req.method.as_str(),
                    String::from_utf8_lossy(&target),
                    be.host_header,
                    self.peer.ip()
                );
                for hd in req.headers() {
                    let name = hd.name.slice(&self.rbuf);
                    if drop_on_request(name) {
                        continue;
                    }
                    h.extend_from_slice(name);
                    h.extend_from_slice(b": ");
                    h.extend_from_slice(hd.value.slice(&self.rbuf));
                    h.extend_from_slice(b"\r\n");
                }
                let req_body = match req.framing {
                    Framing::Length(n) => {
                        let _ = write!(h, "Content-Length: {}\r\n", n);
                        ReqBody::Length(n)
                    }
                    Framing::Chunked => {
                        h.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                        ReqBody::Chunked(ChunkDecoder::new(max_body))
                    }
                    _ => {
                        if matches!(req.method, Method::Post | Method::Put | Method::Patch) {
                            h.extend_from_slice(b"Content-Length: 0\r\n");
                        }
                        ReqBody::Done
                    }
                };
                h.extend_from_slice(b"\r\n");
                self.rbuf.drain(..req.head_len);
                sh.m.fwd += 1;
                let log_line = if sh.access_log {
                    Some(format!("id={} peer={} group={} {} {}", self.id, self.peer, self.group, req.method.as_str(), log_path))
                } else {
                    None
                };
                self.phase = Phase::Exchange(Box::new(Exchange {
                    up,
                    connected: false,
                    up_out: h,
                    req: req_body,
                    resp: Resp::Head(Vec::new()),
                    head_request: head_only,
                    client_ka: req.keep_alive,
                    head_sent: false,
                    reusable: false,
                    status: 0,
                    log_line,
                }));
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- exchange

    fn fail_exchange(&mut self, sh: &mut Shared, status: u16) -> R<()> {
        sh.m.backend_fail += 1;
        let (sent, head_only) = match &self.phase {
            Phase::Exchange(ex) => (ex.head_sent, ex.head_request),
            _ => return Ok(()),
        };
        if sent {
            return Err(End("backend aborted mid-response"));
        }
        self.phase = Phase::Flush { close: true }; // drops Exchange (closes backend socket)
        self.respond_local(sh, status, "text/plain", None, true, head_only);
        Ok(())
    }

    fn step_exchange(&mut self, sh: &mut Shared) -> R<bool> {
        let mut prog = false;
        // Take the exchange out so `self` methods stay usable.
        let mut ex = match std::mem::replace(&mut self.phase, Phase::ReadHead) {
            Phase::Exchange(ex) => ex,
            other => {
                self.phase = other;
                return Ok(false);
            }
        };
        let r = self.step_exchange_inner(sh, &mut ex, &mut prog);
        match r {
            Ok(Some(status)) => {
                // Exchange failed before the response head was sent.
                self.phase = Phase::Exchange(ex);
                self.fail_exchange(sh, status)?;
                Ok(true)
            }
            Ok(None) => {
                if matches!(ex.resp, Resp::Done) {
                    let reusable = ex.reusable && matches!(ex.req, ReqBody::Done);
                    if let Some(l) = &ex.log_line {
                        eprintln!("ACCESS {} -> {}", l, ex.status);
                    }
                    // dropping `ex` closes the backend socket
                    self.phase = Phase::Flush { close: !reusable };
                    return Ok(true);
                }
                self.phase = Phase::Exchange(ex);
                Ok(prog)
            }
            Err(e) => Err(e),
        }
    }

    /// Returns `Ok(Some(status))` to ask for a local error response,
    /// `Ok(None)` when the exchange continues or completed.
    fn step_exchange_inner(&mut self, _sh: &mut Shared, ex: &mut Exchange, prog: &mut bool) -> R<Option<u16>> {
        // ---- A. connect completion + flush request bytes upstream
        if !ex.connected {
            match ex.up.take_error() {
                Ok(None) => {}
                _ => return Ok(Some(502)),
            }
            match ex.up.peer_addr() {
                Ok(_) => {
                    ex.connected = true;
                    *prog = true;
                }
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
                Err(_) => return Ok(Some(502)),
            }
        }
        if ex.connected {
            while !ex.up_out.is_empty() {
                match ex.up.write(&ex.up_out) {
                    Ok(0) => return Ok(Some(502)),
                    Ok(n) => {
                        ex.up_out.drain(..n);
                        *prog = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(Some(502)),
                }
            }
            if ex.up_out.is_empty() && ex.up_out.capacity() > 4 * CAP {
                ex.up_out = Vec::new();
            }
        }

        // ---- B. pull the request body from the client
        let mut tmp = [0u8; READ_CHUNK];
        while !matches!(ex.req, ReqBody::Done) && ex.up_out.len() < CAP {
            if self.rbuf.is_empty() {
                match self.read_client(&mut tmp)? {
                    Rd::Data(n) => self.rbuf.extend_from_slice(&tmp[..n]),
                    Rd::Block => break,
                    Rd::Eof => return Err(End("client closed during request body")),
                }
            }
            *prog = true;
            match &mut ex.req {
                ReqBody::Length(left) => {
                    let n = (*left).min(self.rbuf.len() as u64) as usize;
                    ex.up_out.extend_from_slice(&self.rbuf[..n]);
                    self.rbuf.drain(..n);
                    *left -= n as u64;
                    if *left == 0 {
                        ex.req = ReqBody::Done;
                    }
                }
                ReqBody::Chunked(dec) => match dec.advance(&self.rbuf) {
                    Ok(a) => {
                        if let Some(sp) = a.data {
                            if !sp.is_empty() {
                                let _ = write!(ex.up_out, "{:x}\r\n", sp.len());
                                ex.up_out.extend_from_slice(sp.slice(&self.rbuf));
                                ex.up_out.extend_from_slice(b"\r\n");
                            }
                        }
                        self.rbuf.drain(..a.consumed);
                        if a.done {
                            ex.up_out.extend_from_slice(b"0\r\n\r\n");
                            ex.req = ReqBody::Done;
                        }
                    }
                    Err(ChunkError::TooLarge) => {
                        return if ex.head_sent { Err(End("request body too large")) } else { Ok(Some(413)) };
                    }
                    Err(_) => return if ex.head_sent { Err(End("bad chunked body")) } else { Ok(Some(400)) },
                },
                ReqBody::Done => {}
            }
        }

        // ---- C. pull the response from the backend
        if ex.connected && !matches!(ex.resp, Resp::Done) {
            while self.out.len() < CAP {
                let room = (CAP - self.out.len()).clamp(1, READ_CHUNK);
                let rd = tcp_read(&mut ex.up, &mut tmp[..room])?;
                match rd {
                    Rd::Block => break,
                    Rd::Eof => {
                        *prog = true;
                        match &ex.resp {
                            Resp::Head(_) => return Ok(Some(502)),
                            Resp::UntilClose => {
                                ex.resp = Resp::Done;
                            }
                            Resp::Done => {}
                            _ => return Err(End("backend truncated response")),
                        }
                        break;
                    }
                    Rd::Data(n) => {
                        *prog = true;
                        let data = &tmp[..n];
                        if let Resp::Head(hb) = &mut ex.resp {
                            hb.extend_from_slice(data);
                            let parsed = match parse_response(hb, ex.head_request) {
                                Ok(None) => continue,
                                Ok(Some(r)) => r,
                                Err(_) => return Ok(Some(502)),
                            };
                            let (mut head, resp_head_len) = (Vec::with_capacity(512), parsed.head_len);
                            let _ = write!(head, "HTTP/1.1 {} {}\r\n", parsed.status, reason_phrase(parsed.status));
                            for hd in parsed.headers() {
                                let name = hd.name.slice(hb);
                                if drop_on_response(name) && !(ex.head_request && name.eq_ignore_ascii_case(b"content-length")) {
                                    continue;
                                }
                                head.extend_from_slice(name);
                                head.extend_from_slice(b": ");
                                head.extend_from_slice(hd.value.slice(hb));
                                head.extend_from_slice(b"\r\n");
                            }
                            match parsed.framing {
                                Framing::Length(n) => {
                                    let _ = write!(head, "Content-Length: {}\r\n", n);
                                }
                                Framing::Chunked => head.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
                                Framing::None => {
                                    if !ex.head_request && parsed.status != 204 && parsed.status != 304 {
                                        head.extend_from_slice(b"Content-Length: 0\r\n");
                                    }
                                }
                                Framing::UntilClose => {}
                            }
                            head.extend_from_slice(SEC_HEADERS.as_bytes());
                            let can_ka = ex.client_ka && parsed.framing != Framing::UntilClose;
                            if !can_ka {
                                head.extend_from_slice(b"Connection: close\r\n");
                            }
                            head.extend_from_slice(b"\r\n");
                            self.out.extend_from_slice(&head);
                            ex.head_sent = true;
                            ex.reusable = can_ka;
                            ex.status = parsed.status;
                            let leftover: Vec<u8> = hb[resp_head_len..].to_vec();
                            ex.resp = match parsed.framing {
                                Framing::None => Resp::Done,
                                Framing::Length(n) => Resp::Length(n),
                                Framing::Chunked => Resp::Chunked(ChunkDecoder::new(u64::MAX)),
                                Framing::UntilClose => Resp::UntilClose,
                            };
                            resp_feed(&mut ex.resp, &mut self.out, &leftover)?;
                        } else {
                            resp_feed(&mut ex.resp, &mut self.out, data)?;
                        }
                        if matches!(ex.resp, Resp::Done) {
                            break;
                        }
                    }
                }
            }
        }

        // ---- D. watch the client for pipelined bytes / disconnect while the
        //         response is in flight (needed to stop SSE when the client goes).
        if matches!(ex.req, ReqBody::Done) && !matches!(ex.resp, Resp::Done) && self.rbuf.len() < MAX_HEAD_BYTES {
            match self.read_client(&mut tmp[..4096])? {
                Rd::Data(n) => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    *prog = true;
                }
                Rd::Block => {}
                Rd::Eof => return Err(End("client closed during response")),
            }
        }
        Ok(None)
    }
}

/// Feed backend bytes through the response framing, appending the bytes that
/// belong to this message (raw, framing included) to `out`.
fn resp_feed(resp: &mut Resp, out: &mut Vec<u8>, data: &[u8]) -> R<()> {
    match resp {
        Resp::Length(left) => {
            let n = (*left).min(data.len() as u64) as usize;
            out.extend_from_slice(&data[..n]);
            *left -= n as u64;
            if *left == 0 {
                *resp = Resp::Done;
            }
        }
        Resp::Chunked(dec) => {
            let mut off = 0;
            while off < data.len() {
                let a = dec.advance(&data[off..]).map_err(|_| End("bad chunked response"))?;
                out.extend_from_slice(&data[off..off + a.consumed]);
                off += a.consumed;
                if a.done {
                    *resp = Resp::Done;
                    break;
                }
                if a.consumed == 0 {
                    break;
                }
            }
        }
        Resp::UntilClose => out.extend_from_slice(data),
        Resp::Head(_) | Resp::Done => {}
    }
    Ok(())
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Tls::Ready(s) = &mut self.tls {
            // Best-effort close_notify; the socket is non-blocking.
            let _ = s.shutdown();
        }
    }
}

// ------------------------------------------------------------------ main loop

pub struct Server {
    poll: Poll,
    listener: TcpListener,
    slab: Vec<Option<Box<Conn>>>,
    free: Vec<usize>,
    next_id: u64,
    sh: Shared,
    accept_pending: bool,
}

impl Server {
    pub fn new(cfg: Config, ssl_ctx: SslContext, access_log: bool, tls_log: bool) -> io::Result<Server> {
        let poll = Poll::new()?;
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(cfg.listen),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&cfg.listen.into())?;
        sock.listen(16384)?;
        let mut listener = TcpListener::from_std(sock.into());
        poll.registry().register(&mut listener, LISTENER, Interest::READABLE)?;
        let registry = poll.registry().try_clone()?;
        Ok(Server {
            poll,
            listener,
            slab: Vec::new(),
            free: Vec::new(),
            next_id: 1,
            sh: Shared {
                cfg,
                ssl_ctx,
                registry,
                m: Metrics::default(),
                now: Instant::now(),
                access_log,
                tls_log,
                requeue: Vec::new(),
            },
            accept_pending: false,
        })
    }

    pub fn metrics(&self) -> Metrics {
        self.sh.m.clone()
    }

    fn accept_all(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((mut tcp, peer)) => {
                    self.sh.m.accepted += 1;
                    if self.sh.m.active as usize >= self.sh.cfg.max_conns {
                        self.sh.m.rejected_cap += 1;
                        continue; // drop => RST/close immediately
                    }
                    let _ = tcp.set_nodelay(true);
                    let slot = match self.free.pop() {
                        Some(s) => s,
                        None => {
                            self.slab.push(None);
                            self.slab.len() - 1
                        }
                    };
                    if self.sh.registry.register(&mut tcp, Token((slot + 1) * 2), Interest::READABLE | Interest::WRITABLE).is_err() {
                        self.free.push(slot);
                        continue;
                    }
                    let id = self.next_id;
                    self.next_id += 1;
                    let c = Conn::new(&mut self.sh, id, slot, peer, tcp);
                    self.sh.m.active += 1;
                    self.slab[slot] = Some(Box::new(c));
                    self.service(slot, false);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.accept_pending = false;
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // EMFILE etc.: retry on the next tick.
                    self.accept_pending = true;
                    return;
                }
            }
        }
    }

    fn service(&mut self, slot: usize, timeout: bool) {
        let mut conn = match self.slab.get_mut(slot).and_then(|c| c.take()) {
            Some(c) => c,
            None => return,
        };
        let r = if timeout { conn.on_timeout(&mut self.sh) } else { conn.drive(&mut self.sh) };
        match r {
            Ok(()) => self.slab[slot] = Some(conn),
            Err(End(_reason)) => {
                self.sh.m.active -= 1;
                if conn.is_counted() {
                    self.sh.m.tls_established -= 1;
                }
                drop(conn);
                self.free.push(slot);
            }
        }
    }

    fn sweep(&mut self) {
        if std::env::var_os("PG_DEBUG_STUCK").is_some() {
            let (mut hs, mut rh, mut ex, mut fl, mut ready, mut counted) = (0, 0, 0, 0, 0, 0);
            for c in self.slab.iter().flatten() {
                match c.phase {
                    Phase::Handshake => hs += 1,
                    Phase::ReadHead => rh += 1,
                    Phase::Exchange(_) => ex += 1,
                    Phase::Flush { .. } => fl += 1,
                }
                if matches!(c.tls, Tls::Ready(_)) { ready += 1; }
                if c.counted { counted += 1; }
                if matches!(c.phase, Phase::ReadHead) && !c.counted {
                    eprintln!("UNCOUNTED id={} peer={} tls_ready={} rbuf={}", c.id, c.peer, matches!(c.tls, Tls::Ready(_)), c.rbuf.len());
                }
            }
            eprintln!("PHASES hs={hs} readhead={rh} exchange={ex} flush={fl} tls_ready={ready} counted={counted}");
        }
        for slot in 0..self.slab.len() {
            let expired = match &self.slab[slot] {
                Some(c) => c.expired(&self.sh),
                None => false,
            };
            if expired {
                self.service(slot, true);
            }
        }
    }

    /// Run until `stop` returns true. `tick` is called about once a second.
    pub fn run(&mut self, stop: &dyn Fn() -> bool, tick: &mut dyn FnMut(&Metrics)) -> io::Result<()> {
        let mut events = Events::with_capacity(4096);
        let mut last_tick = Instant::now();
        while !stop() {
            let timeout = if self.sh.requeue.is_empty() && !self.accept_pending {
                Duration::from_millis(250)
            } else {
                Duration::ZERO
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            self.sh.now = Instant::now();
            for ev in events.iter() {
                let t = ev.token().0;
                if t == LISTENER.0 {
                    self.accept_all();
                } else {
                    self.service(t / 2 - 1, false);
                }
            }
            if self.accept_pending {
                self.accept_all();
            }
            let rq = std::mem::take(&mut self.sh.requeue);
            for slot in rq {
                self.service(slot, false);
            }
            if self.sh.now.duration_since(last_tick) >= Duration::from_secs(1) {
                last_tick = self.sh.now;
                self.sweep();
                tick(&self.sh.m);
            }
        }
        Ok(())
    }
}
