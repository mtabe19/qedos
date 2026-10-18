//! pg-load: PQC-TLS load generator + fast epoll test backend.
//!
//! pg-load backend --port 19001
//! pg-load run --target 127.0.0.1:8443 --conns 10000 --mode MODE [--secs S] [--ramp N/s]
//!             [--active-pct P] [--think-ms T] [--path /api/models] [--workers W]
//!
//! MODE: tcp | tls | idle | active | sse | mixed | handshake
//!   tcp        open N TCP connections, never speak TLS (PERF_001)
//!   tls        N TLS 1.3 PQC handshakes, then hold (PERF_002)
//!   idle       N TLS conns, one request each, then idle keep-alive (PERF_003)
//!   active     like idle, but P% of conns loop request/response (PERF_004)
//!   sse        N long-lived SSE streams (PERF_005 part)
//!   mixed      N-S idle/active conns plus S SSE streams (PERF_005)
//!   handshake  connect+handshake+1 request+close as fast as possible with N
//!              concurrent workers for S seconds (PERF_006)

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use openssl::ssl::{
    ErrorCode, HandshakeError, MidHandshakeSslStream, SslConnector, SslContext, SslMethod, SslMode, SslStream,
    SslVerifyMode, SslVersion,
};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Stats {
    tcp_open: AtomicU64,
    tls_open: AtomicU64,
    hs_done: AtomicU64,
    hs_fail: AtomicU64,
    reqs: AtomicU64,
    resp_ok: AtomicU64,
    resp_bad: AtomicU64,
    errors: AtomicU64,
    closed_by_peer: AtomicU64,
    sse_events: AtomicU64,
    lat_us_sum: AtomicU64,
    lat_buckets: [AtomicU64; 24], // log2(us)
    hs_us_sum: AtomicU64,
}

fn bucket(us: u64) -> usize {
    (64 - us.max(1).leading_zeros() as usize).min(23)
}

fn pct(st: &Stats, p: f64) -> u64 {
    let total: u64 = st.lat_buckets.iter().map(|b| b.load(Relaxed)).sum();
    if total == 0 {
        return 0;
    }
    let mut acc = 0;
    for (i, b) in st.lat_buckets.iter().enumerate() {
        acc += b.load(Relaxed);
        if acc as f64 >= p * total as f64 {
            return 1u64 << i;
        }
    }
    0
}

// ------------------------------------------------------------------ backend

mod backend {
    use super::*;

    #[derive(Default)]
    struct Audit {
        total: u64,
        bad: u64,
        last_bad: String,
    }

    fn audit_check(a: &mut Audit, port: u16, head_lc: &str, first: &str) {
        a.total += 1;
        let mut parts = first.split(' ');
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        let allowed_path = ["/api/models", "/api/events", "/api/chat", "/game/"].iter().any(|p| path.starts_with(p));
        let clean = !path.contains("..") && !path.contains('%') && !path.contains(';') && !path.contains('\\') && !path.contains("//");
        let method_ok = method == "get" || method == "post";
        let host_ok = head_lc.lines().any(|l| l == format!("host: 127.0.0.1:{port}"));
        let xff_ok = head_lc.lines().any(|l| l.starts_with("x-forwarded-for: "));
        let no_spoof = !head_lc.lines().any(|l| l.starts_with("x-real-ip:") || l.starts_with("forwarded:") || l.starts_with("via:"));
        if !(allowed_path && clean && method_ok && host_ok && xff_ok && no_spoof) {
            a.bad += 1;
            a.last_bad = first.to_string();
        }
    }

    struct B {
        s: TcpStream,
        rbuf: Vec<u8>,
        wbuf: Vec<u8>,
        close_after: bool,
        sse: Option<(Instant, Duration, u64)>, // next, gap, left
    }

    pub fn run(port: u16) {
        let mut poll = Poll::new().unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.bind(&addr.into()).unwrap();
        sock.listen(16384).unwrap();
        let mut l = TcpListener::from_std(sock.into());
        poll.registry().register(&mut l, Token(0), Interest::READABLE).unwrap();
        let mut conns: HashMap<usize, B> = HashMap::new();
        let mut next = 1usize;
        let mut events = Events::with_capacity(4096);
        let mut audit = Audit::default();
        eprintln!("backend listening on {addr}");
        loop {
            poll.poll(&mut events, Some(Duration::from_millis(20))).ok();
            let mut dirty: Vec<usize> = vec![];
            for ev in events.iter() {
                if ev.token() == Token(0) {
                    loop {
                        match l.accept() {
                            Ok((mut s, _)) => {
                                let id = next;
                                next += 1;
                                let _ = s.set_nodelay(true);
                                poll.registry().register(&mut s, Token(id), Interest::READABLE | Interest::WRITABLE).unwrap();
                                conns.insert(id, B { s, rbuf: vec![], wbuf: vec![], close_after: false, sse: None });
                                dirty.push(id);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                } else {
                    dirty.push(ev.token().0);
                }
            }
            // SSE timers
            let now = Instant::now();
            for (id, c) in conns.iter_mut() {
                if let Some((t, gap, left)) = &mut c.sse {
                    if now >= *t && *left > 0 {
                        let ev = b"data: tick\n\n";
                        c.wbuf.extend_from_slice(format!("{:x}\r\n", ev.len()).as_bytes());
                        c.wbuf.extend_from_slice(ev);
                        c.wbuf.extend_from_slice(b"\r\n");
                        *t = now + *gap;
                        *left -= 1;
                        if *left == 0 {
                            c.wbuf.extend_from_slice(b"0\r\n\r\n");
                            c.close_after = true;
                        }
                        dirty.push(*id);
                    }
                }
            }
            dirty.sort_unstable();
            dirty.dedup();
            for id in dirty {
                let mut drop_it = false;
                if let Some(c) = conns.get_mut(&id) {
                    drop_it = service(c, port, &mut audit);
                }
                if drop_it {
                    conns.remove(&id);
                }
            }
        }
    }

    fn service(c: &mut B, port: u16, audit: &mut Audit) -> bool {
        let mut buf = [0u8; 8192];
        loop {
            match c.s.read(&mut buf) {
                Ok(0) => return true,
                Ok(n) => c.rbuf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return true,
            }
        }
        // parse (at most one request per connection: proxy sends Connection: close)
        if c.sse.is_none() && !c.close_after {
            if let Some(p) = c.rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&c.rbuf[..p]).to_ascii_lowercase();
                let first = head.lines().next().unwrap_or("").to_string();
                let cl: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0);
                if c.rbuf.len() >= p + 4 + cl {
                    let path = first.split(' ').nth(1).unwrap_or("/").to_string();
                    if path == "/__audit__" {
                        let body = format!("{{\"total\":{},\"bad\":{},\"last_bad\":{:?}}}", audit.total, audit.bad, audit.last_bad);
                        c.wbuf.extend_from_slice(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes());
                        c.close_after = true;
                    } else if path.starts_with("/api/events") {
                        audit_check(audit, port, &head, &first);
                        let gap_ms: u64 = path.split("gap_ms=").nth(1).and_then(|v| v.split('&').next()).and_then(|v| v.parse().ok()).unwrap_or(1000);
                        let n: u64 = path.split("n=").nth(1).and_then(|v| v.split('&').next()).and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
                        c.wbuf.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
                        let gap = Duration::from_millis(gap_ms);
                        c.sse = Some((Instant::now(), gap, n));
                    } else {
                        audit_check(audit, port, &head, &first);
                        let body = b"{\"backend\":\"fast\",\"ok\":true}";
                        c.wbuf.extend_from_slice(
                            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
                        );
                        c.wbuf.extend_from_slice(body);
                        c.close_after = true;
                    }
                    c.rbuf.clear();
                }
            }
        }
        while !c.wbuf.is_empty() {
            match c.s.write(&c.wbuf) {
                Ok(n) => {
                    c.wbuf.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return true,
            }
        }
        c.close_after && c.wbuf.is_empty()
    }
}

// ------------------------------------------------------------------- client

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Tcp,
    Tls,
    Idle,
    Active,
    Sse,
    Mixed,
    Handshake,
}

#[derive(Clone)]
struct Opts {
    target: SocketAddr,
    conns: usize,
    mode: Mode,
    secs: u64,
    ramp: u64,
    active_pct: usize,
    think_ms: u64,
    path: String,
    workers: usize,
    sse_conns: usize,
    sources: usize,
}

enum Tls {
    None,
    Hs(MidHandshakeSslStream<TcpStream>),
    Ready(SslStream<TcpStream>),
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Role {
    Holder,
    Requester,
    Sse,
    Handshaker,
}

struct Cn {
    tcp: Option<TcpStream>, // only for Tcp mode / until TLS wraps it
    tls: Tls,
    role: Role,
    connecting: bool,
    t_start: Instant,
    t_req: Instant,
    wbuf: Vec<u8>,
    rbuf: Vec<u8>,
    in_flight: bool,
    next_req: Option<Instant>,
    loops: bool,
    dead: bool,
}

fn client_ctx() -> SslContext {
    let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    b.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    b.set_ciphersuites("TLS_AES_256_GCM_SHA384").unwrap();
    b.set_groups_list("X25519MLKEM768").unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.set_mode(SslMode::RELEASE_BUFFERS | SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
    b.build().into_context()
}

fn make_req(path: &str, keep: bool) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: load.test\r\n{}\r\n", if keep { "" } else { "Connection: close\r\n" }).into_bytes()
}

fn worker(id: usize, o: Opts, st: Arc<Stats>, stop: Arc<std::sync::atomic::AtomicBool>, ctx: SslContext) {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4096);
    let per = o.conns / o.workers + if id < o.conns % o.workers { 1 } else { 0 };
    let mut conns: Vec<Option<Cn>> = (0..per).map(|_| None).collect();
    let mut opened = 0usize;
    let start = Instant::now();
    let ramp_per_worker = (o.ramp as f64 / o.workers as f64).max(1.0);
    let mut sse_assigned = 0usize;
    let sse_for_me = if o.mode == Mode::Sse { per } else if o.mode == Mode::Mixed { o.sse_conns / o.workers } else { 0 };
    let hs_loop = o.mode == Mode::Handshake;
    let mut src_rr = id;
    let steady_req = make_req(&o.path, true);
    let end_time = if o.secs > 0 { Some(start + Duration::from_secs(o.secs)) } else { None };
    let mut slot_free: Vec<usize> = vec![];

    let open_one = |slot: usize, conns: &mut Vec<Option<Cn>>, poll: &Poll, role: Role, src_rr: &mut usize| {
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        sock.set_nonblocking(true).unwrap();
        if o.sources > 1 {
            // spread over 127.0.0.x to get past the ~28k ephemeral-port limit
            let ip = std::net::Ipv4Addr::new(127, 0, 0, 1 + (*src_rr % o.sources) as u8);
            *src_rr += 1;
            let _ = sock.bind(&SocketAddr::new(ip.into(), 0).into());
        }
        let _ = sock.set_nodelay(true);
        match sock.connect(&o.target.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(_) => {
                st.errors.fetch_add(1, Relaxed);
                return false;
            }
        }
        let mut tcp = TcpStream::from_std(sock.into());
        poll.registry().register(&mut tcp, Token(slot), Interest::READABLE | Interest::WRITABLE).unwrap();
        conns[slot] = Some(Cn {
            tcp: Some(tcp),
            tls: Tls::None,
            role,
            connecting: true,
            t_start: Instant::now(),
            t_req: Instant::now(),
            wbuf: vec![],
            rbuf: vec![],
            in_flight: false,
            next_req: None,
            loops: false,
            dead: false,
        });
        true
    };

    loop {
        if stop.load(Relaxed) {
            break;
        }
        if let Some(e) = end_time {
            if Instant::now() >= e && o.mode != Mode::Tcp && o.mode != Mode::Tls && o.mode != Mode::Idle {
                break;
            }
        }
        // ---- ramp: open connections up to the schedule
        let target_open = if hs_loop {
            per
        } else {
            (((start.elapsed().as_secs_f64() * ramp_per_worker) as usize) + 1).min(per)
        };
        if hs_loop {
            while let Some(s) = slot_free.pop() {
                let role = Role::Handshaker;
                if !open_one(s, &mut conns, &poll, role, &mut src_rr) {
                    slot_free.push(s);
                    break;
                }
            }
        }
        while !hs_loop && opened < target_open {
            let slot = opened;
            let role = if sse_assigned < sse_for_me {
                sse_assigned += 1;
                Role::Sse
            } else if o.mode == Mode::Tcp || o.mode == Mode::Tls {
                Role::Holder
            } else {
                Role::Requester
            };
            opened += 1;
            if open_one(slot, &mut conns, &poll, role, &mut src_rr) {
                if let Some(c) = conns[slot].as_mut() {
                    c.loops = o.mode == Mode::Active || o.mode == Mode::Mixed && (id * 7 + slot) % 100 < o.active_pct;
                    if o.mode == Mode::Active {
                        c.loops = ((slot * o.workers + id) % 100) < o.active_pct;
                    }
                }
            }
        }
        if hs_loop && opened == 0 {
            opened = per;
            for s in 0..per {
                slot_free.push(s);
            }
            continue;
        }
        // ---- think-time timers
        let now = Instant::now();
        let mut due: Vec<usize> = vec![];
        if o.mode == Mode::Active || o.mode == Mode::Mixed {
            for (i, c) in conns.iter().enumerate() {
                if let Some(c) = c {
                    if let Some(t) = c.next_req {
                        if now >= t && !c.in_flight {
                            due.push(i);
                        }
                    }
                }
            }
        }
        poll.poll(&mut events, Some(Duration::from_millis(5))).ok();
        let mut work: Vec<usize> = events.iter().map(|e| e.token().0).collect();
        work.extend(due);
        work.sort_unstable();
        work.dedup();
        for slot in work {
            let mut c = match conns.get_mut(slot).and_then(|c| c.take()) {
                Some(c) => c,
                None => continue,
            };
            let keep = step(&mut c, &poll, slot, &o, &st, &ctx, &steady_req);
            if keep && !c.dead {
                conns[slot] = Some(c);
            } else {
                if c.dead {
                    // accounted in step
                }
                if hs_loop {
                    slot_free.push(slot);
                }
                drop(c);
            }
        }
    }
    // drop everything: closes sockets
}

/// Advance a connection; returns false when it should be dropped.
fn step(c: &mut Cn, poll: &Poll, slot: usize, o: &Opts, st: &Stats, ctx: &SslContext, steady: &[u8]) -> bool {
    // 1. TCP connect completion
    if c.connecting {
        let tcp = c.tcp.as_ref().unwrap();
        match tcp.take_error() {
            Ok(None) => {}
            _ => {
                st.errors.fetch_add(1, Relaxed);
                return false;
            }
        }
        match tcp.peer_addr() {
            Ok(_) => {
                c.connecting = false;
                st.tcp_open.fetch_add(1, Relaxed);
                if o.mode == Mode::Tcp {
                    return true;
                }
                let ssl = openssl::ssl::Ssl::new(ctx).unwrap();
                let tcp = c.tcp.take().unwrap();
                c.t_start = Instant::now();
                match ssl.connect(tcp) {
                    Ok(s) => c.tls = Tls::Ready(s),
                    Err(HandshakeError::WouldBlock(m)) => c.tls = Tls::Hs(m),
                    Err(_) => {
                        st.hs_fail.fetch_add(1, Relaxed);
                        st.tcp_open.fetch_sub(1, Relaxed);
                        return false;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotConnected => return true,
            Err(_) => {
                st.errors.fetch_add(1, Relaxed);
                return false;
            }
        }
    }
    if o.mode == Mode::Tcp {
        // detect peer close
        let tcp = c.tcp.as_mut().unwrap();
        let mut b = [0u8; 64];
        match tcp.read(&mut b) {
            Ok(0) => {
                st.closed_by_peer.fetch_add(1, Relaxed);
                st.tcp_open.fetch_sub(1, Relaxed);
                return false;
            }
            _ => return true,
        }
    }
    // 2. TLS handshake
    if let Tls::Hs(_) = c.tls {
        let m = match std::mem::replace(&mut c.tls, Tls::None) {
            Tls::Hs(m) => m,
            _ => unreachable!(),
        };
        match m.handshake() {
            Ok(s) => {
                st.hs_done.fetch_add(1, Relaxed);
                st.tls_open.fetch_add(1, Relaxed);
                st.hs_us_sum.fetch_add(c.t_start.elapsed().as_micros() as u64, Relaxed);
                c.tls = Tls::Ready(s);
                after_handshake(c, o, steady);
            }
            Err(HandshakeError::WouldBlock(m)) => {
                c.tls = Tls::Hs(m);
                return true;
            }
            Err(_) => {
                st.hs_fail.fetch_add(1, Relaxed);
                st.tcp_open.fetch_sub(1, Relaxed);
                return false;
            }
        }
    } else if matches!(c.tls, Tls::Ready(_)) && c.rbuf.is_empty() && c.wbuf.is_empty() && !c.in_flight && c.t_req == c.t_start {
        // handshake finished synchronously (not expected)
    }
    let s = match &mut c.tls {
        Tls::Ready(s) => s,
        _ => return true,
    };
    // first-time init for Ready-without-hs-branch is covered by after_handshake
    // 3. write pending
    while !c.wbuf.is_empty() {
        match s.ssl_write(&c.wbuf) {
            Ok(n) => {
                c.wbuf.drain(..n);
            }
            Err(e) => match e.code() {
                ErrorCode::WANT_WRITE | ErrorCode::WANT_READ => break,
                _ => {
                    st.errors.fetch_add(1, Relaxed);
                    return finish(c, st);
                }
            },
        }
    }
    // 4. read
    let mut buf = [0u8; 16384];
    loop {
        match s.ssl_read(&mut buf) {
            Ok(0) => {
                st.closed_by_peer.fetch_add(1, Relaxed);
                return finish(c, st);
            }
            Ok(n) => {
                if c.role == Role::Sse {
                    let k = buf[..n].windows(5).filter(|w| *w == b"data:").count();
                    st.sse_events.fetch_add(k as u64, Relaxed);
                    continue;
                }
                c.rbuf.extend_from_slice(&buf[..n]);
            }
            Err(e) => match e.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => break,
                ErrorCode::ZERO_RETURN => {
                    return finish(c, st);
                }
                _ => {
                    // abrupt close is expected for Connection: close responses
                    if e.io_error().is_none() {
                        return finish_done(c, st);
                    }
                    st.errors.fetch_add(1, Relaxed);
                    return finish(c, st);
                }
            },
        }
    }
    // 5. response complete?
    if c.in_flight {
        if let Some(p) = c.rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&c.rbuf[..p]).to_ascii_lowercase();
            let cl: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            if c.rbuf.len() >= p + 4 + cl {
                let ok = head.starts_with("http/1.1 200");
                let us = c.t_req.elapsed().as_micros() as u64;
                st.lat_us_sum.fetch_add(us, Relaxed);
                st.lat_buckets[bucket(us)].fetch_add(1, Relaxed);
                if ok {
                    st.resp_ok.fetch_add(1, Relaxed);
                } else {
                    st.resp_bad.fetch_add(1, Relaxed);
                }
                c.rbuf.clear();
                c.in_flight = false;
                if c.role == Role::Handshaker {
                    return finish_done(c, st);
                }
                if c.loops {
                    c.next_req = Some(Instant::now() + Duration::from_millis(o.think_ms));
                } else {
                    c.next_req = None;
                }
            }
        }
    }
    // 6. issue next request?
    if !c.in_flight && c.wbuf.is_empty() {
        if let Some(t) = c.next_req {
            if Instant::now() >= t {
                c.wbuf.extend_from_slice(steady);
                c.in_flight = true;
                c.t_req = Instant::now();
                st.reqs.fetch_add(1, Relaxed);
                c.next_req = None;
                return step(c, poll, slot, o, st, ctx, steady);
            }
        }
    }
    true
}

fn after_handshake(c: &mut Cn, o: &Opts, steady: &[u8]) {
    match c.role {
        Role::Holder => {}
        Role::Requester => {
            // one request, then idle (or loop)
            c.wbuf.extend_from_slice(steady);
            c.in_flight = true;
            c.t_req = Instant::now();
        }
        Role::Sse => {
            c.wbuf.extend_from_slice(&make_req("/api/events?gap_ms=1000", true));
        }
        Role::Handshaker => {
            c.wbuf.extend_from_slice(&make_req(&o.path, false));
            c.in_flight = true;
            c.t_req = Instant::now();
        }
    }
}

fn finish(c: &mut Cn, st: &Stats) -> bool {
    finish_done(c, st)
}

fn finish_done(c: &mut Cn, st: &Stats) -> bool {
    if matches!(c.tls, Tls::Ready(_)) {
        st.tls_open.fetch_sub(1, Relaxed);
    }
    st.tcp_open.fetch_sub(1, Relaxed);
    c.dead = true;
    false
}

fn rss_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

fn main() {
    openssl::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("backend") {
        let mut port = 19001u16;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--port" {
                port = args[i + 1].parse().unwrap();
                i += 1;
            }
            i += 1;
        }
        // SAFETY: plain libc call
        unsafe {
            let mut rl: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
            rl.rlim_cur = rl.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
        backend::run(port);
        return;
    }
    if args.first().map(|s| s.as_str()) != Some("run") {
        eprintln!("usage: pg-load backend --port P | pg-load run --target A --conns N --mode M ...");
        std::process::exit(2);
    }
    let mut o = Opts {
        target: "127.0.0.1:8443".parse().unwrap(),
        conns: 1000,
        mode: Mode::Idle,
        secs: 10,
        ramp: 2000,
        active_pct: 10,
        think_ms: 100,
        path: "/api/models".into(),
        workers: 4,
        sse_conns: 0,
        sources: 1,
    };
    let mut watch_pid: u32 = 0;
    let mut hold_secs = 5u64;
    let mut i = 1;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--target" => o.target = v.parse().unwrap(),
            "--conns" => o.conns = v.parse().unwrap(),
            "--mode" => {
                o.mode = match v.as_str() {
                    "tcp" => Mode::Tcp,
                    "tls" => Mode::Tls,
                    "idle" => Mode::Idle,
                    "active" => Mode::Active,
                    "sse" => Mode::Sse,
                    "mixed" => Mode::Mixed,
                    "handshake" => Mode::Handshake,
                    _ => panic!("bad mode"),
                }
            }
            "--secs" => o.secs = v.parse().unwrap(),
            "--hold" => hold_secs = v.parse().unwrap(),
            "--ramp" => o.ramp = v.parse().unwrap(),
            "--active-pct" => o.active_pct = v.parse().unwrap(),
            "--think-ms" => o.think_ms = v.parse().unwrap(),
            "--path" => o.path = v,
            "--workers" => o.workers = v.parse().unwrap(),
            "--sse-conns" => o.sse_conns = v.parse().unwrap(),
            "--sources" => o.sources = v.parse().unwrap(),
            "--watch-pid" => watch_pid = v.parse().unwrap(),
            other => panic!("unknown arg {other}"),
        }
        i += 2;
    }
    // SAFETY: plain libc call
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        rl.rlim_cur = rl.rlim_max;
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
    }
    let st = Arc::new(Stats::default());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctx = client_ctx();
    let mut hs = vec![];
    for w in 0..o.workers {
        let (o2, st2, stop2, ctx2) = (o.clone(), st.clone(), stop.clone(), ctx.clone());
        hs.push(std::thread::spawn(move || worker(w, o2, st2, stop2, ctx2)));
    }
    let t0 = Instant::now();
    let want_open = if o.mode == Mode::Handshake { 0 } else { o.conns as u64 };
    let mut reached: Option<f64> = None;
    let mut prev_hs = 0;
    let total_run = o.secs + if o.mode == Mode::Tcp || o.mode == Mode::Tls || o.mode == Mode::Idle { 0 } else { 0 };
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let el = t0.elapsed().as_secs_f64();
        let hsd = st.hs_done.load(Relaxed);
        let (tcp, tls) = (st.tcp_open.load(Relaxed), st.tls_open.load(Relaxed));
        eprintln!(
            "t={:.0}s tcp={} tls={} hs_done={} (+{}/s) hs_fail={} reqs={} ok={} bad={} err={} peer_closed={} sse_ev={} p50={}us p99={}us proxy_rss_kb={}",
            el, tcp, tls, hsd, hsd - prev_hs, st.hs_fail.load(Relaxed), st.reqs.load(Relaxed), st.resp_ok.load(Relaxed),
            st.resp_bad.load(Relaxed), st.errors.load(Relaxed), st.closed_by_peer.load(Relaxed), st.sse_events.load(Relaxed),
            pct(&st, 0.5), pct(&st, 0.99), if watch_pid > 0 { rss_kb(watch_pid) } else { 0 }
        );
        prev_hs = hsd;
        let level = match o.mode {
            Mode::Tcp => tcp,
            _ => tls,
        };
        if reached.is_none() && want_open > 0 && level >= want_open {
            reached = Some(el);
        }
        if let Some(r) = reached {
            if el - r >= hold_secs as f64 && matches!(o.mode, Mode::Tcp | Mode::Tls | Mode::Idle) {
                break;
            }
        }
        if o.mode == Mode::Handshake || matches!(o.mode, Mode::Active | Mode::Sse | Mode::Mixed) {
            if el >= (o.secs + if want_open > 0 { 0 } else { 0 }) as f64 + if o.mode == Mode::Handshake { 0.0 } else { 0.0 } {
                // for sse/active/mixed: run for secs after reaching target
                if o.mode == Mode::Handshake {
                    break;
                }
                if let Some(r) = reached {
                    if el - r >= o.secs as f64 {
                        break;
                    }
                } else if el > (o.secs + 120) as f64 {
                    break;
                }
            }
        }
        if el > 600.0 + total_run as f64 {
            break;
        }
    }
    let el = t0.elapsed().as_secs_f64();
    let summary = format!(
        "{{\"mode\":\"{:?}\",\"conns_target\":{},\"tcp_open\":{},\"tls_open\":{},\"hs_done\":{},\"hs_fail\":{},\"reqs\":{},\"resp_ok\":{},\"resp_bad\":{},\"errors\":{},\"peer_closed\":{},\"sse_events\":{},\"elapsed_s\":{:.1},\"reached_target_s\":{},\"hs_per_s\":{:.0},\"avg_hs_ms\":{:.2},\"req_p50_us\":{},\"req_p99_us\":{},\"req_per_s\":{:.0}}}",
        o.mode, o.conns, st.tcp_open.load(Relaxed), st.tls_open.load(Relaxed), st.hs_done.load(Relaxed), st.hs_fail.load(Relaxed),
        st.reqs.load(Relaxed), st.resp_ok.load(Relaxed), st.resp_bad.load(Relaxed), st.errors.load(Relaxed),
        st.closed_by_peer.load(Relaxed), st.sse_events.load(Relaxed), el,
        reached.map(|r| format!("{:.1}", r)).unwrap_or("null".into()),
        st.hs_done.load(Relaxed) as f64 / el,
        st.hs_us_sum.load(Relaxed) as f64 / 1000.0 / (st.hs_done.load(Relaxed).max(1)) as f64,
        pct(&st, 0.5), pct(&st, 0.99), st.resp_ok.load(Relaxed) as f64 / el
    );
    println!("{summary}");
    stop.store(true, Relaxed);
    for h in hs {
        let _ = h.join();
    }
}
