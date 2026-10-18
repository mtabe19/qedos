//! Host-mode configuration. In the seL4 build this table is compiled in or
//! delivered as a signed blob (LAW_011); the host reference reads a file.
//!
//! ```text
//! listen 0.0.0.0:8443
//! cert  config/dev/cert.pem
//! key   config/dev/key.pem
//! max_conns 12000
//! backend a 127.0.0.1:9001
//! backend b 127.0.0.1:9002
//! route GET  /health     health
//! route POST /api/chat   a max_body=1048576
//! route GET  /game/*     b
//! ```

use pg_http::Method;
use pg_policy::{Action, BackendId, Pattern, Route};
use std::net::SocketAddr;

pub struct Backend {
    pub name: String,
    pub addr: SocketAddr,
    pub host_header: String,
}

pub struct Config {
    pub listen: SocketAddr,
    pub cert: String,
    pub key: String,
    pub max_conns: usize,
    pub backends: Vec<Backend>,
    pub routes: Vec<Route<'static>>,
    /// Per-connection timeouts in seconds.
    pub t_handshake: u64,
    pub t_head: u64,
    pub t_idle: u64,
    pub t_backend_connect: u64,
    pub t_response_idle: u64,
}

fn leak(s: &str) -> &'static [u8] {
    Box::leak(s.to_owned().into_boxed_str()).as_bytes()
}

pub fn parse(text: &str) -> Result<Config, String> {
    let mut c = Config {
        listen: "0.0.0.0:8443".parse().unwrap(),
        cert: String::new(),
        key: String::new(),
        max_conns: 12_000,
        backends: vec![],
        routes: vec![],
        t_handshake: 10,
        t_head: 15,
        t_idle: 75,
        t_backend_connect: 5,
        t_response_idle: 300,
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let err = |m: &str| format!("config line {}: {}", n + 1, m);
        match f[0] {
            "listen" => c.listen = f.get(1).ok_or_else(|| err("listen ADDR"))?.parse().map_err(|_| err("bad addr"))?,
            "cert" => c.cert = f.get(1).ok_or_else(|| err("cert PATH"))?.to_string(),
            "key" => c.key = f.get(1).ok_or_else(|| err("key PATH"))?.to_string(),
            "max_conns" => c.max_conns = f.get(1).ok_or_else(|| err("max_conns N"))?.parse().map_err(|_| err("bad number"))?,
            "timeout_handshake" => c.t_handshake = f.get(1).ok_or_else(|| err("N"))?.parse().map_err(|_| err("bad number"))?,
            "timeout_head" => c.t_head = f.get(1).ok_or_else(|| err("N"))?.parse().map_err(|_| err("bad number"))?,
            "timeout_idle" => c.t_idle = f.get(1).ok_or_else(|| err("N"))?.parse().map_err(|_| err("bad number"))?,
            "timeout_response_idle" => c.t_response_idle = f.get(1).ok_or_else(|| err("N"))?.parse().map_err(|_| err("bad number"))?,
            "backend" => {
                if f.len() != 3 {
                    return Err(err("backend NAME IP:PORT"));
                }
                let addr: SocketAddr = f[2].parse().map_err(|_| err("bad backend addr (IP:PORT literal only)"))?;
                if c.backends.len() >= 255 {
                    return Err(err("too many backends"));
                }
                c.backends.push(Backend { name: f[1].to_string(), addr, host_header: f[2].to_string() });
            }
            "route" => {
                if f.len() < 4 {
                    return Err(err("route METHOD PATH TARGET [max_body=N]"));
                }
                let method = match f[1] {
                    "GET" => Method::Get,
                    "HEAD" => Method::Head,
                    "POST" => Method::Post,
                    "PUT" => Method::Put,
                    "DELETE" => Method::Delete,
                    "PATCH" => Method::Patch,
                    "OPTIONS" => Method::Options,
                    _ => return Err(err("unsupported method")),
                };
                let pattern = if let Some(p) = f[2].strip_suffix('*') {
                    if !p.ends_with('/') {
                        return Err(err("wildcard must be /prefix/*"));
                    }
                    Pattern::Prefix(leak(p))
                } else {
                    if !f[2].starts_with('/') {
                        return Err(err("path must start with /"));
                    }
                    Pattern::Exact(leak(f[2]))
                };
                let action = if f[3] == "health" {
                    Action::Health
                } else {
                    let idx = c.backends.iter().position(|b| b.name == f[3]).ok_or_else(|| err("unknown backend (declare before use)"))?;
                    let mut max_body = 0u64;
                    for kv in &f[4..] {
                        if let Some(v) = kv.strip_prefix("max_body=") {
                            max_body = v.parse().map_err(|_| err("bad max_body"))?;
                        } else {
                            return Err(err("unknown route option"));
                        }
                    }
                    Action::Forward { backend: BackendId(idx as u8), max_body }
                };
                c.routes.push(Route { method, pattern, action });
            }
            other => return Err(err(&format!("unknown directive {other}"))),
        }
    }
    if c.cert.is_empty() || c.key.is_empty() {
        return Err("cert and key are required".into());
    }
    if c.routes.is_empty() {
        return Err("no routes".into());
    }
    Ok(c)
}

/// Verify `raw_config` against `sig_hex` using the pinned Ed25519 public key (`LAW_011`)
/// before parsing any directive.
pub fn verify_and_parse(raw_config: &[u8], sig_hex: &[u8]) -> Result<Config, String> {
    let sig = pg_config::parse_hex_sig(sig_hex)
        .ok_or_else(|| "LAW_011: malformed Ed25519 signature (expected 128 hex chars)".to_string())?;
    if !pg_config::verify_ed25519(&pg_config::PUBLIC_KEY, raw_config, &sig) {
        return Err("LAW_011: Ed25519 config signature verification failed".to_string());
    }
    let text = std::str::from_utf8(raw_config)
        .map_err(|_| "config is not valid UTF-8".to_string())?;
    parse(text)
}

/// Read `path` and its required `<path>.sig` Ed25519 signature sidecar, verify the
/// signature against [`pg_config::PUBLIC_KEY`] (LAW_011), and parse the configuration.
pub fn load_verified(path: &str) -> Result<Config, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let sig_path = format!("{path}.sig");
    let sig_hex = std::fs::read(&sig_path)
        .map_err(|e| format!("LAW_011: missing config signature {sig_path}: {e}"))?;
    verify_and_parse(&raw, &sig_hex)
}

