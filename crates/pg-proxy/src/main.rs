//! ProofGate host reference proxy (intermediate stage, runs on Linux).
//!
//! Usage: pg-proxy --config FILE [--no-access-log] [--no-tls-log] [--stats]

mod config;
mod server;
mod tls;

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn raise_nofile() {
    // SAFETY: plain libc calls with a properly initialised struct.
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            rl.rlim_cur = rl.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
    }
}

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}

fn main() {
    let mut cfg_path = None;
    let mut access_log = true;
    let mut tls_log = true;
    let mut stats = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => cfg_path = args.next(),
            "--no-access-log" => access_log = false,
            "--no-tls-log" => tls_log = false,
            "--stats" => stats = true,
            _ => {
                eprintln!("usage: pg-proxy --config FILE [--no-access-log] [--no-tls-log] [--stats]");
                std::process::exit(2);
            }
        }
    }
    let cfg_path = cfg_path.unwrap_or_else(|| {
        eprintln!("--config required");
        std::process::exit(2)
    });
    let cfg = config::load_verified(&cfg_path).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    openssl::init();
    eprintln!("pg-proxy: {}", openssl::version::version());
    let ctx = tls::build_context(&cfg.cert, &cfg.key).unwrap_or_else(|e| {
        eprintln!("tls setup failed: {e}");
        std::process::exit(2)
    });
    raise_nofile();
    // SAFETY: handler only stores to an AtomicBool (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGINT, on_signal as usize);
        libc::signal(libc::SIGTERM, on_signal as usize);
    }
    let listen = cfg.listen;
    let mut srv = server::Server::new(cfg, ctx, access_log, tls_log).unwrap_or_else(|e| {
        eprintln!("cannot start: {e}");
        std::process::exit(1)
    });
    eprintln!("pg-proxy: listening on {listen} (TLS1.3, {} only)", tls::REQUIRED_GROUP);
    let start = std::time::Instant::now();
    let mut peak = 0u64;
    let mut tick = |m: &server::Metrics| {
        // glibc keeps freed pages after a connection burst; hand them back once
        // load has dropped so RSS tracks live connections (PERF_007).
        peak = peak.max(m.active);
        if m.active * 2 < peak {
            // SAFETY: malloc_trim has no preconditions.
            unsafe { libc::malloc_trim(0) };
            peak = m.active;
        }
        if stats {
            eprintln!(
                "STATS t={} active={} tls={} accepted={} hs_ok={} hs_fail={} reqs={} fwd={} local={} rejects={} be_fail={} cap_rej={} violations={} rss_kb={} fds={}",
                start.elapsed().as_secs(), m.active, m.tls_established, m.accepted, m.hs_ok, m.hs_fail, m.requests,
                m.fwd, m.local, m.rejects, m.backend_fail, m.rejected_cap, m.policy_violations, rss_kb(), open_fds()
            );
        }
    };
    if let Err(e) = srv.run(&|| STOP.load(Ordering::SeqCst), &mut tick) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
    eprintln!("pg-proxy: shutting down");
}
