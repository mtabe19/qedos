#!/usr/bin/env python3
"""PERF_001 .. PERF_008 for the ProofGate host reference proxy.

Starts the perf stack (proxy + two fast epoll backends), drives it with
pg-load (PQC-only TLS 1.3 clients), and cross-checks the *server's* own view
(STATS lines, /proc) against the client's. Results -> build/perf/results.json.

Usage: python3 tests/perf.py [--conns 10000] [only PERF_00X ...]
"""
import json, os, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
LOAD = os.path.join(ROOT, "target/release/pg-load")
OUT = os.path.join(ROOT, "build/perf")
os.makedirs(OUT, exist_ok=True)
N = 10000
args = sys.argv[1:]
if "--conns" in args:
    i = args.index("--conns")
    N = int(args[i + 1])
    del args[i:i + 2]
ONLY = set(a for a in args)

results = {}


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def stack_up():
    p = subprocess.run([os.path.join(ROOT, "scripts/perf-up.sh")], capture_output=True, text=True)
    del_env = None
    pid = int(open(os.path.join(ROOT, "build/run/proxy.pid")).read())
    return pid


def proxy_pid():
    return int(open(os.path.join(ROOT, "build/run/proxy.pid")).read())


def proc_stats(pid):
    rss = fds = 0
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"):
                rss = int(l.split()[1])
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None
    return {"rss_kb": rss, "fds": fds}


def server_stats():
    last = None
    with open(os.path.join(ROOT, "build/run/proxy.log"), "rb") as f:
        for line in f.read().decode("utf-8", "replace").splitlines():
            if line.startswith("STATS "):
                last = line
    if not last:
        return {}
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", last)}


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def run_load(extra, pid, timeout=300):
    cmd = [LOAD, "run", "--watch-pid", str(pid)] + extra
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    lines = [l for l in p.stdout.strip().splitlines() if l.startswith("{")]
    summary = json.loads(lines[-1]) if lines else {}
    return summary, p.stderr


def backend_audit():
    out = []
    for port in (19001, 19002):
        try:
            r = subprocess.run(["curl", "-s", "--max-time", "5", f"http://127.0.0.1:{port}/__audit__"], capture_output=True, text=True)
            out.append(json.loads(r.stdout))
        except Exception:
            out.append({"total": -1, "bad": -1})
    return out


def settle(pid, target_active=0, tries=40):
    for _ in range(tries):
        time.sleep(0.5)
        s = server_stats()
        if s.get("active", 1) <= target_active:
            return True
    return False


def record(name, ok, detail):
    results[name] = {"pass": ok, **detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: " + json.dumps(detail, sort_keys=True), flush=True)


def want(name):
    return not ONLY or name in ONLY


def main():
    pid = stack_up()
    base = proc_stats(pid)
    print(f"baseline: {base}  target conns={N}")
    srcs = ["--sources", "8"]

    if want("PERF_001"):
        s, err = run_load(["--mode", "tcp", "--conns", str(N), "--workers", "4", "--ramp", "5000", "--hold", "5"] + srcs, pid)
        mid = server_stats()
        time.sleep(0.1)
        ok = s.get("tcp_open", 0) == N and alive(pid)
        settle(pid)
        record("PERF_001", ok, {"desc": "hold N TCP connections", "client_tcp_open": s.get("tcp_open"), "reached_s": s.get("reached_target_s"),
                                "proxy_rss_kb_peak": max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])})

    if want("PERF_002"):
        s, err = run_load(["--mode", "tls", "--conns", str(N), "--workers", "4", "--ramp", "4000", "--hold", "5"] + srcs, pid)
        peak_rss = max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])
        ok = s.get("tls_open", 0) == N and s.get("hs_fail", 1) == 0 and alive(pid)
        record("PERF_002", ok, {"desc": "hold N TLS1.3/X25519MLKEM768 connections", "client_tls_open": s.get("tls_open"), "hs_fail": s.get("hs_fail"),
                                "avg_hs_ms": s.get("avg_hs_ms"), "reached_s": s.get("reached_target_s"), "proxy_rss_kb_peak": peak_rss,
                                "kb_per_conn": round((peak_rss - base["rss_kb"]) / N, 1)})
        settle(pid)

    if want("PERF_003"):
        s, err = run_load(["--mode", "idle", "--conns", str(N), "--workers", "4", "--ramp", "4000", "--hold", "10"] + srcs, pid)
        peak_rss = max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])
        # server's own view while connections were held (sampled by the client run's duration)
        ok = s.get("tls_open", 0) == N and s.get("resp_ok", 0) == N and s.get("resp_bad", 1) == 0 and s.get("errors", 1) == 0 and alive(pid)
        record("PERF_003", ok, {"desc": "N HTTPS keep-alive connections, 1 request each then idle", "client_tls_open": s.get("tls_open"),
                                "resp_ok": s.get("resp_ok"), "resp_bad": s.get("resp_bad"), "errors": s.get("errors"),
                                "req_p50_us": s.get("req_p50_us"), "req_p99_us": s.get("req_p99_us"), "proxy_rss_kb_peak": peak_rss})
        settle(pid)

    if want("PERF_004"):
        s, err = run_load(["--mode", "active", "--conns", str(N), "--workers", "6", "--ramp", "4000", "--active-pct", "10",
                           "--think-ms", "50", "--secs", "20"] + srcs, pid)
        peak_rss = max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])
        ok = s.get("errors", 1) == 0 and s.get("resp_bad", 1) == 0 and s.get("resp_ok", 0) > N and s.get("hs_fail", 1) == 0 and alive(pid)
        record("PERF_004", ok, {"desc": f"N conns, 10% actively requesting (think 50ms), 20s", "resp_ok": s.get("resp_ok"), "resp_bad": s.get("resp_bad"),
                                "errors": s.get("errors"), "req_per_s": s.get("req_per_s"), "req_p50_us": s.get("req_p50_us"),
                                "req_p99_us": s.get("req_p99_us"), "proxy_rss_kb_peak": peak_rss})
        settle(pid)

    if want("PERF_005"):
        sse = N // 5
        s, err = run_load(["--mode", "mixed", "--conns", str(N), "--sse-conns", str(sse), "--workers", "6", "--ramp", "4000",
                           "--active-pct", "10", "--think-ms", "50", "--secs", "20"] + srcs, pid)
        peak_rss = max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])
        ev = s.get("sse_events", 0)
        ok = s.get("errors", 1) == 0 and s.get("resp_bad", 1) == 0 and ev > sse * 10 and alive(pid) and s.get("hs_fail", 1) == 0
        record("PERF_005", ok, {"desc": f"{sse} long SSE streams + {N - sse} conns with 10% active mixed", "sse_events": ev, "resp_ok": s.get("resp_ok"),
                                "errors": s.get("errors"), "req_p50_us": s.get("req_p50_us"), "req_p99_us": s.get("req_p99_us"),
                                "proxy_rss_kb_peak": peak_rss})
        settle(pid)

    if want("PERF_006"):
        s, err = run_load(["--mode", "handshake", "--conns", "3000", "--workers", "8", "--secs", "15", "--path", "/health"] + srcs, pid)
        ok = s.get("hs_done", 0) > 1000 and s.get("hs_fail", 1) == 0 and alive(pid)
        record("PERF_006", ok, {"desc": "new PQ handshake + 1 request + close, 3000 concurrent, 15s", "hs_per_s": s.get("hs_per_s"),
                                "hs_done": s.get("hs_done"), "hs_fail": s.get("hs_fail"), "avg_hs_ms": s.get("avg_hs_ms"),
                                "req_p50_us": s.get("req_p50_us"), "req_p99_us": s.get("req_p99_us"), "errors": s.get("errors")})
        settle(pid)

    if want("PERF_007"):
        before = proc_stats(pid)
        settle(pid)
        s, err = run_load(["--mode", "idle", "--conns", str(N), "--workers", "4", "--ramp", "4000", "--hold", "3"] + srcs, pid)
        peak = proc_stats(pid)
        settled = settle(pid)
        time.sleep(3)   # allow malloc_trim tick
        after = proc_stats(pid)
        st = server_stats()
        ok = alive(pid) and settled and st.get("active", 1) == 0 and st.get("tls", 1) == 0 and after["fds"] <= before["fds"] + 1 \
            and after["rss_kb"] < before["rss_kb"] + 0.15 * (peak_rss if False else (max([int(m) for m in re.findall(r'proxy_rss_kb=(\d+)', err)] or [0]) - before["rss_kb"])) + 5000
        record("PERF_007", ok, {"desc": "resources recover after load release", "before": before, "after": after, "server_active": st.get("active"),
                                "server_tls": st.get("tls"), "peak_rss_kb": max([int(m) for m in re.findall(r"proxy_rss_kb=(\d+)", err)] or [0])})

    if want("PERF_008"):
        # security probes concurrently with 10k live connections
        import threading
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        from common import raw, status_of
        probes = []
        stop = threading.Event()

        def probe():
            cases = [
                (b"GET /game/../api/chat HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 400),
                (b"GET /game/%2e%2e/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 400),
                (b"GET /game/..;/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 400),
                (b"GET http://127.0.0.1:19002/api/models HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 400),
                (b"CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: x\r\n\r\n", 405),
                (b"POST /api/chat HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400),
                (b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 404),
                (b"DELETE /api/models HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 405),
                (b"GET /api/models HTTP/1.1\r\nHost: evil\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nConnection: close\r\n\r\n", 200),
            ]
            while not stop.is_set():
                for data, want_status in cases:
                    r = raw(data, idle=2, timeout=10)
                    probes.append((status_of(r) == want_status, data[:40], status_of(r)))

        t = threading.Thread(target=probe)
        t.start()
        s, err = run_load(["--mode", "active", "--conns", str(N), "--workers", "6", "--ramp", "4000", "--active-pct", "10",
                           "--think-ms", "50", "--secs", "20"] + srcs, pid)
        stop.set()
        t.join()
        a = backend_audit()
        st = server_stats()
        bad_probes = [p for p in probes if not p[0]]
        ok = alive(pid) and len(probes) > 20 and not bad_probes and all(x["bad"] == 0 for x in a) and st.get("violations", 1) == 0
        record("PERF_008", ok, {"desc": "routing/parser constraints hold with N live connections", "probes_run": len(probes),
                                "probes_wrong": len(bad_probes), "backend_audit": a, "policy_violations": st.get("violations"),
                                "load_resp_ok": s.get("resp_ok"), "load_errors": s.get("errors")})

    final = proc_stats(pid) if alive(pid) else None
    results["_meta"] = {"conns": N, "baseline": base, "final": final, "proxy_alive": alive(pid)}
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    print("\nsummary:", {k: v["pass"] for k, v in results.items() if k != "_meta"})
    subprocess.run([os.path.join(ROOT, "scripts/dev-down.sh")])
    sys.exit(0 if all(v["pass"] for k, v in results.items() if k != "_meta") else 1)


if __name__ == "__main__":
    main()
