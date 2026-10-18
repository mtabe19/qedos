#!/bin/sh
# Start the proxy (no per-request logging) and two fast epoll backends.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
RUN=$R/build/run; mkdir -p "$RUN"
"$R/scripts/dev-down.sh" >/dev/null 2>&1 || true
ulimit -n 1048576 2>/dev/null || true
"$R/target/release/pg-load" backend --port 19001 >"$RUN/be1.log" 2>&1 & echo $! >"$RUN/backend.pid"
"$R/target/release/pg-load" backend --port 19002 >"$RUN/be2.log" 2>&1 & echo $! >>"$RUN/backend2.pid"
sleep 0.4
cd "$R"
"$R/target/release/pg-proxy" --config "${1:-config/perf/proxy.conf}" --no-access-log --no-tls-log --stats >"$RUN/proxy.log" 2>&1 &
echo $! >"$RUN/proxy.pid"
sleep 0.5
echo "perf stack up: proxy pid $(cat "$RUN/proxy.pid")"
