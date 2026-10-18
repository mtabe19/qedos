#!/bin/sh
# Start test backends + proxy in the background (PID files under build/run).
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
RUN=$R/build/run; mkdir -p "$RUN"
CONF=${1:-$R/config/dev/proxy.conf}
[ $# -gt 0 ] && shift || true
"$R/scripts/dev-down.sh" >/dev/null 2>&1 || true
cd "$R"
python3 tests/backend.py >"$RUN/backend.log" 2>&1 &
echo $! >"$RUN/backend.pid"
sleep 0.5
"$R/target/release/pg-proxy" --config "$CONF" "$@" >"$RUN/proxy.log" 2>&1 &
echo $! >"$RUN/proxy.pid"
sleep 0.5
echo "up: proxy pid $(cat "$RUN/proxy.pid"), log $RUN/proxy.log"
