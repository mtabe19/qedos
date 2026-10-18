#!/bin/sh
# Stop the dev stack: PID files first, then anything still listening on the
# stack's ports (stale processes from manual runs).
R=$(cd "$(dirname "$0")/.." && pwd)
RUN=$R/build/run
for n in proxy backend; do
  [ -f "$RUN/$n.pid" ] && kill "$(cat "$RUN/$n.pid")" 2>/dev/null
  rm -f "$RUN/$n.pid"
done
for port in 8443 19001 19002; do
  for pid in $(ss -ltnpH "src 127.0.0.1:$port" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u); do
    kill "$pid" 2>/dev/null
  done
done
sleep 0.3
exit 0
