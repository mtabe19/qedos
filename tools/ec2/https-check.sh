#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# HTTPS checks against QEDOS running on EC2, the same checks as SEL4_001..003 of tests/test_sel4.py:
#   1. TLS 1.3 + X25519MLKEM768 + GET /health -> 200 "ok" (TLS_AES_256_GCM_SHA384)
#   2. TLS 1.2 is refused
#   3. classical key exchange (X25519 only, P-256 only) is refused
# With --backend BACKEND_IP, also the same checks as SEL4_004/005 (M5-5):
#   4. POST /api/chat -> backend A, GET /game/score -> backend B; the backend sees Host BACKEND_IP:port
#      and no X-Forwarded-For (LAW_001, LAW_004)
#   5. hostile requests are rejected with 400/404/405 (the backend-side leak count of SEL4_005 is
#      not checked: the backend cannot be reached from here)
# Run it from the developer's machine while tools/ec2/boot-test.sh collects the console, after
# "DHCP lease acquired" appeared. The instance's security group must allow TCP 8443 from this machine.
#
# usage: tools/ec2/https-check.sh [--backend BACKEND_IP] PUBLIC_IP [PORT]
#        (against the VM's QEMU: tools/ec2/https-check.sh --backend 10.0.2.2 127.0.0.1 18443)
# env:   OPENSSL         openssl 3.5+ with ML-KEM (default: third_party/openssl-install, then Homebrew openssl@3)
#        QEDOS_TIMEOUT   seconds per connection (default 20)
set -u
R=$(cd "$(dirname "$0")/../.." && pwd)
BACKEND=""
if [ "${1:-}" = "--backend" ]; then
  [ $# -ge 2 ] || { echo "usage: $0 [--backend BACKEND_IP] PUBLIC_IP [PORT]" >&2; exit 2; }
  BACKEND=$2
  shift 2
fi
[ $# -ge 1 ] || { echo "usage: $0 [--backend BACKEND_IP] PUBLIC_IP [PORT]" >&2; exit 2; }
HOST=$1
PORT=${2:-8443}
TIMEOUT=${QEDOS_TIMEOUT:-20}

O=${OPENSSL:-}
if [ -z "$O" ]; then
  for c in "$R/third_party/openssl-install/bin/openssl" /opt/homebrew/opt/openssl@3/bin/openssl \
           /usr/local/opt/openssl@3/bin/openssl; do
    if [ -x "$c" ]; then O=$c; break; fi
  done
fi
[ -n "$O" ] || { echo "openssl 3.5+ not found (set OPENSSL)" >&2; exit 1; }
export OPENSSL_CONF="$R/config/openssl-min.cnf"
echo "openssl: $O ($("$O" version))  target: $HOST:$PORT"

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
fails=0

# send REQUEST [s_client options...]: send REQUEST (printf %b escapes) and keep the output in $OUT
# (perl alarm as a timeout)
send() {
  req=$1
  shift
  printf '%b' "$req" |
    perl -e 'alarm shift; exec @ARGV' "$TIMEOUT" \
      "$O" s_client -connect "$HOST:$PORT" -ign_eof "$@" > "$OUT" 2>&1
}
# request [s_client options...]: GET /health
request() {
  send 'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' "$@"
}
PQ="-tls1_3 -groups X25519MLKEM768"

check() { # name, result (0 = pass)
  if [ "$2" -eq 0 ]; then
    echo "PASS $1"
  else
    echo "FAIL $1"
    sed -n '1,40p' "$OUT" | sed 's/^/    | /'
    fails=$((fails + 1))
  fi
}

start=$(date +%s)
request -tls1_3 -groups X25519MLKEM768
grep -q "Negotiated TLS1.3 group: X25519MLKEM768" "$OUT" && grep -q "TLS_AES_256_GCM_SHA384" "$OUT" \
  && grep -q "HTTP/1.1 200 OK" "$OUT"
check "1 TLS 1.3 + X25519MLKEM768 + GET /health ($(( $(date +%s) - start ))s)" $?

request -tls1_2
! grep -q "HTTP/1.1 200" "$OUT"
check "2 TLS 1.2 refused" $?

for grp in X25519 P-256; do
  request -tls1_3 -groups "$grp"
  ! grep -q "HTTP/1.1 200" "$OUT"
  check "3 classical group $grp refused" $?
done

if [ -n "$BACKEND" ]; then
  # shellcheck disable=SC2086
  send 'POST /api/chat HTTP/1.1\r\nHost: evil.attacker.example\r\nX-Forwarded-For: 1.2.3.4\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-sel4!' $PQ
  grep -q "HTTP/1.1 200 OK" "$OUT" && grep -q '"backend": "A"' "$OUT" && grep -q '"body_len": 11' "$OUT" \
    && grep -q "\"host\": \"$BACKEND:19001\"" "$OUT" && ! grep -q "x-forwarded-for" "$OUT"
  check "4a POST /api/chat -> backend A ($BACKEND:19001), Host fixed, X-Forwarded-For removed" $?

  # shellcheck disable=SC2086
  send 'GET /game/score?player=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' $PQ
  grep -q "HTTP/1.1 200 OK" "$OUT" && grep -q '"backend": "B"' "$OUT" && grep -q '"/game/score?player=1"' "$OUT"
  check "4b GET /game/score -> backend B ($BACKEND:19002)" $?

  n=0
  for probe in 'GET /game/../etc/passwd|400' 'GET /game/%2e%2e/secret|400' 'GET /admin|404' 'DELETE /health|405'; do
    n=$((n + 1))
    line=${probe%|*}
    want=${probe##*|}
    # shellcheck disable=SC2086
    send "$line HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n" $PQ
    grep -q "HTTP/1.1 $want" "$OUT"
    check "5.$n $line -> $want" $?
  done
  # shellcheck disable=SC2086
  send 'GET /health HTTP/1.1\r\nConnection: close\r\n\r\n' $PQ
  grep -q "HTTP/1.1 400" "$OUT"
  check "5.5 missing Host -> 400" $?
fi

if [ "$fails" -eq 0 ]; then
  echo "ALL HTTPS CHECKS PASSED"
else
  echo "$fails CHECK(S) FAILED"
  exit 1
fi
