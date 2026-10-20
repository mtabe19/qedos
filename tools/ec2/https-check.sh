#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# HTTPS checks against QEDOS running on EC2, the same checks as SEL4_001..003 of tests/test_sel4.py:
#   1. TLS 1.3 + X25519MLKEM768 + GET /health -> 200 "ok" (TLS_AES_256_GCM_SHA384)
#   2. TLS 1.2 is refused
#   3. classical key exchange (X25519 only, P-256 only) is refused
# Run it from the developer's machine while tools/ec2/boot-test.sh collects the console, after
# "DHCP lease acquired" appeared. The instance's security group must allow TCP 8443 from this machine.
#
# usage: tools/ec2/https-check.sh PUBLIC_IP [PORT]
# env:   OPENSSL         openssl 3.5+ with ML-KEM (default: third_party/openssl-install, then Homebrew openssl@3)
#        QEDOS_TIMEOUT   seconds per connection (default 20)
set -u
R=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -ge 1 ] || { echo "usage: $0 PUBLIC_IP [PORT]" >&2; exit 2; }
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

# request [s_client options...]: send a GET /health and keep the output in $OUT (perl alarm as a timeout)
request() {
  printf 'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' |
    perl -e 'alarm shift; exec @ARGV' "$TIMEOUT" \
      "$O" s_client -connect "$HOST:$PORT" -ign_eof "$@" > "$OUT" 2>&1
}

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

if [ "$fails" -eq 0 ]; then
  echo "ALL HTTPS CHECKS PASSED"
else
  echo "$fails CHECK(S) FAILED"
  exit 1
fi
