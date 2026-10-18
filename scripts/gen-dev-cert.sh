#!/bin/sh
# TEMPORARY self-signed ECDSA P-256 certificate for localhost testing only.
# Not a production trust anchor; production uses a CA-issued X.509 chain.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
O=$R/third_party/openssl-install/bin/openssl
D=$R/config/dev
export OPENSSL_CONF=$R/config/openssl-min.cnf
mkdir -p "$D"
$O req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$D/key.pem" -out "$D/cert.pem" 2>/dev/null
chmod 600 "$D/key.pem"
echo "wrote $D/cert.pem $D/key.pem"
