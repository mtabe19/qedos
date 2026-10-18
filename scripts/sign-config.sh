#!/bin/sh
# Sign qedos configuration files with Ed25519 (LAW_011).
#
# Usage:
#   scripts/sign-config.sh [--key KEY.pem] [FILE.conf ...]
#
# With no FILE arguments, signs config/{dev,test,perf}/proxy.conf producing
# <file>.sig sidecars and writes the binary signed config config/sel4/proxy.sconf.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
O=$R/third_party/openssl-install/bin/openssl
export OPENSSL_CONF=$R/config/openssl-min.cnf

KEY=$R/config/keys/config-signing-key.pem
if [ "${1:-}" = "--key" ]; then
  KEY=$2
  shift 2
fi

sign_one() {
  f=$1
  sig_hex=$($O pkeyutl -sign -inkey "$KEY" -rawin -in "$f" | od -An -tx1 | tr -d ' \n')
  printf "%s\n" "$sig_hex" > "${f}.sig"
}

if [ $# -gt 0 ]; then
  for f in "$@"; do
    sign_one "$f"
  done
  exit 0
fi

for f in "$R/config/dev/proxy.conf" "$R/config/test/proxy.conf" "$R/config/perf/proxy.conf" "$R/config/sel4/proxy.conf"; do
  [ -f "$f" ] && sign_one "$f"
done

mkdir -p "$R/config/sel4"
python3 - "$R" "$O" "$KEY" "$R/config/sel4/proxy.conf" "$R/config/sel4/proxy.sconf" <<'PY'
import os, struct, subprocess, sys, tempfile

root, openssl_bin, key_pem, conf_path, out_sconf = sys.argv[1:]
METHODS = {"GET": 0, "HEAD": 1, "POST": 2, "PUT": 3, "DELETE": 4, "PATCH": 5, "OPTIONS": 6}

backends = []
backend_names = []
routes = []

with open(conf_path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if f[0] == "backend":
            name, addr = f[1], f[2]
            ip_str, port_str = addr.rsplit(":", 1)
            ip_bytes = bytes(int(x) for x in ip_str.split("."))
            port = int(port_str)
            backend_names.append(name)
            backends.append((ip_bytes, port))
        elif f[0] == "route":
            m = METHODS[f[1]]
            raw_pat = f[2]
            if raw_pat.endswith("*"):
                pat_kind = 1
                pat = raw_pat[:-1].encode("ascii")
            else:
                pat_kind = 0
                pat = raw_pat.encode("ascii")
            if f[3] == "health":
                act_kind, backend_id, max_body = 0, 0, 0
            else:
                act_kind = 1
                backend_id = backend_names.index(f[3])
                max_body = 0
                for kv in f[4:]:
                    if kv.startswith("max_body="):
                        max_body = int(kv.split("=", 1)[1])
            routes.append((m, pat_kind, act_kind, backend_id, max_body, pat))

payload = bytearray(b"PGS1")
payload += struct.pack(">BBBB", 1, len(backends), len(routes), 0)
for ip_bytes, port in backends:
    payload += ip_bytes + struct.pack(">H", port)
for m, pat_kind, act_kind, backend_id, max_body, pat in routes:
    payload += struct.pack(">BBBBQB", m, pat_kind, act_kind, backend_id, max_body, len(pat)) + pat

env = dict(os.environ, OPENSSL_CONF=os.path.join(root, "config/openssl-min.cnf"))
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(payload)
    tmp_path = tf.name
try:
    p = subprocess.run(
        [openssl_bin, "pkeyutl", "-sign", "-inkey", key_pem, "-rawin", "-in", tmp_path],
        capture_output=True,
        check=True,
        env=env,
    )
finally:
    os.unlink(tmp_path)
assert len(p.stdout) == 64
with open(out_sconf, "wb") as out:
    out.write(payload + p.stdout)
PY
echo "signed config/{dev,test,perf}/proxy.conf (.sig) and config/sel4/proxy.sconf"
