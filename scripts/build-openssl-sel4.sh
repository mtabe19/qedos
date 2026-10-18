#!/bin/sh
# Reproducible freestanding build of OpenSSL 3.6.1 for x86_64 seL4/Microkit PDs.
set -eu

R=$(cd "$(dirname "$0")/.." && pwd)
V=3.6.1
SHA=b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e
TARBALL="$R/third_party/openssl-$V.tar.gz"
SRC_DIR="$R/build/openssl-sel4-src"
PREFIX="$R/third_party/openssl-sel4"

if [ -x "$R/tools/conda/bin/clang" ]; then
    export CC="$R/tools/conda/bin/clang"
    export AR="$R/tools/conda/bin/llvm-ar"
    export RANLIB="$R/tools/conda/bin/llvm-ranlib"
else
    export CC="${CC:-clang}"
fi

[ -f "$TARBALL" ] || { echo "Missing $TARBALL" >&2; exit 1; }
echo "$SHA  $TARBALL" | sha256sum -c -

rm -rf "$SRC_DIR" "$PREFIX"
mkdir -p "$SRC_DIR" "$PREFIX"
tar xzf "$TARBALL" --strip-components=1 -C "$SRC_DIR"

cd "$SRC_DIR"
./Configure linux-x86_64 \
  --prefix="$PREFIX" \
  --libdir=lib \
  -mno-red-zone -fno-stack-protector -ffreestanding \
  no-threads no-sock no-posix-io no-dso no-engine no-stdio no-async no-afalgeng \
  no-autoerrinit no-autoload-config no-dgram no-dtls no-filenames no-http \
  no-legacy no-ocsp no-padlockeng no-quic no-shared no-srp no-srtp no-tests \
  no-ts no-ui-console no-uplink no-weak-ssl-ciphers no-docs no-comp no-ssl3 \
  enable-ec_nistp_64_gcc_128 \
  -DOPENSSL_NO_SECURE_MEMORY -Dgetauxval=ossl_sel4_getauxval

make -j"$(nproc)" build_libs
make install_dev

ls -lh "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a"
