#!/bin/sh
# Reproducible build of the pinned OpenSSL used by pg-proxy.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
V=3.6.1
SHA=b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e
cd "$R/third_party"
[ -f openssl-$V.tar.gz ] || curl -fL -o openssl-$V.tar.gz https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz
echo "$SHA  openssl-$V.tar.gz" | sha256sum -c -
rm -rf openssl-$V && tar xzf openssl-$V.tar.gz && cd openssl-$V
./Configure --prefix="$R/third_party/openssl-install" --libdir=lib no-shared no-tests no-docs \
  no-comp no-ssl3 no-weak-ssl-ciphers no-legacy no-engine enable-ec_nistp_64_gcc_128
make -j"$(nproc)" && make install_sw
"$R/third_party/openssl-install/bin/openssl" version
