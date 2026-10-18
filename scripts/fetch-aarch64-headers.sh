#!/bin/sh
# Fetch glibc/Linux *headers only* (no libraries) for cross-compiling the freestanding OpenSSL
# for aarch64 on hosts without an aarch64 sysroot (e.g. macOS). The libc shim implements the
# glibc ABI that OpenSSL expects, so glibc-compatible headers are required at compile time.
# Output: third_party/sysroot-aarch64/usr/include (+ aarch64-linux-gnu multiarch dir).
# SHA-256 values below were recorded on first download (TLS, trust-on-first-use) and then pinned.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
DEST="$R/third_party/sysroot-aarch64"
BASE=https://deb.debian.org/debian/pool/main
PKGS="g/glibc/libc6-dev_2.41-12+deb13u4_arm64.deb:71e373cb5e9da975b02fb4af555929cb1977560e2dd8245de4eb8a7b03677a08
l/linux/linux-libc-dev_6.1.176-1_arm64.deb:eeca5ec13bed7206f8171fab9a48e84119dcc20cc79557f104628447a524ad10"
[ -d "$DEST/usr/include" ] && { echo "already present: $DEST"; exit 0; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DEST"
for entry in $PKGS; do
  path=${entry%%:*}; sha=${entry##*:}; f=$TMP/$(basename "$path")
  curl -fL -o "$f" "$BASE/$path"
  echo "$sha  $f" | shasum -a 256 -c -
  d=$TMP/x_$(basename "$path"); mkdir -p "$d"
  (cd "$d" && tar xf "$f" && tar xf data.tar.* -C "$DEST" ./usr/include)
done
ls "$DEST/usr/include" | head -3
