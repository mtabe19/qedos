#!/bin/sh
# Wrapper: run bundled user-space QEMU if present, otherwise fall back to system qemu-system-x86_64 (e.g. macOS Homebrew).
R=$(cd "$(dirname "$0")/.." && pwd)
if [ -x "$R/tools/qemu/usr/bin/qemu-system-x86_64" ]; then
  export LD_LIBRARY_PATH=$R/tools/qemu/usr/lib/x86_64-linux-gnu
  export QEMU_MODULE_DIR=$R/tools/qemu/usr/lib/x86_64-linux-gnu/qemu
  exec "$R/tools/qemu/usr/bin/qemu-system-x86_64" -L "$R/tools/qemu/usr/share/qemu" -L "$R/tools/qemu/usr/share/seabios" "$@"
else
  exec qemu-system-x86_64 "$@"
fi
