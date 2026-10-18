#!/bin/sh
# Wrapper: run the user-space QEMU extracted into tools/qemu (no root needed).
R=$(cd "$(dirname "$0")/.." && pwd)
export LD_LIBRARY_PATH=$R/tools/qemu/usr/lib/x86_64-linux-gnu
export QEMU_MODULE_DIR=$R/tools/qemu/usr/lib/x86_64-linux-gnu/qemu
exec $R/tools/qemu/usr/bin/qemu-system-x86_64 -L $R/tools/qemu/usr/share/qemu -L $R/tools/qemu/usr/share/seabios "$@"
