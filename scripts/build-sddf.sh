#!/bin/sh
# Build the sDDF echo_server example for a Microkit board (aarch64 or x86_64_generic). It provides the
# prebuilt driver / virtualiser ELFs, lwIP + util libraries and the board DTB (aarch64 only, x86 has
# no DTB) that build-sel4.sh reuses. Output: build/echo-$QEDOS_BOARD.
# mtabe19/qedos fork: x86_64_generic support added (Stage E, docs/STAGE_E_EC2.md).
# Requires: Microkit SDK (third_party/microkit), clang + lld + llvm-objcopy, dtc, python venv with sdfgen.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
export PATH="/opt/homebrew/opt/lld/bin:/opt/homebrew/opt/llvm/bin:$R/third_party/venv/bin:$PATH"
BOARD=${QEDOS_BOARD:-qemu_virt_aarch64}
SDDF_REV=12f66678527b7f7b5ec0b90280058b9d83f8c295
SDDF="$R/third_party/sddf"
if [ ! -d "$SDDF/.git" ]; then
  git clone -q https://github.com/au-ts/sddf "$SDDF"
fi
git -C "$SDDF" checkout -q "$SDDF_REV"
make -C "$SDDF/examples/echo_server" \
  MICROKIT_SDK="$R/third_party/microkit/microkit-sdk-2.3.1" \
  MICROKIT_BOARD="$BOARD" MICROKIT_CONFIG=debug TOOLCHAIN=clang \
  BUILD_DIR="$R/build/echo-$BOARD"
ls "$R/build/echo-$BOARD/eth_driver.elf"
case "$BOARD" in x86_64_*) ;; *) ls "$R/build/echo-$BOARD/$BOARD.dtb" ;; esac
