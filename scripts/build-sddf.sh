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
# mtabe19/qedos fork: QEDOS_HPET_FORCE_32BIT=1 builds tsc_hpet in its 32-bit mode on a 64-bit HPET
# (for testing on QEMU). Output then goes to build/echo-$BOARD-hpet32.
SUFFIX=""
# mtabe19/qedos fork: I/O APIC pin of the HPET timer IRQ (x86, default 23: EC2 timer 0 reaches pins 16-23 only).
# build-sel4.sh passes the same value to meta_proofgate.py. (sDDF's own echo_server system keeps pin 2, so the
# echo_server image itself is not used; only its driver ELFs are.)
HPET_PIN=${QEDOS_HPET_IOAPIC_PIN:-23}
SDDF_CFLAGS="-DHPET_IOAPIC_PIN=$HPET_PIN"
if [ "${QEDOS_HPET_FORCE_32BIT:-0}" = 1 ]; then
  SUFFIX=-hpet32
  SDDF_CFLAGS="$SDDF_CFLAGS -DHPET_FORCE_32BIT"
fi
if [ ! -d "$SDDF/.git" ]; then
  git clone -q https://github.com/au-ts/sddf "$SDDF"
fi
git -C "$SDDF" checkout -q -f "$SDDF_REV"
# mtabe19/qedos fork: apply local sDDF patches (patches/sddf/*.patch, in name order)
for p in "$R"/patches/sddf/*.patch; do
  [ -f "$p" ] || continue
  git -C "$SDDF" apply "$p"
done
CFLAGS="$SDDF_CFLAGS" make -C "$SDDF/examples/echo_server" \
  MICROKIT_SDK="$R/third_party/microkit/microkit-sdk-2.3.1" \
  MICROKIT_BOARD="$BOARD" MICROKIT_CONFIG=debug TOOLCHAIN=clang \
  BUILD_DIR="$R/build/echo-$BOARD$SUFFIX"
ls "$R/build/echo-$BOARD$SUFFIX/eth_driver.elf"
case "$BOARD" in x86_64_*) ;; *) ls "$R/build/echo-$BOARD$SUFFIX/$BOARD.dtb" ;; esac
