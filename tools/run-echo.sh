#!/bin/sh
# Boot a Microkit x86_64 image in QEMU TCG with a virtio-net-pci at slot 0x2 (sDDF hard-codes it).
# usage: run-echo.sh LOADER_IMG SERIAL_LOG "hostfwd rules" [seconds]
R=$(cd "$(dirname "$0")/.." && pwd)
exec timeout ${4:-120} "$R/tools/qemu.sh" -machine q35 \
  -kernel "$R/third_party/microkit/microkit-sdk-2.3.1/board/x86_64_generic/debug/elf/sel4_32.elf" -initrd "$1" \
  -m 2G -cpu qemu64,+fsgsbase,+pdpe1gb,+xsave,+xsaveopt,+rdrand -display none -serial "file:$2" -monitor none -no-reboot \
  -netdev "user,id=netdev0,$3" -device virtio-net-pci,netdev=netdev0,addr=0x2.0,romfile=
