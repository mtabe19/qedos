#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# Boot a disk image made by tools/mk-grub-disk.sh in QEMU (SeaBIOS -> GRUB -> seL4), with the same
# machine, CPU flags and virtio-net-pci slot as tools/run-echo.sh. The disk is opened with snapshot=on,
# so the image file is never modified.
# usage: run-disk.sh DISK_IMG SERIAL_LOG "hostfwd rules" [seconds]
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
IMG="$1"
[ -f "$IMG" ] || { echo "disk image not found: $IMG (run tools/mk-grub-disk.sh)" >&2; exit 1; }
if command -v timeout >/dev/null 2>&1; then
  exec timeout "${4:-120}" "$R/tools/qemu.sh" -machine q35 \
    -drive "file=$IMG,format=raw,snapshot=on" \
    -m 2G -cpu qemu64,+fsgsbase,+pdpe1gb,+xsave,+xsaveopt,+rdrand -display none -serial "file:$2" -monitor none -no-reboot \
    -netdev "user,id=netdev0,$3" -device virtio-net-pci,netdev=netdev0,addr=0x2.0,romfile=
else
  exec "$R/tools/qemu.sh" -machine q35 \
    -drive "file=$IMG,format=raw,snapshot=on" \
    -m 2G -cpu qemu64,+fsgsbase,+pdpe1gb,+xsave,+xsaveopt,+rdrand -display none -serial "file:$2" -monitor none -no-reboot \
    -netdev "user,id=netdev0,$3" -device virtio-net-pci,netdev=netdev0,addr=0x2.0,romfile=
fi
