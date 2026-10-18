#!/bin/sh
# Boot a Microkit aarch64 image in QEMU (virt, hypervisor mode, virtio-net-device on mmio bus 0).
# usage: run-aarch64.sh LOADER_IMG SERIAL_LOG "hostfwd rules" [seconds]
set -eu
IMG="$1"
CMD="qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 -m 2G -nographic \
  -serial file:$2 -monitor none -no-reboot -global virtio-mmio.force-legacy=false \
  -device loader,file=$IMG,addr=0x70000000,cpu-num=0 \
  -netdev user,id=netdev0,$3 -device virtio-net-device,netdev=netdev0,bus=virtio-mmio-bus.0"
if command -v timeout >/dev/null 2>&1; then exec timeout "${4:-120}" $CMD; fi
$CMD &
Q=$!
( sleep "${4:-120}"; kill $Q 2>/dev/null ) &
trap 'kill $Q 2>/dev/null' TERM INT
wait $Q
