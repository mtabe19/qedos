#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# Build a raw BIOS-bootable disk image: MBR + GRUB (i386-pc) + one FAT32 partition holding
# sel4_32.elf and loader.img. The same image is meant to be written to an EBS volume.
# Works on macOS (no grub-install / loop devices needed): grub-mkimage + mtools + python3.
#
# usage: tools/mk-grub-disk.sh [OUT_IMG]          (default: build/disk/qedos-bios.img)
# env:   QEDOS_SEL4_DIR   directory with sel4_32.elf(.gz) and loader.img(.gz) (default build/sel4)
#        QEDOS_MB         1 or 2: multiboot protocol used by GRUB (default 2)
#        GRUB_MKIMAGE     grub-mkimage command (default: i686-elf-grub-mkimage, else grub-mkimage)
#        GRUB_I386_PC_DIR GRUB i386-pc module directory (default: from brew i686-elf-grub, else /usr/lib/grub/i386-pc)
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
SEL4_DIR=${QEDOS_SEL4_DIR:-$R/build/sel4}
OUT=${1:-$R/build/disk/qedos-bios.img}
MB=${QEDOS_MB:-2}
PART_START=2048            # sectors; leaves ~1 MiB for GRUB core.img after the MBR

if [ -z "${GRUB_MKIMAGE:-}" ]; then
  if command -v i686-elf-grub-mkimage >/dev/null 2>&1; then GRUB_MKIMAGE=i686-elf-grub-mkimage
  else GRUB_MKIMAGE=grub-mkimage; fi
fi
if [ -z "${GRUB_I386_PC_DIR:-}" ]; then
  if command -v brew >/dev/null 2>&1 && [ -d "$(brew --prefix i686-elf-grub 2>/dev/null)/lib/i686-elf/grub/i386-pc" ]; then
    GRUB_I386_PC_DIR="$(brew --prefix i686-elf-grub)/lib/i686-elf/grub/i386-pc"
  else
    GRUB_I386_PC_DIR=/usr/lib/grub/i386-pc
  fi
fi
for t in "$GRUB_MKIMAGE" mformat mmd mcopy python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 1; }
done
[ -f "$GRUB_I386_PC_DIR/boot.img" ] || { echo "boot.img not found in $GRUB_I386_PC_DIR" >&2; exit 1; }

# 1. Kernel and Microkit loader image (decompress the committed .gz if needed)
for f in sel4_32.elf loader.img; do
  if [ ! -f "$SEL4_DIR/$f" ] && [ -f "$SEL4_DIR/$f.gz" ]; then
    gzip -dc "$SEL4_DIR/$f.gz" > "$SEL4_DIR/$f"
  fi
  [ -f "$SEL4_DIR/$f" ] || { echo "missing $SEL4_DIR/$f" >&2; exit 1; }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/qedos-disk.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "$(dirname "$OUT")"

# 2. GRUB config (serial console on COM1, same port seL4 uses for debug output)
if [ "$MB" = 1 ]; then MBK=multiboot; MBM=module; else MBK=multiboot2; MBM=module2; fi
cat > "$WORK/grub.cfg" <<CFG
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console
set timeout=0
set default=0
menuentry "QEDOS (seL4 Microkit, $MBK)" {
  echo "GRUB: loading sel4_32.elf + loader.img ($MBK)"
  $MBK /boot/sel4_32.elf
  $MBM /boot/loader.img
  boot
}
CFG
cat > "$WORK/early.cfg" <<CFG
set root=(hd0,msdos1)
set prefix=(hd0,msdos1)/boot/grub
CFG

# 3. GRUB core.img (placed right after the MBR, sector 1 onwards)
"$GRUB_MKIMAGE" -O i386-pc -d "$GRUB_I386_PC_DIR" -o "$WORK/core.img" \
  -p '(hd0,msdos1)/boot/grub' -c "$WORK/early.cfg" \
  biosdisk part_msdos fat normal configfile echo test serial terminal multiboot multiboot2 boot

# 4. Size the disk: payload + GRUB modules + margin, at least 64 MiB
payload=$(( $(wc -c < "$SEL4_DIR/sel4_32.elf") + $(wc -c < "$SEL4_DIR/loader.img") ))
size_mib=$(( payload / 1048576 + 48 ))
[ "$size_mib" -lt 64 ] && size_mib=64
total_sectors=$(( size_mib * 2048 ))
rm -f "$OUT"
dd if=/dev/zero of="$OUT" bs=1048576 count="$size_mib" 2>/dev/null

# 5. FAT32 filesystem inside the partition (mtools, offset = PART_START sectors)
export MTOOLS_SKIP_CHECK=1
IMG="$OUT@@$(( PART_START * 512 ))"
mformat -i "$IMG" -F -v QEDOS -H "$PART_START" ::
mmd -i "$IMG" ::/boot ::/boot/grub
mcopy -i "$IMG" "$SEL4_DIR/sel4_32.elf" "$SEL4_DIR/loader.img" ::/boot/
mcopy -i "$IMG" "$WORK/grub.cfg" ::/boot/grub/
mcopy -i "$IMG" -s "$GRUB_I386_PC_DIR" ::/boot/grub/

# 6. MBR: GRUB boot.img code + one bootable FAT32 (LBA) partition; core.img at sector 1
python3 - "$OUT" "$GRUB_I386_PC_DIR/boot.img" "$WORK/core.img" "$PART_START" "$total_sectors" <<'PY'
import struct, sys
disk, boot, core = sys.argv[1], sys.argv[2], sys.argv[3]
start, total = int(sys.argv[4]), int(sys.argv[5])
b = open(boot, "rb").read()
c = open(core, "rb").read()
assert len(b) == 512, "unexpected boot.img size"
assert len(c) <= (start - 1) * 512, "core.img (%d bytes) does not fit before the partition" % len(c)
mbr = bytearray(512)
mbr[:440] = b[:440]
mbr[446:462] = bytes([0x80, 0xFE, 0xFF, 0xFF, 0x0C, 0xFE, 0xFF, 0xFF]) + struct.pack("<II", start, total - start)
mbr[510:512] = b"\x55\xaa"
with open(disk, "r+b") as f:
    f.seek(0); f.write(mbr)
    f.seek(512); f.write(c)
print("core.img: %d bytes (%d sectors)" % (len(c), (len(c) + 511) // 512))
PY

ls -l "$OUT"
echo "OK: $OUT ($size_mib MiB, $MBK)"
