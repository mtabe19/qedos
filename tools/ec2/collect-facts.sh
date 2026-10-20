#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# Collect hardware facts of an EC2 instance type with a throw-away Amazon Linux 2023 instance:
# PCI devices (ENA BARs / MSI-X), /proc/iomem, ACPI tables (HPET?), clock sources, CPU flags.
# A user-data script prints them to the serial console between markers, waits 3 minutes so that
# `ec2 get-console-output --latest` can pick them up, and powers the instance off (shutdown behaviour
# = stop, so the console output captured at stop is also kept). No SSH, key pair, public IP or IAM
# role is used. The facts are saved to build/ec2/facts-<type>-<stamp>.txt and the instance is
# terminated at the end.
#
# usage: tools/ec2/collect-facts.sh
# env:   AWS_PROFILE (default qedos), AWS_DEFAULT_REGION (default ap-northeast-1)
#        QEDOS_EC2_TYPE (default t3.medium), QEDOS_EC2_SUBNET (default: first default-for-az subnet)
#        QEDOS_FACTS_SECONDS (max wait for the end marker, default 420)
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
export AWS_PROFILE="${AWS_PROFILE:-qedos}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"
export AWS_REGION="$AWS_DEFAULT_REGION"
export AWS_PAGER=""
TYPE="${QEDOS_EC2_TYPE:-t3.medium}"
MAX_SECONDS="${QEDOS_FACTS_SECONDS:-420}"
OUTDIR="$R/build/ec2"
STAMP=$(date +%Y%m%d-%H%M%S)
NAME="qedos-facts-$STAMP"
CONSOLE="$OUTDIR/facts-console-$TYPE-$STAMP.log"
FACTS="$OUTDIR/facts-$TYPE-$STAMP.txt"
UDATA="$OUTDIR/facts-userdata-$STAMP.sh"
mkdir -p "$OUTDIR"
IID=""

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
on_exit() {
  rc=$?
  trap - EXIT INT TERM
  if [ -n "$IID" ]; then
    log "terminate instance $IID (not waiting)"
    aws ec2 terminate-instances --instance-ids "$IID" >/dev/null || log "WARN: terminate failed"
  fi
  exit "$rc"
}

aws sts get-caller-identity --query Arn --output text >/dev/null || { echo "not logged in: run 'aws login --profile $AWS_PROFILE'" >&2; exit 1; }
SUBNET="${QEDOS_EC2_SUBNET:-}"
if [ -z "$SUBNET" ]; then
  SUBNET=$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
fi
AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)

# ---- user-data: everything goes to /dev/ttyS0 between markers, then power off
cat > "$UDATA" <<'UD'
#!/bin/bash
# Plain stdout: cloud-init output reaches the serial console through the journal
# (lines are prefixed with "[ time] cloud-init[pid]: "). Writing to /dev/ttyS0 directly
# blocked while getty owned the port.
exec 2>&1
sleep 20   # let the boot messages settle so the facts are at the end of the console log
echo "===QEDOS-FACTS-BEGIN==="
sec() { echo; echo "### $*"; }
sec uname; uname -a
sec instance-type; cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null; cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null
sec cpu; grep -m1 'model name' /proc/cpuinfo; nproc; grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E -x 'tsc|constant_tsc|nonstop_tsc|tsc_deadline_timer|tsc_known_freq|x2apic|apic|hypervisor|rdrand|rdseed|fsgsbase|pdpe1gb|xsave|xsaveopt|invpcid|pcid|smep|smap|vmx' | tr '\n' ' '; echo
sec clocksource; cat /sys/devices/system/clocksource/clocksource0/available_clocksource /sys/devices/system/clocksource/clocksource0/current_clocksource
sec dmesg-clock; dmesg | grep -i -E 'hpet|tsc|clocksource|kvm-clock|apic|x2apic|ioapic|acpi: (hpet|mcfg|dmar|madt|srat)|iommu|dmar|pci_bus 0000:00' | head -80
sec acpi-tables; ls /sys/firmware/acpi/tables
sec hpet-table; if [ -r /sys/firmware/acpi/tables/HPET ]; then od -An -tx1 /sys/firmware/acpi/tables/HPET; else echo "no HPET table"; fi
sec iomem; cat /proc/iomem
sec ioports; cat /proc/ioports | head -40
sec pci-sysfs
for d in /sys/bus/pci/devices/*; do
  echo "$(basename $d) vendor=$(cat $d/vendor) device=$(cat $d/device) class=$(cat $d/class) irq=$(cat $d/irq) driver=$(basename $(readlink $d/driver 2>/dev/null) 2>/dev/null)"
  awk '$1 != "0x0000000000000000" {print "    res" NR-1 ": " $0}' $d/resource
  [ -d $d/msi_irqs ] && echo "    msi_irqs: $(ls $d/msi_irqs | tr '\n' ' ')"
done
if command -v lspci >/dev/null 2>&1; then sec lspci; lspci -nn; fi
for d in /sys/bus/pci/devices/*; do
  if [ "$(cat $d/vendor)" = "0x1d0f" ] && [ "$(cat $d/class | cut -c1-6)" = "0x0200" ]; then
    sec "ena-config $(basename $d)"; od -An -tx1 -N 256 $d/config
    if command -v lspci >/dev/null 2>&1; then lspci -vv -s "$(basename $d)"; fi
  fi
done
sec interrupts; head -30 /proc/interrupts
sec serial; cat /proc/tty/driver/serial 2>/dev/null | head -5
echo
echo "===QEDOS-FACTS-END==="
sleep 180   # keep running so that get-console-output --latest sees the facts
poweroff
UD

trap on_exit EXIT
trap 'exit 130' INT TERM
log "run $NAME  type=$TYPE  ami=$AMI (AL2023)  subnet=$SUBNET"
IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --count 1 \
  --subnet-id "$SUBNET" --no-associate-public-ip-address \
  --instance-initiated-shutdown-behavior stop \
  --user-data "file://$UDATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=project,Value=qedos-stage-e}]" \
  --query 'Instances[0].InstanceId' --output text)
log "instance $IID launched; waiting for ===QEDOS-FACTS-END=== (max ${MAX_SECONDS}s)"

# keep the longest console output seen so far; a shorter (or empty) answer never overwrites it
: > "$CONSOLE"
take() {
  if [ -s "$CONSOLE.tmp" ] && [ "$(cat "$CONSOLE.tmp")" != "None" ] && \
     [ "$(wc -c < "$CONSOLE.tmp")" -gt "$(wc -c < "$CONSOLE")" ]; then
    mv "$CONSOLE.tmp" "$CONSOLE"
  fi
  rm -f "$CONSOLE.tmp"
}
end=$(( $(date +%s) + MAX_SECONDS ))
found=0
while [ "$(date +%s)" -lt "$end" ]; do
  sleep 20
  aws ec2 get-console-output --instance-id "$IID" --latest --query Output --output text \
    > "$CONSOLE.tmp" 2>/dev/null || true
  take
  log "console: $(wc -l < "$CONSOLE" | tr -d ' ') lines (longest so far)"
  if grep -q '===QEDOS-FACTS-END===' "$CONSOLE"; then found=1; break; fi
done
if [ "$found" = 0 ]; then
  log "end marker not seen with --latest; waiting for the instance to stop and reading the stored output"
  aws ec2 wait instance-stopped --instance-ids "$IID" || log "WARN: wait stopped failed"
  aws ec2 get-console-output --instance-id "$IID" --query Output --output text \
    > "$CONSOLE.tmp" 2>/dev/null || true
  take
  grep -q '===QEDOS-FACTS-END===' "$CONSOLE" && found=1
fi
if [ "$found" = 1 ]; then
  sed -n '/===QEDOS-FACTS-BEGIN===/,/===QEDOS-FACTS-END===/p' "$CONSOLE" | tr -d '\r' | \
    sed -E 's/^\[ *[0-9.]+\] [A-Za-z0-9_.-]+\[[0-9]+\]: ?//' > "$FACTS"
  log "facts saved: $FACTS ($(wc -l < "$FACTS" | tr -d ' ') lines)"
else
  log "end marker not seen; partial console log: $CONSOLE"
  exit 1
fi
