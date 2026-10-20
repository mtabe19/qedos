#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# One boot-test cycle on EC2, run from the developer's Mac (no helper instance):
#   disk image -> EBS snapshot (coldsnap) -> AMI (legacy-bios) -> instance -> console log -> clean up.
# The instance gets no public IP, no key pair and no inbound rules. Console output is read with
# `ec2 get-console-output --latest` and saved under build/ec2/.
#
# usage: tools/ec2/boot-test.sh [--keep] [--snapshot snap-xxxx]
#        tools/ec2/boot-test.sh --cleanup build/ec2/run-YYYYmmdd-HHMMSS.env
#   --keep             leave instance, AMI and snapshot in place (clean up later with --cleanup)
#   --snapshot ID      reuse an existing snapshot instead of uploading the disk image
#   --cleanup FILE     terminate / deregister / delete the resources recorded in FILE
# env:
#   AWS_PROFILE (default qedos), AWS_DEFAULT_REGION (default ap-northeast-1)
#   QEDOS_DISK_IMG         disk image (default build/disk/qedos-bios.img)
#   QEDOS_EC2_TYPE         instance type (default t3.medium; the image needs RAM at 0x7A000000)
#   QEDOS_EC2_SUBNET       subnet id (default: first default-for-az subnet)
#   QEDOS_CONSOLE_SECONDS  how long to collect console output after launch (default 300)
#   QEDOS_WAIT_TERMINATE   1: wait until the instance is terminated before deregistering the AMI
#                          (default 0: QEDOS ignores ACPI shutdown, so termination takes ~4 min;
#                          the root volume is DeleteOnTermination and goes away by itself)
#   QEDOS_OMIT_ZERO        1 (default): coldsnap --omit-zero-blocks, skipped automatically when
#                          EBS encryption by default is on (coldsnap README warns against it there)
# requires: aws (v2, logged in), coldsnap (cargo install --locked coldsnap)
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
export AWS_PROFILE="${AWS_PROFILE:-qedos}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"
export AWS_REGION="$AWS_DEFAULT_REGION"
export AWS_PAGER=""
IMG="${QEDOS_DISK_IMG:-$R/build/disk/qedos-bios.img}"
TYPE="${QEDOS_EC2_TYPE:-t3.medium}"
CONSOLE_SECONDS="${QEDOS_CONSOLE_SECONDS:-300}"
OMIT_ZERO="${QEDOS_OMIT_ZERO:-1}"
WAIT_TERMINATE="${QEDOS_WAIT_TERMINATE:-0}"
OUTDIR="$R/build/ec2"
STAMP=$(date +%Y%m%d-%H%M%S)
NAME="qedos-stage-e-$STAMP"
mkdir -p "$OUTDIR"

KEEP=0
SNAP=""
AMI=""
IID=""
REUSED_SNAP=0
STATE="$OUTDIR/run-$STAMP.env"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

save_state() {
  {
    echo "NAME=$NAME"
    echo "SNAP=$SNAP"
    echo "REUSED_SNAP=$REUSED_SNAP"
    echo "AMI=$AMI"
    echo "IID=$IID"
  } > "$STATE"
}

cleanup() {
  if [ -n "$IID" ]; then
    log "terminate instance $IID"
    if aws ec2 terminate-instances --instance-ids "$IID" >/dev/null; then
      if [ "${WAIT_TERMINATE:-0}" = 1 ]; then
        aws ec2 wait instance-terminated --instance-ids "$IID" || log "WARN: wait terminated failed"
      else
        log "termination requested (not waiting; check later with describe-instances)"
      fi
    else
      log "WARN: terminate failed"
    fi
  fi
  if [ -n "$AMI" ]; then
    log "deregister AMI $AMI"
    aws ec2 deregister-image --image-id "$AMI" >/dev/null || log "WARN: deregister failed"
  fi
  if [ -n "$SNAP" ] && [ "$REUSED_SNAP" = 0 ]; then
    log "delete snapshot $SNAP"
    aws ec2 delete-snapshot --snapshot-id "$SNAP" || log "WARN: delete-snapshot failed"
  fi
  log "cleanup done"
}

on_exit() {
  rc=$?
  trap - EXIT INT TERM
  if [ "$KEEP" = 1 ]; then
    log "resources kept (state: $STATE). Clean up later with: tools/ec2/boot-test.sh --cleanup $STATE"
  else
    cleanup
  fi
  exit "$rc"
}

# ---- options
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --snapshot) SNAP="$2"; REUSED_SNAP=1; shift 2 ;;
    --cleanup)
      # shellcheck disable=SC1090
      . "$2"
      cleanup
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v aws >/dev/null || { echo "aws CLI not found" >&2; exit 1; }
aws sts get-caller-identity --query Arn --output text >/dev/null || { echo "not logged in: run 'aws login --profile $AWS_PROFILE'" >&2; exit 1; }

SUBNET="${QEDOS_EC2_SUBNET:-}"
if [ -z "$SUBNET" ]; then
  SUBNET=$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true \
    --query 'Subnets[0].SubnetId' --output text)
  [ -n "$SUBNET" ] && [ "$SUBNET" != "None" ] || { echo "no default subnet; set QEDOS_EC2_SUBNET" >&2; exit 1; }
fi

trap on_exit EXIT
trap 'exit 130' INT TERM
log "run $NAME  type=$TYPE  subnet=$SUBNET  profile=$AWS_PROFILE  region=$AWS_REGION"

# ---- 1. snapshot (coldsnap uses the CLI's current short-term credentials)
if [ -z "$SNAP" ]; then
  [ -f "$IMG" ] || { echo "disk image not found: $IMG (run tools/mk-grub-disk.sh)" >&2; exit 1; }
  command -v coldsnap >/dev/null || { echo "coldsnap not found (cargo install --locked coldsnap)" >&2; exit 1; }
  OMIT_FLAG=""
  if [ "$OMIT_ZERO" = 1 ]; then
    if [ "$(aws ec2 get-ebs-encryption-by-default --query EbsEncryptionByDefault --output text)" = "False" ]; then
      OMIT_FLAG="--omit-zero-blocks"
    else
      log "EBS encryption by default is on: uploading zero blocks too"
    fi
  fi
  CSLOG="$OUTDIR/coldsnap-$STAMP.log"
  log "upload $IMG -> EBS snapshot (coldsnap $OMIT_FLAG, log: $CSLOG)"
  CREDS=$(aws configure export-credentials --format env)
  ( eval "$CREDS"; unset AWS_PROFILE; coldsnap upload --wait $OMIT_FLAG "$IMG"; echo "COLDSNAP_RC=$?" ) 2>&1 | tee "$CSLOG"
  # take the id even when the upload failed, so that cleanup can delete the partial snapshot
  SNAP=$(grep -o 'snap-[0-9a-f]*' "$CSLOG" | head -1 || true)
  save_state
  grep -q '^COLDSNAP_RC=0$' "$CSLOG" || { echo "coldsnap upload failed (see $CSLOG)" >&2; exit 1; }
  [ -n "$SNAP" ] || { echo "coldsnap did not return a snapshot id" >&2; exit 1; }
  aws ec2 create-tags --resources "$SNAP" --tags "Key=Name,Value=$NAME" "Key=project,Value=qedos-stage-e"
fi
save_state
log "snapshot $SNAP"

# ---- 2. AMI (legacy BIOS; ENA flag is required by Nitro types even though QEDOS has no ENA driver yet)
AMI=$(aws ec2 register-image --name "$NAME" --description "QEDOS Stage E boot test" \
  --architecture x86_64 --virtualization-type hvm --boot-mode legacy-bios --ena-support \
  --root-device-name /dev/xvda \
  --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=$SNAP,VolumeType=gp3,DeleteOnTermination=true}" \
  --query ImageId --output text)
save_state
aws ec2 create-tags --resources "$AMI" --tags "Key=project,Value=qedos-stage-e"
log "AMI $AMI"
aws ec2 wait image-available --image-ids "$AMI"

# ---- 3. instance (no public IP, no key pair, default security group)
IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --count 1 \
  --subnet-id "$SUBNET" --no-associate-public-ip-address \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=project,Value=qedos-stage-e}]" \
  --query 'Instances[0].InstanceId' --output text)
save_state
log "instance $IID ($TYPE) launched"
aws ec2 wait instance-running --instance-ids "$IID"
log "instance running; collecting console output for ${CONSOLE_SECONDS}s -> $OUTDIR/console-$STAMP.log"

# ---- 4. console output (refreshed by EC2 about once a minute)
CONSOLE="$OUTDIR/console-$STAMP.log"
: > "$CONSOLE"
shown=0
end=$(( $(date +%s) + CONSOLE_SECONDS ))
while [ "$(date +%s)" -lt "$end" ]; do
  aws ec2 get-console-output --instance-id "$IID" --latest --query Output --output text \
    > "$CONSOLE.tmp" 2>/dev/null || true
  if [ -s "$CONSOLE.tmp" ] && [ "$(cat "$CONSOLE.tmp")" != "None" ]; then
    mv "$CONSOLE.tmp" "$CONSOLE"
    total=$(wc -l < "$CONSOLE" | tr -d ' ')
    if [ "$total" -gt "$shown" ]; then
      tail -n +"$((shown + 1))" "$CONSOLE"
      shown=$total
    fi
  fi
  sleep 15
done
rm -f "$CONSOLE.tmp"
log "console log saved: $CONSOLE ($shown lines)"
