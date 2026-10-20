#!/bin/sh
# Added in the mtabe19/qedos fork (Stage E, EC2 boot experiments).
# Test backends for QEDOS on EC2 (M5-5): an Amazon Linux 2023 instance on a fixed ENI (fixed private
# IPv4, written into the signed config, see config/ec2-t3/proxy.conf.in) that runs tests/backend.py
# (backends A on 19001 and B on 19002) from user-data. No SSH, key pair or IAM role. The ENI's
# security group allows TCP 19001-19002 from QEDOS's security group only (docs/STAGE_E_EC2.md 2.7).
# As a safety net the instance terminates itself after QEDOS_BACKEND_MINUTES.
#
# usage: tools/ec2/backend.sh up      launch the instance (state: build/ec2/backend-run.env)
#        tools/ec2/backend.sh down    terminate it
# env:   QEDOS_BACKEND_ENI      fixed ENI of the backend (from build/ec2/eni.env)
#        QEDOS_BACKEND_MINUTES  self-termination after this many minutes (default 120)
#        QEDOS_BACKEND_TYPE     instance type (default t3.micro)
#        QEDOS_BACKEND_SECONDS  max wait for the "backends up" line on the console (default 360)
#        AWS_PROFILE (default qedos), AWS_DEFAULT_REGION (default ap-northeast-1)
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
export AWS_PROFILE="${AWS_PROFILE:-qedos}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"
export AWS_REGION="$AWS_DEFAULT_REGION"
export AWS_PAGER=""
TYPE="${QEDOS_BACKEND_TYPE:-t3.micro}"
MINUTES="${QEDOS_BACKEND_MINUTES:-120}"
MAX_SECONDS="${QEDOS_BACKEND_SECONDS:-360}"
OUTDIR="$R/build/ec2"
STATE="$OUTDIR/backend-run.env"
STAMP=$(date +%Y%m%d-%H%M%S)
NAME="qedos-backend-$STAMP"
mkdir -p "$OUTDIR"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

[ $# -eq 1 ] || { echo "usage: $0 up|down" >&2; exit 2; }
aws sts get-caller-identity --query Arn --output text >/dev/null || { echo "not logged in: run 'aws login --profile $AWS_PROFILE'" >&2; exit 1; }

case "$1" in
  down)
    [ -f "$STATE" ] || { echo "no $STATE (nothing to terminate)" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$STATE"
    log "terminate backend instance $IID"
    aws ec2 terminate-instances --instance-ids "$IID" >/dev/null
    rm -f "$STATE"
    log "termination requested (the ENI becomes available again once it is terminated)"
    exit 0 ;;
  up) ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac

[ ! -f "$STATE" ] || { echo "$STATE exists: run '$0 down' first" >&2; exit 1; }
ENI="${QEDOS_BACKEND_ENI:-}"
[ -n "$ENI" ] || { echo "QEDOS_BACKEND_ENI is required (see build/ec2/eni.env)" >&2; exit 1; }
ENI_STATUS=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" \
  --query 'NetworkInterfaces[0].Status' --output text)
if [ "$ENI_STATUS" != available ]; then
  log "ENI $ENI is $ENI_STATUS; waiting until it is available"
  aws ec2 wait network-interface-available --network-interface-ids "$ENI"
fi
BIP=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" \
  --query 'NetworkInterfaces[0].PrivateIpAddress' --output text)
AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)

# ---- user-data: tests/backend.py on 0.0.0.0, self-termination as a safety net
UDATA="$OUTDIR/backend-userdata-$STAMP.sh"
{
  echo '#!/bin/bash'
  echo "shutdown -h +$MINUTES"
  echo 'mkdir -p /opt/qedos'
  echo "base64 -d > /opt/qedos/backend.py <<'B64'"
  base64 < "$R/tests/backend.py"
  echo 'B64'
  # the unit's output goes to the journal and from there to the serial console
  echo 'systemd-run --unit qedos-backend --setenv=QEDOS_BACKEND_BIND=0.0.0.0 --setenv=PYTHONUNBUFFERED=1 /usr/bin/python3 /opt/qedos/backend.py'
  echo 'sleep 5; systemctl is-active qedos-backend && echo "QEDOS-BACKEND: backends up on 0.0.0.0:19001,19002"'
} > "$UDATA"

log "run $NAME  type=$TYPE  ami=$AMI (AL2023)  eni=$ENI  private IPv4=$BIP  self-terminate in ${MINUTES}min"
IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --count 1 \
  --network-interfaces "DeviceIndex=0,NetworkInterfaceId=$ENI" \
  --instance-initiated-shutdown-behavior terminate \
  --user-data "file://$UDATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=project,Value=qedos-stage-e}]" \
  --query 'Instances[0].InstanceId' --output text)
{ echo "IID=$IID"; echo "BIP=$BIP"; } > "$STATE"
log "instance $IID launched (state: $STATE); waiting for the backends (max ${MAX_SECONDS}s)"

end=$(( $(date +%s) + MAX_SECONDS ))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep 20
  if aws ec2 get-console-output --instance-id "$IID" --latest --query Output --output text 2>/dev/null |
       grep -q 'QEDOS-BACKEND: backends up'; then
    log "backends up at $BIP:19001 (A) and $BIP:19002 (B)"
    exit 0
  fi
done
log "WARN: 'backends up' not seen on the console within ${MAX_SECONDS}s (the console may lag; the instance is kept)"
