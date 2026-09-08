#!/usr/bin/env bash
#
# Launch the full evaluation across 20 EC2 workers.
#
#   ./scripts/launch-run.sh                 launch everything
#   ./scripts/launch-run.sh --dry-run       print the plan, launch nothing
#   ./scripts/launch-run.sh --only W07      launch one worker
#
# Each worker boots, provisions itself, runs ONE assigned slice of the run,
# publishes its results to S3, and terminates. Nothing needs a live operator:
# the machine you launch from can be closed the moment the last instance is up.
#
# THE ALLOCATION IS NOT EVEN, AND SHOULD NOT BE. Work is split where it is
# expensive, measured on c6i.8xlarge:
#
#   ZK-Redact Exp 2   119 arms: the 84 of (3 conflict x 7 B_R x 4 Delta_R), plus
#                     35 from the workload-size axis, which is swept on the
#                     headline arm alone (7 B_R x 5 shorter workloads).
#                     84 x 5000 x 0.106 s/auth = 12.4 h, and the shorter
#                     workloads add 7 x 4350 x 0.106 s = 0.9 h -> 13.3 h
#                     setup is 9.5 s, so splitting it is almost free -> 10 hosts
#   Ref[22]           31m45s of setup EVERY time it starts, so its three
#                     experiments get three hosts rather than one host paying
#                     that cost three times over
#   Ref[13] Exp 3     12 setups (6 sweeps x 2 ledger sizes) -> 2 hosts by sweep
#                     WAS 24, at four ledger sizes. The audit figure now draws
#                     history depth on x with one curve per scheme per ledger
#                     size, so only L=100 and L=1000 are measured.
#   Ref[10] fabric    cost goes as 1/c, so c=1 alone is half the sweep -> 3 hosts
#                     by concurrency level, and only these need a Fabric network
#
# TWENTY, NOT MORE. The account's On-Demand Standard quota is 640 vCPU and a
# c6i.8xlarge takes 32, so 20 is the ceiling. The instance type is not
# negotiable downward to fit more in: the config names c6i.8xlarge, and
# cmd/merge-results refuses to pool results whose hosts differ in core count —
# a throughput curve pooled across different machines measures the machines.
#
# A worker that fails does NOT terminate; it stays up with its log so the
# failure can be read. Check for survivors when the run is over.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REGION="${REGION:-us-east-1}"
AMI="${AMI:-ami-05a3e9423ae4d7a19}"           # Ubuntu 22.04 LTS, amd64
TYPE="${TYPE:-c6i.8xlarge}"                    # 32 vCPU, 64 GB — the config's target
KEY="${KEY:-ojcoms}"
SG="${SG:-sg-0a1ab0b9de454a9f2}"
PROFILE="${PROFILE:-zkredact-probe-s3}"
BUCKET="${BUCKET:-zkredact-results-528301714999}"
RUN_ID="${RUN_ID:-run-$(date -u +%Y%m%d-%H%M%S)}"
NAME="ZKredact-Worker"

DRY=0
ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --only)    ONLY="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "launch-run: $*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# The worker table.
#
# id | fabric topology ("" = none) | shard arguments, one run-shard.sh call per
#                                    ';' separated entry
# -----------------------------------------------------------------------------
WORKERS=(
  # --- Exp 1 -----------------------------------------------------------------
  "W01||--name W01-exp1-zkredact --exp verification --schemes zkredact"
  "W02|full|--name W02-exp1-ref10-fabric-c1 --exp verification --schemes ref10_emt --transports fabric --levels 1"
  "W03|full|--name W03-exp1-ref10-fabric-c2-4 --exp verification --schemes ref10_emt --transports fabric --levels 2,4"
  "W04|full|--name W04-exp1-ref10-fabric-tail --exp verification --schemes ref10_emt --transports fabric --levels 8,16,32,64,128,256,512,1024"
  "W05||--name W05-exp1-ref13 --exp verification --schemes ref13_vrbc"
  "W06||--name W06-exp1-ref22 --exp verification --schemes ref22_shen"

  # --- Exp 2: ZK-Redact's 84 arms across 10 hosts, ~9 arms each --------------
  "W07||--name W07-exp2-zk-0 --exp redaction --schemes zkredact --arms 0/10"
  "W08||--name W08-exp2-zk-1 --exp redaction --schemes zkredact --arms 1/10"
  "W09||--name W09-exp2-zk-2 --exp redaction --schemes zkredact --arms 2/10"
  "W10||--name W10-exp2-zk-3 --exp redaction --schemes zkredact --arms 3/10"
  "W11||--name W11-exp2-zk-4 --exp redaction --schemes zkredact --arms 4/10"
  "W12||--name W12-exp2-zk-5 --exp redaction --schemes zkredact --arms 5/10"
  "W13||--name W13-exp2-zk-6 --exp redaction --schemes zkredact --arms 6/10"
  "W14||--name W14-exp2-zk-7 --exp redaction --schemes zkredact --arms 7/10"
  "W15||--name W15-exp2-zk-8 --exp redaction --schemes zkredact --arms 8/10"
  "W16||--name W16-exp2-zk-9 --exp redaction --schemes zkredact --arms 9/10"

  # --- Exp 2 baselines, and Exp 3 --------------------------------------------
  # Ref[22] pays 31m45s of setup every time it starts, so its Exp 2 and Exp 3
  # sit on different hosts rather than one host paying it twice.
  "W17||--name W17-exp2-baselines --exp redaction --schemes ref13_vrbc,ref22_shen,ref10_emt"
  "W18||--name W18-exp3-ref13-a --exp audit --schemes ref13_vrbc --arms 0/2"
  "W19||--name W19-exp3-ref13-b --exp audit --schemes ref13_vrbc --arms 1/2"
  "W20||--name W20-exp3-ref22-zk-ref10 --exp audit --schemes ref22_shen,zkredact,ref10_emt"

  # Ref[10]'s OTHER transport. Exp 1 sweeps exp1_vote_transports, and W02-W04
  # each pin --transports fabric so the concurrency split does not re-run the
  # slow arm three times over — which leaves in_process belonging to nobody
  # unless it is named here. It is the arm where Ref[10] is FAST (669 auth/s
  # against 0.53 over fabric), so dropping it would remove the low-load half of
  # the crossover Exp 1 exists to show. Seconds of work; it shares a host with
  # nothing because every other slot is spoken for.
  "W21||--name W21-exp1-ref10-inprocess --exp verification --schemes ref10_emt --transports in_process"
)

echo "run id:  $RUN_ID"
echo "results: s3://$BUCKET/$RUN_ID/"
echo "workers: ${#WORKERS[@]}"
echo

# -----------------------------------------------------------------------------
# Ship the working tree, .git included.
#
# Without .git the harness records git_commit "unknown", which
# output.record.git_commit marks unpublishable — run-shard.sh refuses to start
# rather than discover that after hours of compute.
# -----------------------------------------------------------------------------
TARBALL="${TMPDIR:-/tmp}/zkredact-$RUN_ID.tgz"
if (( DRY == 0 )); then
  [[ -z "$(git status --porcelain)" ]] || echo "WARNING: working tree is dirty; the commit will not identify the code"
  echo "packaging $(git rev-parse --short HEAD)..."
  # --exclude patterns match at any depth, so anchor the ones that would
  # otherwise eat a source directory: 'results' alone also removes pkg/results,
  # which cost a deploy once already.
  tar --exclude='./zkredact/results' --exclude='./zkredact/Reference' \
      --exclude='./zkredact/Overleaf' --exclude='*/chaincode/redaction/vendor' \
      -czf "$TARBALL" -C "$(dirname "$REPO_ROOT")" "$(basename "$REPO_ROOT")" 2>/dev/null
  aws s3 cp "$TARBALL" "s3://$BUCKET/$RUN_ID/code.tgz" --only-show-errors \
    || die "could not upload the code tarball"
  echo "uploaded $(du -h "$TARBALL" | cut -f1) to s3://$BUCKET/$RUN_ID/code.tgz"
  echo
fi

launched=0
for row in "${WORKERS[@]}"; do
  IFS='|' read -r id fabric shards <<< "$row"
  [[ -z "$ONLY" || "$ONLY" == "$id" ]] || continue

  fabric_arg=""
  [[ -n "$fabric" ]] && fabric_arg="--fabric $fabric"

  # One run-shard.sh invocation per ';' entry. The LAST one terminates; earlier
  # ones must not, or the host would stop with work still to do.
  cmds=""
  IFS=';' read -ra parts <<< "$shards"
  for i in "${!parts[@]}"; do
    tail_args="--s3 s3://$BUCKET/$RUN_ID"
    if (( i == ${#parts[@]} - 1 )); then
      tail_args="$tail_args --terminate"
      # Fabric setup belongs to the shard that needs it.
      [[ -n "$fabric_arg" ]] && tail_args="$tail_args $fabric_arg"
    fi
    cmds+="  ./scripts/run-shard.sh ${parts[$i]} $tail_args"$'\n'
  done

  if (( DRY == 1 )); then
    printf '%s  %s\n' "$id" "${fabric:+[fabric $fabric] }"
    printf '%s' "$cmds"
    continue
  fi

  USER_DATA=$(cat <<EOF
#!/bin/bash
exec > /var/log/zkredact-worker.log 2>&1
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq awscli
cd /home/ubuntu
aws s3 cp s3://$BUCKET/$RUN_ID/code.tgz . --only-show-errors
tar xzf code.tgz
find /home/ubuntu/zkredact -name '._*' -delete
chown -R ubuntu:ubuntu /home/ubuntu/zkredact
cd /home/ubuntu/zkredact

# Stop the meter if this host stops working. run-shard.sh deliberately does NOT
# terminate on failure so a broken shard can be read — which is right for
# debugging and wrong for the bill. The watchdog closes that gap without losing
# the evidence: it publishes the logs to S3 before shutting down, so a failure
# stays diagnosable after the instance is gone.
chmod +x scripts/idle-watchdog.sh
nohup ./scripts/idle-watchdog.sh "s3://$BUCKET/$RUN_ID" "$id" >/dev/null 2>&1 &

sudo -u ubuntu -H bash -lc '
  cd ~/zkredact
  chmod +x scripts/*.sh network/scripts/*.sh
  ./scripts/setup-ec2.sh
  export PATH=\$PATH:/usr/local/go/bin:\$HOME/fabric/bin
$cmds'
EOF
)

  iid=$(aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI" --instance-type "$TYPE" --key-name "$KEY" \
    --security-group-ids "$SG" \
    --iam-instance-profile "Name=$PROFILE" \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
    --instance-initiated-shutdown-behavior terminate \
    --user-data "$USER_DATA" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=Worker,Value=$id},{Key=RunId,Value=$RUN_ID}]" \
    --query 'Instances[0].InstanceId' --output text 2>&1 | tail -1)

  if [[ "$iid" == i-* ]]; then
    printf '%-5s %s\n' "$id" "$iid"
    launched=$((launched + 1))
  else
    printf '%-5s FAILED: %s\n' "$id" "$iid"
  fi
done

(( DRY == 1 )) && exit 0

echo
echo "$launched of ${#WORKERS[@]} launched"
echo
echo "watch:     aws ec2 describe-instances --region $REGION \\"
echo "             --filters Name=tag:RunId,Values=$RUN_ID Name=instance-state-name,Values=running \\"
echo "             --query 'length(Reservations[].Instances[])'"
echo "results:   aws s3 ls s3://$BUCKET/$RUN_ID/ --recursive"
echo "survivors: any instance still running when S3 stops filling has FAILED —"
echo "           ssh in and read ~/shard-*.log, or /var/log/zkredact-worker.log"
