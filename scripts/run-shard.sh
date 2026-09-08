#!/usr/bin/env bash
#
# Run one shard on this host, publish its results, and stop paying for the box.
#
#   ./scripts/run-shard.sh --name B-exp3-ref13 \
#       --exp audit --schemes ref13_vrbc \
#       --s3 s3://my-bucket/run-2026-09-07
#
#   ./scripts/run-shard.sh --name F1 --exp verification --schemes ref10_emt \
#       --transports fabric --levels 1 --fabric full --s3 s3://... --terminate
#
# WHY THIS EXISTS. A sharded run is only worth its money if every shard's
# results come back and every instance stops when its work is done. Doing both
# by hand across a dozen hosts is how a paid run loses a shard to a forgotten
# scp, or burns six hours of a machine that finished in five minutes.
#
# WHAT IT GUARANTEES
#
#   1. Results are published BEFORE the instance is allowed to stop. A shard
#      that cannot publish does not terminate — a live box you can log into is
#      cheaper than a measurement you have to take again.
#   2. The exit status says whether the shard actually worked, not merely that
#      the process ended. The results file is read back and any non-zero
#      failure count fails the shard, which is what caught Ref[13] writing a
#      complete-looking file from 30 successful redactions out of 360.
#   3. Every run records the commit it ran. Without .git the harness writes
#      git_commit "unknown", and output.record.git_commit in the config says
#      that is not publishable. Checked up front rather than discovered later.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NAME=""
EXP=""
SCHEMES=""
TRANSPORTS=""
LEVELS=""
ARMS=""
CONFIG="config/experiment.yaml"
S3=""
FABRIC=""
TERMINATE=0

die() { echo "run-shard: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)       NAME="${2:-}"; shift 2 ;;
    --exp)        EXP="${2:-}"; shift 2 ;;
    --schemes)    SCHEMES="${2:-}"; shift 2 ;;
    --transports) TRANSPORTS="${2:-}"; shift 2 ;;
    --levels)     LEVELS="${2:-}"; shift 2 ;;
    --arms)       ARMS="${2:-}"; shift 2 ;;
    --config)     CONFIG="${2:-}"; shift 2 ;;
    --s3)         S3="${2:-}"; shift 2 ;;
    --fabric)     FABRIC="${2:-}"; shift 2 ;;   # minimal | full
    --terminate)  TERMINATE=1; shift ;;
    -h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$NAME" ]] || die "--name is required; it labels the results and the log"
[[ -n "$EXP"  ]] || die "--exp is required (verification | redaction | audit | all)"

LOG="$HOME/shard-$NAME.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== shard $NAME  exp=$EXP schemes=${SCHEMES:-all} $(date -u +%FT%TZ) ==="

# -----------------------------------------------------------------------------
# Provenance, checked BEFORE hours of compute rather than after
# -----------------------------------------------------------------------------
if ! git -C "$REPO_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  die "no git metadata in $REPO_ROOT — results would record git_commit \"unknown\",
       which output.record.git_commit marks unpublishable. Deploy the repository
       WITH its .git directory."
fi
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  echo "WARNING: working tree is dirty; the commit does not identify the code"
fi
echo "commit $COMMIT"

# -----------------------------------------------------------------------------
# Config gate. run-experiment does NOT validate; make validate-config is a
# separate command, so a shard that skips it can run for hours against a config
# the validator would have refused.
# -----------------------------------------------------------------------------
if ! go run ./cmd/validate-config "$CONFIG" >/dev/null 2>&1; then
  go run ./cmd/validate-config "$CONFIG" 2>&1 | tail -20
  die "validate-config refused $CONFIG"
fi
echo "config ok: $CONFIG"

# -----------------------------------------------------------------------------
# Fabric, only when the shard votes over it
# -----------------------------------------------------------------------------
if [[ -n "$FABRIC" ]]; then
  # A REPLAYED VOTE IS NOT A CODE FAULT. The trace is seeded, so a retry submits
  # the same round ids and the contract refuses a ballot it already holds. A
  # shard therefore starts from a chain that has never seen its votes.
  echo "bringing the $FABRIC topology up on a fresh ledger..."

  # THE DOCKER GROUP IS NOT IN THIS SHELL. setup-ec2.sh adds it with usermod and
  # works around its own absence internally, but network.sh calls docker
  # directly and inherits this shell's groups — which is how three fabric
  # workers provisioned cleanly and then died on "the Docker daemon is not
  # reachable". Pick a route that works and use it for every network call.
  NET=""
  if ! docker info >/dev/null 2>&1; then
    if command -v sg >/dev/null 2>&1 && sg docker -c "docker info" >/dev/null 2>&1; then
      NET="sg docker -c"
    elif sudo docker info >/dev/null 2>&1; then
      NET="sudo -E"
    else
      die "no route to the Docker daemon; a fabric shard cannot run here"
    fi
    echo "docker reached via ${NET}"
  fi
  net_sh() {
    case "$NET" in
      "sg docker -c") sg docker -c "./network/scripts/network.sh $*" ;;
      "sudo -E")      sudo -E ./network/scripts/network.sh "$@" ;;
      *)              ./network/scripts/network.sh "$@" ;;
    esac
  }

  net_sh down >/dev/null 2>&1
  net_sh up "$FABRIC" || die "network.sh up $FABRIC failed"
  net_sh deploy      || die "network.sh deploy failed"
fi

# -----------------------------------------------------------------------------
# The shard
# -----------------------------------------------------------------------------
ARGS=(-config "$CONFIG" -exp "$EXP")
[[ -n "$SCHEMES"    ]] && ARGS+=(-schemes "$SCHEMES")
[[ -n "$TRANSPORTS" ]] && ARGS+=(-transports "$TRANSPORTS")
[[ -n "$LEVELS"     ]] && ARGS+=(-levels "$LEVELS")
[[ -n "$ARMS"       ]] && ARGS+=(-arms "$ARMS")

RESULTS_DIR=$(grep -E '^\s*results_dir:' "$CONFIG" | head -1 | sed 's/.*"\(.*\)".*/\1/')
RESULTS_DIR="${RESULTS_DIR:-results}"
mkdir -p "$RESULTS_DIR"
BEFORE=$(ls "$RESULTS_DIR"/*.json 2>/dev/null | wc -l)

echo "running: run-experiment ${ARGS[*]}"
START=$(date +%s)
go run ./cmd/run-experiment "${ARGS[@]}"
RC=$?
ELAPSED=$(( $(date +%s) - START ))
echo "shard finished rc=$RC in ${ELAPSED}s"

AFTER=$(ls "$RESULTS_DIR"/*.json 2>/dev/null | wc -l)
if (( AFTER <= BEFORE )); then
  echo "FAIL: the shard wrote no new results file"
  RC=1
fi

# Exit 0 is not the same as working: the runner records a failure count and
# carries on, so a file can be complete-looking and built from almost no
# successful work.
if (( RC == 0 )) && command -v python3 >/dev/null 2>&1; then
  NEWEST=$(ls -t "$RESULTS_DIR"/*.json 2>/dev/null | head -1)
  BAD=$(python3 - "$NEWEST" <<'EOF'
import json, sys
try:
    pts = json.load(open(sys.argv[1])).get("result", {}).get("points", [])
except Exception as e:
    print(f"unreadable results file ({e})"); raise SystemExit
req = sum(p.get("requested", 0) or 0 for p in pts)
bad = sum(p.get("failed", 0) or 0 for p in pts)
if not pts:
    print("results file holds no points")
elif req and bad:
    print(f"{bad} of {req} operations FAILED across {len(pts)} point(s)")
EOF
)
  if [[ -n "$BAD" ]]; then
    echo "FAIL: $BAD"
    RC=1
  fi
fi

# -----------------------------------------------------------------------------
# Publish BEFORE stopping. Order matters: an instance that terminates with
# unpublished results has destroyed the thing it was paid to produce.
# -----------------------------------------------------------------------------
PUBLISHED=0
if [[ -n "$S3" ]]; then
  if aws s3 cp "$RESULTS_DIR" "$S3/$NAME/" --recursive --only-show-errors \
     && aws s3 cp "$LOG" "$S3/$NAME/" --only-show-errors; then
    echo "published to $S3/$NAME/"
    PUBLISHED=1
  else
    echo "FAIL: could not publish results to $S3"
    RC=1
  fi
else
  echo "no --s3 given; results stay in $RESULTS_DIR on this host"
fi

if (( TERMINATE == 1 )); then
  if (( PUBLISHED == 1 && RC == 0 )); then
    echo "shutting down (results published, shard clean)"
    sudo shutdown -h now
  else
    # A live box is cheaper than a measurement taken twice.
    echo "NOT terminating: rc=$RC published=$PUBLISHED — log in and recover"
  fi
fi

exit $RC
