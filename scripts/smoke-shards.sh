#!/usr/bin/env bash
#
# Shard rehearsal — run every command the AWS run will issue, tiny.
#
#   ./scripts/smoke-shards.sh              all shards that need no network
#   ./scripts/smoke-shards.sh --fabric     also the Ref[10] fabric arm
#   ./scripts/smoke-shards.sh -x exp2      run only shards matching a pattern
#
# WHY THIS EXISTS. The AWS plan splits the run across instances by experiment
# and by scheme. Each instance issues ONE run-experiment command. A shard that
# is going to fail — a missing parameter, a scheme that refuses its sweep, a
# ledger that cannot be built — fails for the same reason here, in seconds,
# before an instance is paid for.
#
# It measures NOTHING. config/smoke.yaml is sized so every sweep is truncated;
# a number out of this script is a defect if it reaches a table.
#
# THE FABRIC ARM NEEDS A FRESH LEDGER. Ref[10] votes through the chaincode, the
# request trace is seeded, and the contract refuses a second ballot from the
# same member in the same round. So a fabric run is repeatable only against a
# chain that has never seen it: tear the network down and back up between
# attempts, or the shard fails with "has already voted" on a contract that is
# behaving exactly as it should.
#
# Exit status is the point: 0 means every shard ran to completion and wrote its
# results file. Anything else names the shards that did not.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIG="config/smoke.yaml"
BIN="${TMPDIR:-/tmp}/smoke-run-experiment"
LOG_DIR="results/smoke/logs"
WITH_FABRIC=0
FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fabric) WITH_FABRIC=1; shift ;;
    -x)       FILTER="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Read back the results file a shard just wrote and report any point whose
# operations did not actually succeed. Prints a reason on failure, nothing when
# the file is clean. Silent (treated as clean) when python3 is unavailable —
# this is a check, not the harness's own validation.
results_with_failures() {
  local log="$1" json
  json=$(grep -o '[^ ]*\.json' "$log" | tail -1)
  [[ -n "$json" && -r "$json" ]] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  python3 - "$json" <<'EOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"unreadable results file ({e})"); sys.exit(0)
pts = doc.get("result", {}).get("points", [])
if not pts:
    print("results file holds no points"); sys.exit(0)
req = sum(p.get("requested", 0) or 0 for p in pts)
bad = sum((p.get("failed", 0) or 0) for p in pts)
if req and bad:
    print(f"{bad} of {req} operations FAILED across {len(pts)} point(s)")
EOF
}

red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }
grey()  { printf '\033[90m%s\033[0m' "$1"; }

# -----------------------------------------------------------------------------
# The shard table. One row per instance in the AWS plan.
#
# Format: name | experiment | schemes | needs_fabric | config (blank = $CONFIG)
#
# The four ref10 fabric rows are ONE shard each in the real plan, split by
# concurrency level. run-experiment has no level flag yet, so they collapse to a
# single fabric rehearsal here — the flag is what the plan is waiting on, and
# this script is what will prove it once it lands.
#
# The fabric row carries its OWN config. config/smoke.yaml sets
# block_max_transactions to 10 and the channel batches at 100, so a run against
# a live peer would batch on a cadence nothing recorded. smoke-fabric.yaml keeps
# the channel's value and shrinks the Exp 3 ledger sweep instead.
# -----------------------------------------------------------------------------
SHARDS=(
  "A-exp1-zkredact|verification|zkredact|0|"
  "B-exp3-ref13|audit|ref13_vrbc|0|"
  "C-exp3-ref22|audit|ref22_shen|0|"
  "C-exp1-ref22|verification|ref22_shen|0|"
  "C-exp1-ref13|verification|ref13_vrbc|0|"
  "D-exp2-zkredact|redaction|zkredact|0|"
  "D-exp2-ref10|redaction|ref10_emt|0|"
  "D-exp2-ref13|redaction|ref13_vrbc|0|"
  "D-exp2-ref22|redaction|ref22_shen|0|"
  "D-exp3-zkredact|audit|zkredact|0|"
  "D-exp3-ref10|audit|ref10_emt|0|"
  "E-exp1-ref10-inprocess|verification|ref10_emt|0|"
  "F-exp1-ref10-fabric|verification|ref10_emt|1|config/smoke-fabric.yaml"
)

echo "shard rehearsal: $CONFIG"
echo

if ! go build -o "$BIN" ./cmd/run-experiment; then
  echo "$(red FAIL) build" >&2
  exit 1
fi

for c in "$CONFIG" config/smoke-fabric.yaml; do
  [[ -r "$c" ]] || continue
  if ! go run ./cmd/validate-config "$c" >/dev/null 2>&1; then
    echo "$(red FAIL) validate-config rejected $c — fix it before rehearsing shards" >&2
    go run ./cmd/validate-config "$c" 2>&1 | tail -20
    exit 1
  fi
done
echo "$(green ok) configs valid"

mkdir -p "$LOG_DIR"

printf '\n%-26s %-13s %-12s %8s  %s\n' SHARD EXPERIMENT SCHEME TIME RESULT
printf '%s\n' "----------------------------------------------------------------------------"

failed=()
skipped=0
passed=0

for row in "${SHARDS[@]}"; do
  IFS='|' read -r name exp schemes needs_fabric shard_config <<< "$row"
  [[ -n "$shard_config" ]] || shard_config="$CONFIG"

  if [[ -n "$FILTER" && "$name" != *"$FILTER"* ]]; then
    continue
  fi

  if [[ "$needs_fabric" == "1" && "$WITH_FABRIC" == "0" ]]; then
    printf '%-26s %-13s %-12s %8s  %s\n' "$name" "$exp" "$schemes" "-" "$(grey 'SKIP (needs --fabric)')"
    skipped=$((skipped + 1))
    continue
  fi

  log="$LOG_DIR/$name.log"
  start=$(date +%s)
  # A shard that hangs is a failure too: the real run has a wall clock and this
  # rehearsal must not sit forever on a deadlock that EC2 would bill for.
  if command -v timeout >/dev/null 2>&1; then
    timeout 900 "$BIN" -config "$shard_config" -exp "$exp" -schemes "$schemes" >"$log" 2>&1
  else
    "$BIN" -config "$shard_config" -exp "$exp" -schemes "$schemes" >"$log" 2>&1
  fi
  rc=$?
  elapsed=$(( $(date +%s) - start ))

  if [[ $rc -eq 0 ]] && grep -q "wrote " "$log"; then
    # Exiting 0 is not the same as working. Ref[13] returned exit 0 from Exp 2
    # having FAILED 19 of 20 redactions: the runner records a failure count and
    # carries on, so a shard can write a full results file built from almost no
    # successful work. Read the file back and say so.
    bad=$(results_with_failures "$log")
    if [[ -n "$bad" ]]; then
      printf '%-26s %-13s %-12s %7ss  %s\n' "$name" "$exp" "$schemes" "$elapsed" "$(red "FAIL — $bad")"
      failed+=("$name")
      continue
    fi
    printf '%-26s %-13s %-12s %7ss  %s\n' "$name" "$exp" "$schemes" "$elapsed" "$(green PASS)"
    passed=$((passed + 1))
  else
    reason="exit $rc"
    [[ $rc -eq 124 ]] && reason="TIMEOUT after 900s"
    [[ $rc -eq 0 ]] && reason="exit 0 but wrote no results file"
    # A replayed vote is not a code fault: the contract is correctly refusing a
    # ballot it already holds. The trace is seeded, so a re-run submits the SAME
    # round ids, and the fabric arm therefore needs a ledger that has never seen
    # them. Naming the remedy here saves debugging a contract that is working.
    if grep -q "has already voted in" "$log" 2>/dev/null; then
      reason="stale ledger — this network already holds these votes; network.sh down && up <topology> && deploy, then retry"
    fi
    printf '%-26s %-13s %-12s %7ss  %s\n' "$name" "$exp" "$schemes" "$elapsed" "$(red "FAIL — $reason")"
    # The last error line is almost always the useful one; the rest is the
    # capability matrix nobody needs when something broke.
    tail -3 "$log" | sed 's/^/      /'
    failed+=("$name")
  fi
done

printf '%s\n' "----------------------------------------------------------------------------"
echo "$passed passed, ${#failed[@]} failed, $skipped skipped   (logs in $LOG_DIR)"

if [[ ${#failed[@]} -gt 0 ]]; then
  echo
  echo "$(red 'these shards would fail on EC2:') ${failed[*]}"
  exit 1
fi

if [[ $skipped -gt 0 ]]; then
  echo
  echo "$(grey 'the fabric arm was not rehearsed. Bring the network up and rerun with --fabric')"
  echo "$(grey 'before launching F1-F4 — it is the only shard that needs a live peer.')"
fi
