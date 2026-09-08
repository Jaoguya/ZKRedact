#!/bin/bash
# Terminate this host once it stops doing the work it was launched for.
#
# run-shard.sh deliberately does NOT terminate on failure, so a broken shard
# leaves a live box — which is right for debugging and wrong for the bill. This
# closes that gap without losing the evidence: the logs go to S3 first, so a
# failure stays diagnosable after the instance is gone.
#
# Idle means no setup, no shard, no experiment process, for IDLE_LIMIT
# consecutive minutes. A working host never looks idle even between shards.
IDLE_LIMIT=${IDLE_LIMIT:-10}
S3="$1"
WORKER="$2"
idle=0
while true; do
  if pgrep -f "setup-ec2.sh|run-shard.sh|run-experiment|apt-get|install-fabric" >/dev/null 2>&1; then
    idle=0
  else
    idle=$((idle + 1))
  fi
  if (( idle >= IDLE_LIMIT )); then
    logger "zkredact-watchdog: idle ${IDLE_LIMIT}m, publishing logs and shutting down"
    if [[ -n "$S3" ]]; then
      aws s3 cp /var/log/zkredact-worker.log "$S3/$WORKER/watchdog-worker.log" --only-show-errors 2>/dev/null
      for f in /home/ubuntu/shard-*.log; do
        [[ -e "$f" ]] && aws s3 cp "$f" "$S3/$WORKER/watchdog-$(basename "$f")" --only-show-errors 2>/dev/null
      done
      echo "watchdog: host idle ${IDLE_LIMIT}m after its shard; terminated to stop the meter" \
        > /tmp/watchdog-reason.txt
      aws s3 cp /tmp/watchdog-reason.txt "$S3/$WORKER/WATCHDOG-TERMINATED.txt" --only-show-errors 2>/dev/null
    fi
    shutdown -h now
    exit 0
  fi
  sleep 60
done
