#!/usr/bin/env bash
# One complete live experiment with the detector running in REAL TIME (follow
# mode, not replay): capture on, daemon following the live logs, scenario
# workload + pgbench background load, then capture off and everything copied
# into live_runs/<name>/.
#
#   bash workload_simulation/run_full_live.sh <name> <model.pt[,model2.pt,...]> [runner args...]
#   (several models: one daemon per model, all following the same live logs)
#   bash workload_simulation/run_full_live.sh 6_full casce_gat_v3.pt --class all --pgbench \
#        --specs 'dataset_test/run_*/specs/*.yaml' 'dataset_benign_extra/run_*/specs/*.yaml'
#
# Needs the casce_environment container with casce_banking set up
# (setup_banking_db.sh) and the current logger.sh / kernel_telemetry.py in its
# /dataset_workspace (EXPERIMENTS.md, "4D environment").
set -uo pipefail
cd "$(dirname "$0")/.."
name=$1 model=$2; shift 2
WS=${CASCE_WORKSPACE:-$HOME/Desktop/Projects/CASCE_DATASET}
out=live_runs/$name
mkdir -p "$out"
log() { echo "== $(date +%H:%M:%S) $*"; }

for f in postgres_events.json kernel_events.json session_labels.jsonl; do
  if [ -s "$WS/$f" ]; then echo "workspace still holds a capture ($f); archive it first"; exit 1; fi
done

log "capture start"
docker exec -u root casce_environment bash /dataset_workspace/logger.sh start | tail -1 || exit 1

daemons=()
for m in ${model//,/ }; do
  t=$(basename "$m" .pt | sed 's/casce_gat_//')
  log "daemon ($m) following $WS live"
  python3 -u realtime_daemon.py --log-dir "$WS" --model-path "$m" --out-dir "$out/daemon_${t}_live" \
    > "$out/daemon_${t}_live.log" 2>&1 &
  daemons+=($!)
done
sleep 5

log "workload: $*"
python3 -u workload_simulation/run_live_scenarios.py --out-dir "$out" "$@" > "$out/runner.log" 2>&1
tail -2 "$out/runner.log"

log "letting the daemon finalise sessions (idle timeout)"
sleep 90
docker exec -u root casce_environment bash /dataset_workspace/logger.sh stop | tail -1
sleep 5
for d in "${daemons[@]}"; do kill -INT $d 2>/dev/null; done
for d in "${daemons[@]}"; do wait $d 2>/dev/null; done

log "copy capture"
cp "$WS"/postgres_events.json "$WS"/kernel_events.json "$WS"/kernel_events.raw.json \
   "$WS"/session_labels.jsonl "$WS"/time_sync.json "$out"/ 2>/dev/null
docker exec -u root casce_environment bash /dataset_workspace/logger.sh archive | tail -1
wc -l "$out"/postgres_events.json "$out"/kernel_events.json "$out"/session_labels.jsonl
log "done"
