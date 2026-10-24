#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <out_dir> <class> <spec_glob> [model_path]"
  exit 1
fi

OUT_DIR="$1"
CASE_CLASS="$2"
SPEC_GLOB="${3:-dataset_test/run_*/specs/*.yaml}"
MODEL_PATH="${4:-casce_gat_v3p.pt}"
WS="${CASCE_WORKSPACE:-$HOME/Desktop/Projects/CASCE_DATASET}"

mkdir -p "$OUT_DIR"

# Ensure the workspace is clean before a live run starts.
if docker exec -u root casce_environment bash /dataset_workspace/logger.sh status 2>/dev/null | grep -q "ACTIVE"; then
  docker exec -u root casce_environment bash /dataset_workspace/logger.sh stop
fi
docker exec -u root casce_environment bash /dataset_workspace/logger.sh reset || true

# Start the logger and daemon.
docker exec -u root casce_environment bash /dataset_workspace/logger.sh start
python3 -u realtime_daemon.py --log-dir "$WS" --model-path "$MODEL_PATH" --out-dir "$OUT_DIR/daemon" > "$OUT_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
trap 'docker exec -u root casce_environment bash /dataset_workspace/logger.sh stop >/dev/null 2>&1 || true; kill -INT "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true' EXIT

sleep 5
python3 -u workload_simulation/run_live_scenarios.py --out-dir "$OUT_DIR" --class "$CASE_CLASS" --limit 1 --specs "$SPEC_GLOB"

# Give the daemon time to finalise the live session and flush score output.
sleep 15
docker exec -u root casce_environment bash /dataset_workspace/logger.sh stop || true
kill -INT "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
trap - EXIT

# Keep only the first/clean label record in a single-session folder.
if [ -f "$OUT_DIR/live_manifest.jsonl" ]; then
  awk 'NR==1 || $0 ~ /"key"/' "$OUT_DIR/live_manifest.jsonl" > "$OUT_DIR/live_manifest_single.jsonl" || true
  if [ -s "$OUT_DIR/live_manifest_single.jsonl" ]; then
    cp "$OUT_DIR/live_manifest_single.jsonl" "$OUT_DIR/live_manifest.jsonl"
  fi
fi

if [ -f "$WS/session_labels.jsonl" ]; then
  cp "$WS/session_labels.jsonl" "$OUT_DIR/session_labels.jsonl"
fi

# Save a small summary for the paper folder.
python3 - <<'PY' "$OUT_DIR"
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
manifest = out / 'live_manifest.jsonl'
labels = out / 'session_labels.jsonl'
summary = {'out_dir': str(out), 'manifest_rows': 0, 'label_rows': 0}
if manifest.exists():
    summary['manifest_rows'] = sum(1 for _ in open(manifest))
if labels.exists():
    summary['label_rows'] = sum(1 for _ in open(labels))
(out / 'case_summary.json').write_text(json.dumps(summary, indent=2))
PY

echo "Single-session live case saved to $OUT_DIR"
