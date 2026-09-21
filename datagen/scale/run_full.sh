#!/bin/bash
# Full-scale corpus generation: generate -> codegen+validate every run dir -> gate.
# Usage: bash datagen/scale/run_full.sh <target> <seed> <out_dir>
set -uo pipefail
cd "$(dirname "$0")/../.."   # repo root
TARGET="${1:-10000}"
SEED="${2:-1337}"
OUT="${3:-datagen/generated/gen}"
LOGDIR="datagen/scale/_full_logs"
mkdir -p "$LOGDIR"

echo "[$(date +%H:%M:%S)] generating $TARGET scenarios (seed $SEED) -> $OUT"
python3 datagen/scale/generate.py --target "$TARGET" --out "$OUT" --seed "$SEED" --per-run 25 \
    > "$LOGDIR/generate.log" 2>&1
if [ $? -ne 0 ]; then echo "GENERATE FAILED (see $LOGDIR/generate.log)"; tail -5 "$LOGDIR/generate.log"; exit 1; fi
tail -2 "$LOGDIR/generate.log"

echo "[$(date +%H:%M:%S)] codegen + validate over run dirs..."
ok=0; fail=0; : > "$LOGDIR/failures.log"
for d in "$OUT"/*/; do
    if python3 datagen/codegen.py "$d" >/dev/null 2>&1 \
       && python3 datagen/validate_run.py "$d" >/dev/null 2>&1; then
        ok=$((ok+1))
    else
        fail=$((fail+1)); echo "FAIL $(basename "$d")" >> "$LOGDIR/failures.log"
    fi
done
echo "[$(date +%H:%M:%S)] validate: ok=$ok fail=$fail"

echo "[$(date +%H:%M:%S)] corpus gate..."
python3 datagen/gate_pilot.py --root "$OUT" --json "$LOGDIR/full_corpus_gate.json" \
    > "$LOGDIR/gate_summary.txt" 2>&1
echo "validate_ok=$ok validate_fail=$fail" > "$LOGDIR/summary.txt"
echo "[$(date +%H:%M:%S)] DONE. gate json: $LOGDIR/full_corpus_gate.json"
