#!/usr/bin/env bash
# Runs every fold x seed that has no report yet (seed 1 for all folds first),
# $PARALLEL at a time.   SEEDS="1 2 3" PARALLEL=4 loto/run_all.sh
cd "$(dirname "$0")/.."
folds=$(python3 -c "import json;print(' '.join(f['fold'] for f in json.load(open('loto/folds.json'))['folds']))")
for s in ${SEEDS:-1 2 3}; do for f in $folds; do
  [ -f "loto/${f}_s${s}.report.json" ] || echo "$f $s"
done; done | OMP_NUM_THREADS=4 MKL_NUM_THREADS=4 xargs -P "${PARALLEL:-4}" -L 1 ./run_loto.sh
echo "ALL DONE"
