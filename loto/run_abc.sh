#!/usr/bin/env bash
# Comparison runs on the SAME template-disjoint folds as loto/ (v2 baseline),
# one seed each, one stage after the other. Each stage writes its own folder,
# then summarizes, commits and pushes only that folder.
#
#   A0  v2 models from loto/, θ re-tuned with --theta-mode fpr  (fix 3 alone, no retraining)
#   A   v2 + extra benign corpus, θ mode f1                     (fix 4 alone)
#   B   v3, θ mode fpr                                          (fixes 1-3)
#   C   v3 + extra benign corpus, θ mode fpr                    (fixes 1-4)
#
#   setsid nohup bash loto/run_abc.sh > loto/run_abc.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."
SEED=${SEED:-1}
folds=$(python3 -c "import json;print(' '.join(f['fold'] for f in json.load(open('loto/folds.json'))['folds']))")
full=dataset_dev/enriched_graphs/graphml
pref=training_v2/dev_all_prefixes/graphml

finish() {   # finish <out-dir> <description>
  python3 loto_summary.py --dir "$1" --out "$1/loto_summary.json" > "$1/loto_summary.txt" 2>&1
  git add "$1" && git commit -q -m "LOTO $2 (seed $SEED): results" \
      -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- "$1" \
    && git push -q origin realtime-v2
  echo "== $(date +%H:%M) stage done: $2"; cat "$1/loto_summary.txt"
}

echo "== $(date +%H:%M) A0: v2 models, benign-FPR θ"
mkdir -p loto_v2_fpr
for f in $folds; do
  o=loto_v2_fpr/${f}_s${SEED}; d=training_v2/loto/$f
  [ -f $o.report.json ] && continue
  cp loto/${f}_s${SEED}.pt $o.pt && cp loto/${f}_s${SEED}.json $o.json
  python3 -u algorithm_4_hybrid.py --mode tune --model-path $o.pt --theta-mode fpr \
    --input-dir $full,$pref,training_v2/pgbench_val/graphml \
    --labels $d/val_full.json,$d/val_prefixes.json,training_v2/pgbench_val/labels.json \
    --outdir $o.tune > $o.tune.log 2>&1
  theta=$(python3 -c "import json; print(json.load(open('$o.json'))['theta_a'])")
  python3 -u fold_report.py --fold-dir $d --model $o.pt --theta "$theta" --out $o.report.json > $o.report.log 2>&1
done
finish loto_v2_fpr "A0 v2 + benign-FPR theta"

EXTRA=1 FV=2 THETA_MODE=f1  OUT=loto_v2_extra SEEDS=$SEED bash loto/run_all.sh
finish loto_v2_extra "A v2 + extra benign corpus"

FV=3 THETA_MODE=fpr OUT=loto_v3 SEEDS=$SEED bash loto/run_all.sh
finish loto_v3 "B v3 (fixes 1-3)"

EXTRA=1 FV=3 THETA_MODE=fpr OUT=loto_v3_extra SEEDS=$SEED bash loto/run_all.sh
finish loto_v3_extra "C v3 + extra benign corpus"

echo "== $(date +%H:%M) ALL STAGES DONE"
