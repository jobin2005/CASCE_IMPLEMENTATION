#!/usr/bin/env bash
# Single v3 deployment model, trained exactly like casce_gat_v2 (same data, seed,
# settings; only --feature-version 3), then the same evaluations v2 had:
# E1 synthetic test set and replays of the live captures 4a, 4b, 4c, 5a, 5b.
#
#   setsid nohup bash run_v3_full.sh > live_eval_v3/run.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p live_eval_v3
TRAIN_DIR=dataset_dev/enriched_graphs/graphml,training_v2/dev_train_prefixes/graphml,training_v2/pgbench_train/graphml
TRAIN_LBL=dataset_dev/algo4_splits/train_labels.json,training_v2/dev_train_prefixes/labels.json,training_v2/pgbench_train/labels.json
VAL_DIR=dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml
VAL_LBL=dataset_dev/algo4_splits/val_labels.json,training_v2/dev_val_prefixes/labels.json,training_v2/pgbench_val/labels.json

echo "== $(date +%H:%M) train v3"
python3 -u algorithm_4_hybrid.py --mode train --feature-version 3 --seed 42 --epochs 50 \
  --train-dir $TRAIN_DIR --train-labels $TRAIN_LBL --val-dir $VAL_DIR --val-labels $VAL_LBL \
  --model-path casce_gat_v3.pt > live_eval_v3/train.log 2>&1 || { echo "train FAILED"; exit 1; }

echo "== $(date +%H:%M) tune θ on validation (original f1 rule)"
python3 -u algorithm_4_hybrid.py --mode tune --model-path casce_gat_v3.pt --theta-mode f1 \
  --input-dir $VAL_DIR --labels $VAL_LBL --outdir tune_out_v3 > live_eval_v3/tune.log 2>&1

echo "== $(date +%H:%M) E1 synthetic test set"
python3 -u algorithm_4_hybrid.py --mode evaluate --model-path casce_gat_v3.pt \
  --input-dir dataset_test/enriched_graphs/graphml --labels dataset_test/algo4_splits/test_labels.json \
  --outdir eval_test_report_v3 > live_eval_v3/evaluate_e1.log 2>&1
grep -E "using|Samples|Precision|Recall|F1|FPR|ROC" live_eval_v3/evaluate_e1.log

for r in 4a 4b 4c 5a_attacks 5b_mixed; do
  echo "== $(date +%H:%M) replay live_runs/$r"
  rm -rf live_runs/$r/daemon_v3
  python3 -u realtime_daemon.py --replay --replay-realtime --log-dir live_runs/$r \
    --model-path casce_gat_v3.pt --out-dir live_runs/$r/daemon_v3 > live_eval_v3/$r.daemon.log 2>&1
  python3 -u workload_simulation/evaluate_live.py --run-dir live_runs/$r \
    --scores live_runs/$r/daemon_v3/session_scores.jsonl --alerts live_runs/$r/daemon_v3/alerts.jsonl \
    --model-path casce_gat_v3.pt --compare-synthetic > live_eval_v3/$r.eval.txt 2>&1
  sed -n '/== Final verdict/,/^$/p' live_eval_v3/$r.eval.txt
done

git add -f casce_gat_v3.pt
git add casce_gat_v3.json tune_out_v3 eval_test_report_v3 live_eval_v3 run_v3_full.sh
git commit -q -m "Single v3 model (trained like casce_gat_v2) + E1 test + replay of live runs 4a-5b" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && git push -q origin realtime-v2
echo "== $(date +%H:%M) ALL DONE"
