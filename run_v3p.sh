#!/usr/bin/env bash
# v3P: production candidate. Same model, features (v3), settings, seed and θ rule
# as casce_gat_v3; the training data adds what v3 lacked:
#   - the bank's other normal workloads: dataset_benign_extra runs 101-105
#     (train) and 106 (validation); runs 107-112 are held out for testing;
#   - live-captured normal traffic with real eBPF kernel events
#     (live_runs/7_train_benign: dataset_dev benign scenarios of runs 1-10 +
#     benign_extra runs 101-105 + pgbench), never the test scenarios.
#
#   bash run_v3p.sh
set -uo pipefail
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-4} MKL_NUM_THREADS=${MKL_NUM_THREADS:-4}
cd "$(dirname "$0")"
out=training_v3p
mkdir -p $out live_eval_v3p
log() { echo "== $(date +%H:%M) $*"; }

if [ ! -f $out/live_benign/labels_selected.json ]; then
  log "graphs from the live training capture"
  python3 build_training_graphs.py --runs live_runs/7_train_benign --out-dir $out/live_benign \
    > $out/live_benign.build.log 2>&1 || { echo "build FAILED"; exit 1; }
  # all scenario sessions + 100 sampled pgbench sessions (pgbench is already
  # well covered by training_v2/pgbench_train)
  python3 - <<'EOF'
import json, random
idx = [json.loads(l) for l in open("training_v3p/live_benign/index.jsonl")]
labels = {json.loads(l)["session_id"]: json.loads(l)["label"] for l in open("live_runs/7_train_benign/session_labels.jsonl")}
pg = sorted({r["session"] for r in idx if labels.get(r["session"], "").endswith(":pgbench")})
keep_pg = set(random.Random(42).sample(pg, min(100, len(pg))))
sel = {r["file"]: int(r["label"] == "Malicious") for r in idx
       if not labels.get(r["session"], "").endswith(":pgbench") or r["session"] in keep_pg}
json.dump(sel, open("training_v3p/live_benign/labels_selected.json", "w"), indent=1)
print(f"live benign graphs selected: {len(sel)} (pgbench sessions kept {len(keep_pg)} of {len(pg)})")
EOF
fi

TRAIN_DIR=dataset_dev/enriched_graphs/graphml,training_v2/dev_train_prefixes/graphml,training_v2/pgbench_train/graphml,dataset_benign_extra/enriched_graphs/graphml,$out/live_benign/graphml
TRAIN_LBL=dataset_dev/algo4_splits/train_labels.json,training_v2/dev_train_prefixes/labels.json,training_v2/pgbench_train/labels.json,$out/benign_extra_train.json,$out/live_benign/labels_selected.json
VAL_DIR=dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml,dataset_benign_extra/enriched_graphs/graphml
VAL_LBL=dataset_dev/algo4_splits/val_labels.json,training_v2/dev_val_prefixes/labels.json,training_v2/pgbench_val/labels.json,$out/benign_extra_val.json

log "train v3P"
python3 -u algorithm_4_hybrid.py --mode train --feature-version 3 --seed 42 --epochs 50 \
  --train-dir $TRAIN_DIR --train-labels $TRAIN_LBL --val-dir $VAL_DIR --val-labels $VAL_LBL \
  --model-path casce_gat_v3p.pt > live_eval_v3p/train.log 2>&1 || { echo "train FAILED"; exit 1; }
grep -E "Training set|Validation set|Early stopping" live_eval_v3p/train.log

log "tune θ on validation (original f1 rule)"
python3 -u algorithm_4_hybrid.py --mode tune --model-path casce_gat_v3p.pt --theta-mode f1 \
  --input-dir $VAL_DIR --labels $VAL_LBL --outdir tune_out_v3p > live_eval_v3p/tune.log 2>&1
grep -E "Best F1|Recorded" live_eval_v3p/tune.log

log "E1 synthetic test set + held-out extra benign runs 107-112"
python3 -u algorithm_4_hybrid.py --mode evaluate --model-path casce_gat_v3p.pt \
  --input-dir dataset_test/enriched_graphs/graphml,dataset_benign_extra/enriched_graphs/graphml \
  --labels dataset_test/algo4_splits/test_labels.json,$out/benign_extra_test.json \
  --outdir eval_test_report_v3p > live_eval_v3p/evaluate.log 2>&1
grep -E "using|Samples|Precision|Recall|F1|FPR|ROC" live_eval_v3p/evaluate.log
log "done"
