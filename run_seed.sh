#!/usr/bin/env bash
# Seed-variance run for one model config: train -> tune theta on validation ->
# per-template test report. Uses the exact data of casce_gat_v2 / the
# priv_abuse holdout (see their .json sidecars).
#
#   ./run_seed.sh holdout_priv_abuse 1      # or: ./run_seed.sh v2 1
#
# Writes models_seeds/<name>_s<seed>.{pt,json}, .train.log, .tune/, .report.json
set -euo pipefail
cd "$(dirname "$0")"
name=$1 seed=$2
case $name in
  v2) lbl_train=dataset_dev/algo4_splits/train_labels.json,training_v2/dev_train_prefixes/labels.json
      lbl_val=dataset_dev/algo4_splits/val_labels.json,training_v2/dev_val_prefixes/labels.json ;;
  holdout_priv_abuse)
      h=training_v2/holdout_priv_abuse
      lbl_train=$h/algo4_splits__train_labels.json,$h/dev_train_prefixes__labels.json
      lbl_val=$h/algo4_splits__val_labels.json,$h/dev_val_prefixes__labels.json ;;
  *) echo "unknown config $name" >&2; exit 1 ;;
esac
train_dir=dataset_dev/enriched_graphs/graphml,training_v2/dev_train_prefixes/graphml,training_v2/pgbench_train/graphml
val_dir=dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml
out=models_seeds/${name}_s${seed}
mkdir -p models_seeds

python3 -u algorithm_4_hybrid.py --mode train --feature-version 2 --seed "$seed" --epochs 50 \
  --train-dir $train_dir --train-labels $lbl_train,training_v2/pgbench_train/labels.json \
  --val-dir $val_dir --val-labels $lbl_val,training_v2/pgbench_val/labels.json \
  --model-path $out.pt > $out.train.log 2>&1

python3 -u algorithm_4_hybrid.py --mode tune --model-path $out.pt --input-dir $val_dir \
  --labels $lbl_val,training_v2/pgbench_val/labels.json --outdir $out.tune > $out.tune.log 2>&1
theta=$(python3 -c "import json; print(json.load(open('$out.tune/threshold_sweep.json'))['best_theta'])")

python3 -u holdout_report.py --family banking_priv_abuse --theta "$theta" --model "$name=$out.pt" \
  --out $out.report.json > $out.report.log 2>&1
echo "$name seed $seed done, theta $theta"
