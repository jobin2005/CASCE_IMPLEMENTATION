#!/usr/bin/env bash
# One template-disjoint fold, one seed: train (feature v2, same settings as
# casce_gat_v2) -> tune θ_A on the fold's validation templates -> report on the
# fold's unseen test templates. Folds come from make_template_folds.py.
#
#   ./run_loto.sh priv_abuse 1
#
# Writes loto/<fold>_s<seed>.{pt,json}, .train.log, .tune/, .tune.log, .report.json
set -euo pipefail
cd "$(dirname "$0")"
fold=$1 seed=$2
f=training_v2/loto/$fold
out=loto/${fold}_s${seed}
full=dataset_dev/enriched_graphs/graphml
pref=training_v2/dev_all_prefixes/graphml
mkdir -p loto

python3 -u algorithm_4_hybrid.py --mode train --feature-version 2 --seed "$seed" --epochs 50 \
  --train-dir $full,$pref,training_v2/pgbench_train/graphml \
  --train-labels $f/train_full.json,$f/train_prefixes.json,training_v2/pgbench_train/labels.json \
  --val-dir $full,$pref,training_v2/pgbench_val/graphml \
  --val-labels $f/val_full.json,$f/val_prefixes.json,training_v2/pgbench_val/labels.json \
  --model-path $out.pt > $out.train.log 2>&1

python3 -u algorithm_4_hybrid.py --mode tune --model-path $out.pt \
  --input-dir $full,$pref,training_v2/pgbench_val/graphml \
  --labels $f/val_full.json,$f/val_prefixes.json,training_v2/pgbench_val/labels.json \
  --outdir $out.tune > $out.tune.log 2>&1
theta=$(python3 -c "import json; print(json.load(open('$out.json'))['theta_a'])")

python3 -u fold_report.py --fold-dir $f --model $out.pt --theta "$theta" --out $out.report.json \
  > $out.report.log 2>&1
echo "$fold seed $seed done, theta $theta: $(tail -n 1 $out.report.log)"
