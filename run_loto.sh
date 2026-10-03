#!/usr/bin/env bash
# One template-disjoint fold, one seed: train (feature v2, same settings as
# casce_gat_v2) -> tune θ_A on the fold's validation templates -> report on the
# fold's unseen test templates. Folds come from make_template_folds.py.
#
#   ./run_loto.sh priv_abuse 1
#   FV=3 THETA_MODE=fpr OUT=loto_v3 ./run_loto.sh priv_abuse 1     # feature v3, benign-FPR θ
#
# Writes $OUT/<fold>_s<seed>.{pt,json}, .train.log, .tune/, .tune.log, .report.json
# (defaults FV=2 THETA_MODE=f1 OUT=loto reproduce the v2 runs)
set -euo pipefail
cd "$(dirname "$0")"
fold=$1 seed=$2
f=training_v2/loto/$fold
fv=${FV:-2} theta_mode=${THETA_MODE:-f1} outdir=${OUT:-loto}
out=$outdir/${fold}_s${seed}
full=dataset_dev/enriched_graphs/graphml
pref=training_v2/dev_all_prefixes/graphml
mkdir -p "$outdir"

python3 -u algorithm_4_hybrid.py --mode train --feature-version "$fv" --seed "$seed" --epochs 50 \
  --train-dir $full,$pref,training_v2/pgbench_train/graphml \
  --train-labels $f/train_full.json,$f/train_prefixes.json,training_v2/pgbench_train/labels.json \
  --val-dir $full,$pref,training_v2/pgbench_val/graphml \
  --val-labels $f/val_full.json,$f/val_prefixes.json,training_v2/pgbench_val/labels.json \
  --model-path $out.pt > $out.train.log 2>&1

python3 -u algorithm_4_hybrid.py --mode tune --model-path $out.pt --theta-mode "$theta_mode" \
  --input-dir $full,$pref,training_v2/pgbench_val/graphml \
  --labels $f/val_full.json,$f/val_prefixes.json,training_v2/pgbench_val/labels.json \
  --outdir $out.tune > $out.tune.log 2>&1
theta=$(python3 -c "import json; print(json.load(open('$out.json'))['theta_a'])")

python3 -u fold_report.py --fold-dir $f --model $out.pt --theta "$theta" --out $out.report.json \
  > $out.report.log 2>&1
echo "$fold seed $seed done, theta $theta: $(tail -n 1 $out.report.log)"
