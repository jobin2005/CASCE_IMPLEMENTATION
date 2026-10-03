#!/usr/bin/env bash
# Re-tune θ with --theta-mode f1 (the original rule) for already-trained models,
# without retraining: rescore_f1.sh <src-dir> <dst-dir> [seed]
set -uo pipefail
cd "$(dirname "$0")/.."
src=$1 dst=$2 seed=${3:-1}
full=dataset_dev/enriched_graphs/graphml; pref=training_v2/dev_all_prefixes/graphml
mkdir -p "$dst"
for f in $(python3 -c "import json;print(' '.join(f['fold'] for f in json.load(open('loto/folds.json'))['folds']))"); do
  o=$dst/${f}_s${seed}; d=training_v2/loto/$f
  [ -f $o.report.json ] && continue
  cp $src/${f}_s${seed}.pt $o.pt && cp $src/${f}_s${seed}.json $o.json
  python3 -u algorithm_4_hybrid.py --mode tune --model-path $o.pt --theta-mode f1 \
    --input-dir $full,$pref,training_v2/pgbench_val/graphml \
    --labels $d/val_full.json,$d/val_prefixes.json,training_v2/pgbench_val/labels.json \
    --outdir $o.tune > $o.tune.log 2>&1
  theta=$(python3 -c "import json; print(json.load(open('$o.json'))['theta_a'])")
  python3 -u fold_report.py --fold-dir $d --model $o.pt --theta "$theta" --out $o.report.json > $o.report.log 2>&1
done
python3 loto_summary.py --dir "$dst" --out "$dst/loto_summary.json" > "$dst/loto_summary.txt" 2>&1
