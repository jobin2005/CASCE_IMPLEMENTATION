#!/usr/bin/env bash
# Evaluate an ensemble described by <name>.json ({"ensemble": [member .pt files]}):
# tune θ on the v3P validation set, offline test (E1 test + held-out benign_extra
# runs 107-112), replay of the 8_final live capture, comparison with single models.
#   bash run_ensemble_eval.sh casce_gat_v3p_ens2
set -uo pipefail
cd "$(dirname "$0")"
name=$1; out=live_eval_ensemble/$name; mkdir -p $out
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-4}
VAL_DIR=dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml,dataset_benign_extra/enriched_graphs/graphml
VAL_LBL=dataset_dev/algo4_splits/val_labels.json,training_v2/dev_val_prefixes/labels.json,training_v2/pgbench_val/labels.json,training_v3p/benign_extra_val.json
log() { echo "== $(date +%H:%M) $*"; }
log "tune θ on validation"
python3 -u algorithm_4_hybrid.py --mode tune --model-path $name.pt --theta-mode f1 \
  --input-dir $VAL_DIR --labels $VAL_LBL --outdir $out/tune > $out/tune.log 2>&1
grep -E "Best F1|Recorded" $out/tune.log
log "offline test"
python3 -u algorithm_4_hybrid.py --mode evaluate --model-path $name.pt \
  --input-dir dataset_test/enriched_graphs/graphml,dataset_benign_extra/enriched_graphs/graphml \
  --labels dataset_test/algo4_splits/test_labels.json,training_v3p/benign_extra_test.json \
  --outdir $out/eval_offline > $out/evaluate.log 2>&1
grep -E "Samples|Precision|Recall|F1|FPR|ROC" $out/evaluate.log
log "replay 8_final"
rm -rf live_runs/8_final/daemon_${name#casce_gat_}_replay
python3 -u realtime_daemon.py --replay --replay-realtime --log-dir live_runs/8_final --model-path $name.pt \
  --out-dir live_runs/8_final/daemon_${name#casce_gat_}_replay > $out/replay.log 2>&1
python3 workload_simulation/live_compare.py live_runs/8_final daemon_v3_live daemon_v3p_live daemon_v3p_s7_replay \
  daemon_${name#casce_gat_}_replay | tee $out/compare_8_final.md
log "done"
