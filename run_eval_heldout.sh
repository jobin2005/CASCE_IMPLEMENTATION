#!/usr/bin/env bash
# run_eval_heldout.sh: Evaluate CASCE detector using evaluate.py on Held-Out Zero-Day split
set -e

DEV_DIRS=$(eval echo output/dataset_dev/run_{1..56} | tr ' ' ',')
TEST_DIRS=$(eval echo output/dataset_test/run_{1..24} | tr ' ' ',')
ALL_DIRS="${DEV_DIRS},${TEST_DIRS}"

DEV_LABELS=$(eval echo output/dataset_dev/run_{1..56}/labels_heldout_eval.json | tr ' ' ',')
TEST_LABELS=$(eval echo output/dataset_test/run_{1..24}/labels_heldout_eval.json | tr ' ' ',')
ALL_LABELS="${DEV_LABELS},${TEST_LABELS}"

python3 evaluate.py \
  --input-dirs "$ALL_DIRS" \
  --label-files "$ALL_LABELS" \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_heldout_report
