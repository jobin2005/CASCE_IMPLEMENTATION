#!/usr/bin/env bash
# eval_heldout.sh: Evaluate CASCE hybrid detector on held-out zero-day attack families
set -e

DEV_DIRS=$(eval echo output/dataset_dev/run_{1..56} | tr ' ' ',')
TEST_DIRS=$(eval echo output/dataset_test/run_{1..24} | tr ' ' ',')
ALL_DIRS="${DEV_DIRS},${TEST_DIRS}"

DEV_LABELS=$(eval echo output/dataset_dev/run_{1..56}/labels_heldout_eval.json | tr ' ' ',')
TEST_LABELS=$(eval echo output/dataset_test/run_{1..24}/labels_heldout_eval.json | tr ' ' ',')
ALL_LABELS="${DEV_LABELS},${TEST_LABELS}"

python3 algorithm_4_hybrid.py --mode evaluate \
  --input-dir "$ALL_DIRS" \
  --labels "$ALL_LABELS" \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_heldout
