#!/usr/bin/env bash
# run_eval_indist.sh: Evaluate CASCE detector using evaluate.py on In-Distribution test split
set -e

TEST_DIRS=$(eval echo output/dataset_test/run_{1..24} | tr ' ' ',')
TEST_LABELS=$(eval echo output/dataset_test/run_{1..24}/labels_test_indist.json | tr ' ' ',')

python3 evaluate.py \
  --input-dirs "$TEST_DIRS" \
  --label-files "$TEST_LABELS" \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_indist_report
