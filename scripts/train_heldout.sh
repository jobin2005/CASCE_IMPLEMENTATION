#!/usr/bin/env bash
# train_heldout.sh: Retrain CASCE HeteroGAT strictly on the zero-day heldout split
# Runs 1..42: Training (labels_train_noheldout.json)
# Runs 43..56: Validation (labels_val_noheldout.json)
set -e

echo "============================================================"
echo "  Retraining CASCE HeteroGAT on Held-Out Split"
echo "  Target Model: casce_gat_noheldout.pt"
echo "============================================================"

TRAIN_DIRS=$(eval echo output/dataset_dev/run_{1..42} | tr ' ' ',')
VAL_DIRS=$(eval echo output/dataset_dev/run_{43..56} | tr ' ' ',')

TRAIN_LABELS=$(eval echo output/dataset_dev/run_{1..42}/labels_train_noheldout.json | tr ' ' ',')
VAL_LABELS=$(eval echo output/dataset_dev/run_{43..56}/labels_val_noheldout.json | tr ' ' ',')

python3 algorithm_4_hybrid.py --mode train \
  --train-dir "$TRAIN_DIRS" \
  --train-labels "$TRAIN_LABELS" \
  --val-dir "$VAL_DIRS" \
  --val-labels "$VAL_LABELS" \
  --model-path casce_gat_noheldout.pt \
  --epochs 50 \
  --lr 1e-3

echo ""
echo "Retraining complete. Weights saved to casce_gat_noheldout.pt"
