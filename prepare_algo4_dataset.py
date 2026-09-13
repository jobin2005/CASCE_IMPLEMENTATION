#!/usr/bin/env python3
"""
Prepare Train/Val Labels for Algorithm 4 HeteroGAT Model Training
===================================================================
Converts datagen/generated/banking_1000/labels.csv into structured
train_labels.json and val_labels.json mapping graphml file basenames to 0 (benign) or 1 (malicious).
"""

import os
import csv
import json
import random
from pathlib import Path

def prepare_splits(data_dir: Path, train_ratio=0.8, seed=42):
    labels_csv = data_dir / "labels.csv"
    graphml_dir = data_dir / "enriched_graphs" / "graphml"

    if not labels_csv.exists():
        raise FileNotFoundError(f"labels.csv not found at '{labels_csv}'")
    if not graphml_dir.exists():
        raise FileNotFoundError(f"Enriched graphml directory not found at '{graphml_dir}'")

    raw_labels = {}
    with open(labels_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sid = row["session_id"]
            lbl = 1 if row["label"] in ("Attack", "Malicious") else 0
            raw_labels[sid] = lbl

    # Match with graphml files
    graph_files = sorted(graphml_dir.glob("enriched_*.graphml"))
    print(f"Found {len(graph_files)} enriched GraphML files.")

    paired_data = []
    for gfile in graph_files:
        filename = gfile.name
        # extract session id from enriched_banking_1000_session_20000.graphml
        sid = filename.replace("enriched_", "").replace(".graphml", "").split("_")[-1]
        if sid in raw_labels:
            paired_data.append((filename, raw_labels[sid]))

    random.seed(seed)
    random.shuffle(paired_data)

    split_idx = int(len(paired_data) * train_ratio)
    train_pairs = paired_data[:split_idx]
    val_pairs = paired_data[split_idx:]

    train_dict = dict(train_pairs)
    val_dict = dict(val_pairs)

    out_dir = data_dir / "algo4_splits"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "train_labels.json").write_text(json.dumps(train_dict, indent=2))
    (out_dir / "val_labels.json").write_text(json.dumps(val_dict, indent=2))
    (out_dir / "all_labels.json").write_text(json.dumps(dict(paired_data), indent=2))

    print(f"\nSaved Splits to '{out_dir}':")
    print(f"  Train Set: {len(train_dict)} graphs ({sum(train_dict.values())} malicious, {len(train_dict)-sum(train_dict.values())} benign)")
    print(f"  Val Set:   {len(val_dict)} graphs ({sum(val_dict.values())} malicious, {len(val_dict)-sum(val_dict.values())} benign)")

if __name__ == '__main__':
    data_dir = Path("datagen/generated/banking_1000")
    prepare_splits(data_dir)
