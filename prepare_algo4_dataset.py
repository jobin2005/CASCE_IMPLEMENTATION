#!/usr/bin/env python3
"""
Prepare Train/Val/Test Labels for Algorithm 4 HeteroGAT Model Training
========================================================================
Family-aware splitting: all sessions from the same family_id go into
the same split, preventing data leakage from structurally identical
graphs appearing in both training and validation sets.

Uses expectation_manifest.json (emitted by codegen.py) to resolve
family_id per session. Falls back to a heuristic family extraction
from filenames when the manifest is unavailable.
"""

import os
import csv
import json
import random
from pathlib import Path
from collections import defaultdict


def _load_family_map(data_dir: Path) -> dict:
    family_map = {}
    manifest_files = list(data_dir.glob("run_*/expectation_manifest.json"))
    
    for manifest_file in manifest_files:
        run_name = manifest_file.parent.name
        with open(manifest_file) as f:
            manifest = json.load(f)
        for sname, sdata in manifest.get("scenarios", {}).items():
            family_id = sdata.get("family_id", sname)
            for sess_label, sess_info in sdata.get("sessions", {}).items():
                pid = sess_info.get("backend_pid")
                if pid:
                    family_map[f"{run_name}_{pid}"] = family_id
                    
    return family_map


def prepare_splits(data_dir: Path, train_ratio=0.6, val_ratio=0.2, seed=42):
    """Split dataset by family_id into train/val/test sets.
    
    Args:
        data_dir: Path to the generated data directory
        train_ratio: Fraction of families for training (default 0.6)
        val_ratio: Fraction of families for validation (default 0.2)
        seed: Random seed for reproducibility
    
    The remaining (1 - train_ratio - val_ratio) goes to test.
    """
    graphml_dir = data_dir / "enriched_graphs" / "graphml"

    if not graphml_dir.exists():
        raise FileNotFoundError(f"Enriched graphml directory not found at '{graphml_dir}'")

    # Load labels from all run directories
    raw_labels = {}
    label_files = list(data_dir.glob("run_*/labels.csv"))
    if not label_files:
        raise FileNotFoundError(f"No labels.csv found in {data_dir}/run_*")
        
    for lf in label_files:
        run_name = lf.parent.name
        with open(lf, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sid = row.get("session_id")
                if sid:
                    lbl = 1 if row["label"] in ("Attack", "Malicious") else 0
                    raw_labels[f"{run_name}_{sid}"] = lbl

    # Match with graphml files
    graph_files = sorted(graphml_dir.glob("enriched_*.graphml"))
    print(f"Found {len(graph_files)} enriched GraphML files.")

    # Build family map
    family_map = _load_family_map(data_dir)

    # Build (filename, label, family_id) tuples
    families = defaultdict(list)  # family_id -> [(filename, label)]

    for gfile in graph_files:
        filename = gfile.name
        # format: enriched_run_001_20000_Benign.graphml
        parts = filename.replace("enriched_", "").replace(".graphml", "").split("_")
        
        if len(parts) >= 3 and parts[0] == "run":
            run_sid = f"{parts[0]}_{parts[1]}_{parts[2]}"
        else:
            continue
            
        if run_sid not in raw_labels:
            continue
        label = raw_labels[run_sid]

        if run_sid in family_map:
            fid = family_map[run_sid]
        else:
            fid = f"auto_family_{run_sid}"

        families[fid].append((filename, label))

    # Split families into train/val/test
    family_ids = sorted(families.keys())
    random.seed(seed)
    random.shuffle(family_ids)

    n_families = len(family_ids)
    n_train = int(n_families * train_ratio)
    n_val = int(n_families * val_ratio)

    train_families = set(family_ids[:n_train])
    val_families = set(family_ids[n_train:n_train + n_val])
    test_families = set(family_ids[n_train + n_val:])

    train_dict = {}
    val_dict = {}
    test_dict = {}

    for fid in train_families:
        for filename, label in families[fid]:
            train_dict[filename] = label

    for fid in val_families:
        for filename, label in families[fid]:
            val_dict[filename] = label

    for fid in test_families:
        for filename, label in families[fid]:
            test_dict[filename] = label

    # Verify no family overlap
    assert train_families.isdisjoint(val_families), "Train/val family overlap!"
    assert train_families.isdisjoint(test_families), "Train/test family overlap!"
    assert val_families.isdisjoint(test_families), "Val/test family overlap!"

    out_dir = data_dir / "algo4_splits"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "train_labels.json").write_text(json.dumps(train_dict, indent=2))
    (out_dir / "val_labels.json").write_text(json.dumps(val_dict, indent=2))
    (out_dir / "test_labels.json").write_text(json.dumps(test_dict, indent=2))
    (out_dir / "all_labels.json").write_text(
        json.dumps({**train_dict, **val_dict, **test_dict}, indent=2))

    # Save family split metadata for auditing
    split_meta = {
        "train_families": sorted(train_families),
        "val_families": sorted(val_families),
        "test_families": sorted(test_families),
        "seed": seed,
    }
    (out_dir / "split_metadata.json").write_text(json.dumps(split_meta, indent=2))

    def _stats(d):
        n_mal = sum(d.values())
        return f"{len(d)} graphs ({n_mal} malicious, {len(d)-n_mal} benign)"

    print(f"\nSaved Family-Aware Splits to '{out_dir}':")
    print(f"  Families:  {n_families} total ({len(train_families)} train, "
          f"{len(val_families)} val, {len(test_families)} test)")
    print(f"  Train Set: {_stats(train_dict)}")
    print(f"  Val Set:   {_stats(val_dict)}")
    print(f"  Test Set:  {_stats(test_dict)}")

    # Warn if any split is single-class
    for name, d in [("Train", train_dict), ("Val", val_dict), ("Test", test_dict)]:
        if d:
            labels_in_split = set(d.values())
            if len(labels_in_split) < 2:
                print(f"  ⚠ WARNING: {name} set is 100% class {labels_in_split.pop()}!")


if __name__ == '__main__':
    data_dir = Path("datagen/generated/banking_1000")
    prepare_splits(data_dir)
