#!/usr/bin/env python3
"""
Zero-Day Attack Family Holdout Experiment Runner
=================================================
Holds out ENTIRE families (both benign and malicious halves) matching
a keyword, trains the GAT on the remaining families, and evaluates.

Previous version only held out the malicious half (e.g. 'defense_mal'),
leaving the benign twin ('audit_ben') in training — making the held-out
set 100% one class and the evaluation unable to fail.
"""

import os
import json
import subprocess
from pathlib import Path
from collections import defaultdict


def run_zeroday_experiment(data_dir: Path, holdout_keyword="defense"):
    manifest_file = data_dir / "expectation_manifest.json"
    with open(manifest_file) as f:
        manifest = json.load(f)

    # Build family_id -> [graphml filenames] mapping
    family_to_files = defaultdict(list)
    file_to_family = {}

    for sname, sdata in manifest.get("scenarios", {}).items():
        family_id = sdata.get("family_id", sname)
        for sess_label, sess_info in sdata.get("sessions", {}).items():
            pid = sess_info.get("backend_pid")
            if pid:
                fname = f"enriched_banking_1000_session_{pid}.graphml"
                family_to_files[family_id].append(fname)
                file_to_family[fname] = family_id

    # Identify which FAMILIES match the holdout keyword
    # (not individual scenarios — we hold out the entire family)
    holdout_families = set()
    for sname, sdata in manifest.get("scenarios", {}).items():
        if holdout_keyword.lower() in sname.lower():
            family_id = sdata.get("family_id", sname)
            holdout_families.add(family_id)

    if not holdout_families:
        print(f"WARNING: No families match keyword '{holdout_keyword}'")
        return

    print(f"Holding out {len(holdout_families)} family/families matching '{holdout_keyword}':")
    for fid in sorted(holdout_families):
        print(f"  - {fid} ({len(family_to_files[fid])} sessions)")

    # Load all labels
    labels_file = data_dir / "algo4_splits" / "all_labels.json"
    with open(labels_file) as f:
        all_labels = json.load(f)

    # Split by family, holding out BOTH halves of matched families
    train_labels = {}
    val_labels = {}

    for gfile, label in all_labels.items():
        family = file_to_family.get(gfile, "")
        if family in holdout_families:
            val_labels[gfile] = label
        else:
            train_labels[gfile] = label

    # Report class distribution — this is the key diagnostic
    val_mal = sum(val_labels.values())
    val_ben = len(val_labels) - val_mal
    train_mal = sum(train_labels.values())
    train_ben = len(train_labels) - train_mal

    out_dir = data_dir / f"zeroday_{holdout_keyword}"
    out_dir.mkdir(parents=True, exist_ok=True)

    train_path = out_dir / "train_labels.json"
    val_path = out_dir / "val_labels.json"

    train_path.write_text(json.dumps(train_labels, indent=2))
    val_path.write_text(json.dumps(val_labels, indent=2))

    print(f"\n{'='*60}")
    print(f" ZERO-DAY HOLDOUT SPLIT FOR KEYWORD: '{holdout_keyword}'")
    print(f"{'='*60}")
    print(f"  Training Set: {len(train_labels)} graphs "
          f"({train_mal} malicious, {train_ben} benign)")
    print(f"  Holdout Set:  {len(val_labels)} graphs "
          f"({val_mal} malicious, {val_ben} benign)")

    # Critical diagnostic: warn if held-out set is single-class
    if val_labels:
        classes_in_holdout = set(val_labels.values())
        if len(classes_in_holdout) < 2:
            class_name = "malicious" if 1 in classes_in_holdout else "benign"
            print(f"\n  ⚠ WARNING: Held-out set is 100% {class_name}!")
            print(f"    FPR is unmeasurable. 'Predict {class_name} always' scores 100%.")
            print(f"    This means the evaluation CANNOT FAIL.")
        else:
            print(f"\n  ✓ Held-out set contains both classes (can measure FPR)")

    # 1. Train GAT on Train Set
    model_path = out_dir / "zeroday_gat.pt"
    cmd_train = [
        "./.venv/bin/python3", "algorithm_4_hybrid.py", "--mode", "train",
        "--train-dir", str(data_dir / "enriched_graphs" / "graphml"),
        "--train-labels", str(train_path),
        "--val-dir", str(data_dir / "enriched_graphs" / "graphml"),
        "--val-labels", str(val_path),
        "--model-path", str(model_path),
        "--epochs", "25"
    ]
    print("\n--- Training Model on Train Set ---")
    subprocess.run(cmd_train, check=True)

    # 2. Evaluate GAT on Held-Out Val Set
    cmd_eval = [
        "./.venv/bin/python3", "algorithm_4_hybrid.py", "--mode", "evaluate",
        "--input-dir", str(data_dir / "enriched_graphs" / "graphml"),
        "--labels", str(val_path),
        "--model-path", str(model_path),
        "--outdir", str(out_dir / "eval")
    ]
    print("\n--- Evaluating Model on Held-Out Zero-Day Set ---")
    subprocess.run(cmd_eval, check=True)


if __name__ == '__main__':
    data_dir = Path("datagen/generated/banking_1000")
    run_zeroday_experiment(data_dir, holdout_keyword="defense")
