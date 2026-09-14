#!/usr/bin/env python3
"""
Zero-Day Attack Family Holdout Experiment
===========================================
Holds out 100% of a specific attack family (e.g. Sabotage / Exfiltration /
Defense Evasion) from the training set and evaluates model generalization
on completely unseen attack patterns.

Uses expectation_manifest.json to identify families, ensuring both halves
of matched pairs (benign + malicious) are held out together.
"""

import json
import csv
from pathlib import Path
from collections import defaultdict


def create_zeroday_splits(data_dir: Path, holdout_scenario="sabotage"):
    """Create train/holdout splits by holding out entire families.
    
    Args:
        data_dir: Path to the generated data directory
        holdout_scenario: Keyword to match against scenario_id/family_id
    """
    manifest_file = data_dir / "expectation_manifest.json"
    graphml_dir = data_dir / "enriched_graphs" / "graphml"

    # Load labels
    raw_labels = {}
    for lf in data_dir.glob("run_*/labels.csv"):
        run_name = lf.parent.name
        with open(lf, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sid = row.get("session_id")
                if sid:
                    raw_labels[f"{run_name}_{sid}"] = (
                        1 if row["label"] in ("Attack", "Malicious") else 0
                    )

    # Build family map from manifest
    family_to_scenarios = defaultdict(list)
    pid_to_family = {}
    
    manifest_files = list(data_dir.glob("run_*/expectation_manifest.json"))
    for manifest_file in manifest_files:
        run_name = manifest_file.parent.name
        with open(manifest_file) as f:
            manifest = json.load(f)
            for sname, sdata in manifest.get("scenarios", {}).items():
                family_id = sdata.get("family_id", sname)
                family_to_scenarios[family_id].append(sname)
                for sess_label, sess_info in sdata.get("sessions", {}).items():
                    pid = sess_info.get("backend_pid")
                    if pid:
                        pid_to_family[f"{run_name}_{pid}"] = family_id

    # Identify holdout families
    holdout_families = set()
    for manifest_file in manifest_files:
        with open(manifest_file) as f:
            manifest = json.load(f)
            for sname, sdata in manifest.get("scenarios", {}).items():
                if holdout_scenario.lower() in sname.lower():
                    family_id = sdata.get("family_id", sname)
                    holdout_families.add(family_id)

    # Match graphml files to families
    graph_files = sorted(graphml_dir.glob("enriched_*.graphml"))

    train_dict = {}
    val_dict = {}

    for gfile in graph_files:
        filename = gfile.name
        parts = filename.replace("enriched_", "").replace(".graphml", "").split("_")
        if len(parts) >= 3 and parts[0] == "run":
            run_sid = f"{parts[0]}_{parts[1]}_{parts[2]}"
        else:
            continue
            
        if run_sid not in raw_labels:
            continue
        label = raw_labels[run_sid]

        family = pid_to_family.get(run_sid, "")
        if family in holdout_families:
            val_dict[filename] = label
        else:
            train_dict[filename] = label

    out_dir = data_dir / f"zeroday_splits_{holdout_scenario}"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "train_labels.json").write_text(json.dumps(train_dict, indent=2))
    (out_dir / "val_labels.json").write_text(json.dumps(val_dict, indent=2))

    train_mal = sum(train_dict.values())
    val_mal = sum(val_dict.values())

    print(f"\nZero-Day Holdout Splits for '{holdout_scenario}':")
    print(f"  Held-out families: {sorted(holdout_families)}")
    print(f"  Train Set: {len(train_dict)} graphs "
          f"({train_mal} malicious, {len(train_dict)-train_mal} benign)")
    print(f"  Holdout Val Set: {len(val_dict)} graphs "
          f"({val_mal} malicious, {len(val_dict)-val_mal} benign)")

    # Critical: warn if held-out set is single-class
    if val_dict:
        classes_in_holdout = set(val_dict.values())
        if len(classes_in_holdout) < 2:
            class_name = "malicious" if 1 in classes_in_holdout else "benign"
            print(f"  ⚠ WARNING: Holdout set is 100% {class_name}!")
            print(f"    Evaluation cannot fail — 'predict {class_name} always' scores 100%.")
        else:
            print(f"  ✓ Holdout set contains both classes")

    return out_dir


if __name__ == '__main__':
    data_dir = Path("datagen/generated/banking_1000")
    create_zeroday_splits(data_dir, holdout_scenario="exfil")
