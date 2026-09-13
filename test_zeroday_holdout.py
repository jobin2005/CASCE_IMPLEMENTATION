#!/usr/bin/env python3
"""
Zero-Day Attack Family Holdout Experiment
===========================================
Holds out 100% of a specific attack family (e.g. Sabotage / Exfiltration / Defense Evasion)
from the training set and evaluates model generalization on completely unseen attack patterns.
"""

import os
import json
import csv
from pathlib import Path

def create_zeroday_splits(data_dir: Path, holdout_scenario="sabotage"):
    labels_csv = data_dir / "labels.csv"
    graphml_dir = data_dir / "enriched_graphs" / "graphml"

    raw_metadata = {}
    with open(labels_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_metadata[row["session_id"]] = {
                "label": 1 if row["label"] in ("Attack", "Malicious") else 0,
                "role": row.get("role", ""),
                "pair_id": row.get("matched_pair_id", "")
            }

    # Load specs to identify scenario types
    specs_dir = data_dir / "specs"
    scenario_types = {}
    for spec_file in specs_dir.glob("*.yaml"):
        # e.g. banking_gen_0002_exfil_mal.yaml
        name = spec_file.stem
        # find matching session id
        # spec file names correspond to matched pairs
        parts = name.split("_")
        stype = parts[3] if len(parts) >= 4 else "unknown"
        scenario_types[name] = stype

    graph_files = sorted(graphml_dir.glob("enriched_*.graphml"))

    train_dict = {}
    val_dict = {}
    holdout_count = 0

    for gfile in graph_files:
        filename = gfile.name
        sid = filename.replace("enriched_", "").replace(".graphml", "").split("_")[-1]
        meta = raw_metadata.get(sid, {})
        label = meta.get("label", 0)

        # Check if this graph belongs to the holdout scenario family
        # E.g. search if holdout_scenario is in the spec name or spec files
        is_holdout = False
        # We can map sid (e.g. 20000) to spec index
        spec_num = (int(sid) - 20000) // 2 + 1 if sid.isdigit() and int(sid) >= 20000 else 0
        spec_pattern = f"banking_gen_{spec_num:04d}"

        for sname, stype in scenario_types.items():
            if spec_pattern in sname and holdout_scenario.lower() in stype.lower():
                is_holdout = True
                break

        if is_holdout:
            val_dict[filename] = label
            holdout_count += 1
        else:
            train_dict[filename] = label

    out_dir = data_dir / f"zeroday_splits_{holdout_scenario}"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "train_labels.json").write_text(json.dumps(train_dict, indent=2))
    (out_dir / "val_labels.json").write_text(json.dumps(val_dict, indent=2))

    print(f"\nZero-Day Holdout Splits for '{holdout_scenario}':")
    print(f"  Train Set: {len(train_dict)} graphs ({sum(train_dict.values())} malicious, {len(train_dict)-sum(train_dict.values())} benign)")
    print(f"  Holdout Val Set: {len(val_dict)} graphs ({sum(val_dict.values())} malicious, {len(val_dict)-sum(val_dict.values())} benign)")
    return out_dir

if __name__ == '__main__':
    data_dir = Path("datagen/generated/banking_1000")
    create_zeroday_splits(data_dir, holdout_scenario="exfil")
