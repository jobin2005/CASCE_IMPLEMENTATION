#!/usr/bin/env python3
"""
Zero-Day Attack Family Holdout Experiment Runner
=================================================
Identifies scenario attack families from expectation_manifest.json,
holds out 100% of a target attack family (e.g., 'defense_mal' or 'exfil'),
trains the GAT model on the remaining 4 families, and evaluates performance.
"""

import os
import json
import subprocess
from pathlib import Path

def run_zeroday_experiment(data_dir: Path, holdout_keyword="defense"):
    manifest_file = data_dir / "expectation_manifest.json"
    with open(manifest_file) as f:
        manifest = json.load(f)

    session_to_scenario = {}
    scenario_family = {}

    for sname, sdata in manifest.get("scenarios", {}).items():
        family = sname  # e.g. banking_gen_0006_defense_mal
        scenario_family[sname] = family
        for sess_key, sess_info in sdata.get("sessions", {}).items():
            pid = sess_info.get("backend_pid")
            if pid:
                session_to_scenario[f"enriched_banking_1000_session_{pid}.graphml"] = sname
                session_to_scenario[f"banking_1000_session_{pid}.graphml"] = sname

    labels_file = data_dir / "algo4_splits" / "all_labels.json"
    with open(labels_file) as f:
        all_labels = json.load(f)

    train_labels = {}
    val_labels = {}

    for gfile, label in all_labels.items():
        sname = session_to_scenario.get(gfile, "")
        if holdout_keyword.lower() in sname.lower():
            val_labels[gfile] = label
        else:
            train_labels[gfile] = label

    out_dir = data_dir / f"zeroday_{holdout_keyword}"
    out_dir.mkdir(parents=True, exist_ok=True)

    train_path = out_dir / "train_labels.json"
    val_path = out_dir / "val_labels.json"

    train_path.write_text(json.dumps(train_labels, indent=2))
    val_path.write_text(json.dumps(val_labels, indent=2))

    print(f"\n========================================================")
    print(f" ZERO-DAY HOLDOUT SPLIT FOR ATTACK KEYWORD: '{holdout_keyword}'")
    print(f"========================================================")
    print(f"  Training Set (Remaining Families): {len(train_labels)} graphs ({sum(train_labels.values())} malicious)")
    print(f"  Validation Set (Held-Out Zero-Day): {len(val_labels)} graphs ({sum(val_labels.values())} malicious)")

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
