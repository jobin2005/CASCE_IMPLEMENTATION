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

import sys
import json
import csv
from pathlib import Path
from collections import defaultdict


def create_zeroday_splits(data_dir: Path, holdout_scenario="exfil", model_path: Path = None, threshold: float = 0.65):
    """Create train/holdout splits by holding out entire families and optionally evaluate.
    
    Args:
        data_dir: Path to the generated data directory (e.g. datagen/generated/multi_domain_huge)
        holdout_scenario: Keyword to match against scenario_id/family_id
        model_path: Optional path to trained GAT checkpoint for immediate evaluation
        threshold: Classification threshold theta_a (default: 0.65)
    """
    data_dir = Path(data_dir)
    # If user pointed directly to enriched_graphs or graphml, get the parent data dir
    if data_dir.name in ("graphml", "enriched_graphs"):
        data_dir = data_dir.parents[1] if data_dir.name == "graphml" else data_dir.parent

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
                family_id = sdata.get("family_id", sname)
                if holdout_scenario.lower() in sname.lower() or holdout_scenario.lower() in family_id.lower():
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

    print(f"\nZero-Day Holdout Splits for scenario keyword '{holdout_scenario}':")
    print(f"  Held-out families ({len(holdout_families)}): {sorted(holdout_families)}")
    print(f"  Train Set: {len(train_dict)} graphs "
          f"({train_mal} malicious, {len(train_dict)-train_mal} benign)")
    print(f"  Holdout Val Set: {len(val_dict)} graphs "
          f"({val_mal} malicious, {len(val_dict)-val_mal} benign)")
    print(f"  Splits written to: {out_dir}")

    # Critical: warn if held-out set is single-class
    if val_dict:
        classes_in_holdout = set(val_dict.values())
        if len(classes_in_holdout) < 2:
            class_name = "malicious" if 1 in classes_in_holdout else "benign"
            print(f"  ⚠ WARNING: Holdout set is 100% {class_name}!")
        else:
            print(f"  ✓ Holdout set contains balanced classes")

    # Evaluate if model_path provided
    if model_path and Path(model_path).exists() and val_dict:
        print(f"\nEvaluating trained model '{model_path}' on held-out zero-day families...")
        from algorithm_4_hybrid import detect, load_model
        import networkx as nx

        model = load_model(str(model_path))
        y_true, y_pred = [], []
        for filename, label in val_dict.items():
            gpath = graphml_dir / filename
            if not gpath.exists():
                continue
            G = nx.read_graphml(gpath)
            sid = filename.replace("enriched_", "").replace(".graphml", "")
            res = detect(G, model, session_id=sid, theta_a=threshold)
            pred = 1 if res["risk"] >= threshold else 0
            y_true.append(int(label))
            y_pred.append(pred)

        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        acc = (tp + tn) / max(1, len(y_true))
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(1e-9, prec + rec)

        print(f"\n{'='*65}")
        print(f" ZERO-DAY ATTACK GENERALIZATION REPORT ('{holdout_scenario}', θ_A = {threshold})")
        print(f"{'='*65}")
        print(f"  Samples:     {len(y_true)} ({tp+fn} malicious, {tn+fp} benign)")
        print(f"  Accuracy:    {acc:.4f}")
        print(f"  Precision:   {prec:.4f}")
        print(f"  Recall:      {rec:.4f}")
        print(f"  F1 Score:    {f1:.4f}")
        print(f"  Confusion:   TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"{'='*65}\n")

    return out_dir


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Zero-day attack family holdout split & evaluation.")
    parser.add_argument("data_dir", nargs="?", default="datagen/generated/multi_domain_huge",
                        help="Root data directory containing run_* subdirectories.")
    parser.add_argument("--data-dir", dest="data_dir_opt", default=None,
                        help="Alternative flag for data directory.")
    parser.add_argument("--scenario", "--keyword", dest="scenario", default="exfil",
                        help="Scenario/family keyword to hold out completely (e.g. exfil, tamper, alter_role, lateral).")
    parser.add_argument("--model-path", default=None,
                        help="Optional model checkpoint (.pt) to evaluate immediately on holdout set.")
    parser.add_argument("--theta-a", "--threshold", dest="threshold", type=float, default=0.65,
                        help="Classification threshold theta_a (default: 0.65).")
    args = parser.parse_args()

    target_dir = args.data_dir_opt or args.data_dir
    create_zeroday_splits(
        data_dir=target_dir,
        holdout_scenario=args.scenario,
        model_path=args.model_path,
        threshold=args.threshold
    )
