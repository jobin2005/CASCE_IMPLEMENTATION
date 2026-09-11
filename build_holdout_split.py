#!/usr/bin/env python3
"""
build_holdout_split.py
=======================

Fixes the train/test leakage flagged in the review: dataset_dev and
dataset_test contain byte-identical attack payloads (same scripts, same
commands, same exfil endpoint), so the existing run-level split
(dev runs 1-42 train / 43-56 val / dataset_test = test) never actually
measures generalization -- the model has seen the literal attack scripts
in the "held-out" test set during training.

This script does NOT touch your raw dataset (it can't invent new attack
payloads). What it CAN do: hold one or more entire attack *families* out
of training entirely, so the model never sees that family's payload
during train or val, and give you a separate, honest metric for how it
does on that family wherever it appears (dev or test). Report that number
alongside your existing test number, and be explicit in the paper that
the existing test number measures re-recognition, not generalization,
for the families you did NOT hold out.

Usage
-----
1. See what attack families you have and how they're distributed:
       python3 build_holdout_split.py --inventory \
           --output-root output

2. Once you've picked one or more families to hold out completely from
   training (pick ones with enough examples in both dev and test to be
   informative -- see the inventory table):
       python3 build_holdout_split.py \
           --output-root output \
           --holdout-types "Data_Exfiltration,Ingress_Tool_Transfer"

   This writes, per run directory, in addition to (never overwriting)
   the existing labels.json:
     - labels_train_noheldout.json   (dataset_dev runs 1..TRAIN_VAL_SPLIT,
                                       held-out families removed entirely)
     - labels_val_noheldout.json     (dataset_dev runs TRAIN_VAL_SPLIT+1..end,
                                       held-out families removed entirely)
     - labels_test_indist.json       (dataset_test, held-out families
                                       removed -- your "in-distribution"
                                       test number, same caveat as before)
     - labels_heldout_eval.json      (every session of a held-out family,
                                       from BOTH dataset_dev and
                                       dataset_test, plus all Normal
                                       sessions in that same run so
                                       precision/recall are both
                                       computable -- this is your honest
                                       generalization number)

3. Train on the no-heldout labels, then run evaluate.py twice: once
   against labels_test_indist.json (comparable to your old number, same
   leakage caveat) and once against labels_heldout_eval.json (the number
   that actually means something for the families you held out).
"""

import os
import json
import argparse

TRAIN_VAL_SPLIT = 42  # keep in sync with run_pipeline.py


def _attack_type_from_filename(fname):
    """enriched_session_<key>_<Label>.graphml -> ('Normal', is_normal) or
    (<Label>, False). Mirrors the parsing already used in run_pipeline.py's
    stage_stats(), so family names line up with what you saw there."""
    if "_Normal" in fname:
        return "Normal", True
    parts = fname.replace("enriched_session_", "").replace(".graphml", "").split("_", 1)
    atype = parts[1] if len(parts) > 1 else "Unknown"
    return atype, False


def _discover_runs(base_path):
    if not os.path.isdir(base_path):
        return []
    runs = [d for d in os.listdir(base_path)
            if d.startswith("run_") and os.path.isdir(os.path.join(base_path, d))]
    runs.sort(key=lambda x: int(x.split("_")[1]))
    return runs


def _run_num(run_name):
    return int(run_name.split("_")[1])


def _inventory(output_root):
    """Print attack-family counts per split so you can pick sensible
    holdout candidates -- ones with real examples in both dev and test."""
    dev_root = os.path.join(output_root, "dataset_dev")
    test_root = os.path.join(output_root, "dataset_test")

    counts = {"dataset_dev": {}, "dataset_test": {}}
    for root, split_name in [(dev_root, "dataset_dev"), (test_root, "dataset_test")]:
        for run in _discover_runs(root):
            run_dir = os.path.join(root, run)
            for fname in os.listdir(run_dir):
                if not fname.endswith(".graphml"):
                    continue
                atype, _ = _attack_type_from_filename(fname)
                counts[split_name][atype] = counts[split_name].get(atype, 0) + 1

    all_types = sorted(set(counts["dataset_dev"]) | set(counts["dataset_test"]))
    print(f"\n{'Attack family':<30} {'dataset_dev':>12} {'dataset_test':>13}")
    print("-" * 57)
    for atype in all_types:
        d = counts["dataset_dev"].get(atype, 0)
        t = counts["dataset_test"].get(atype, 0)
        flag = ""
        if atype != "Normal" and d > 0 and t > 0:
            flag = "  <- candidate for --holdout-types (present in both, so it's currently leaking)"
        print(f"{atype:<30} {d:>12} {t:>13}{flag}")
    print("\nPick one or more of the flagged families for --holdout-types. "
          "A family with very few examples will give a noisy held-out metric, "
          "so prefer ones with double digits in each split if you have the choice.")


def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _build_split(output_root, holdout_types):
    holdout_set = set(holdout_types)
    dev_root = os.path.join(output_root, "dataset_dev")
    test_root = os.path.join(output_root, "dataset_test")

    heldout_by_run = {}  # run_dir -> {filename: 1}  (all label=1, they're attacks)
    total_train = total_val = total_test_indist = total_heldout = 0

    dev_runs = _discover_runs(dev_root)
    for run in dev_runs:
        run_dir = os.path.join(dev_root, run)
        is_train = _run_num(run) <= TRAIN_VAL_SPLIT
        kept, heldout = {}, {}
        for fname in os.listdir(run_dir):
            if not fname.endswith(".graphml"):
                continue
            atype, is_normal = _attack_type_from_filename(fname)
            label = 0 if is_normal else 1
            if atype in holdout_set:
                heldout[fname] = 1  # only attack families go here, never Normal
            else:
                kept[fname] = label
        out_name = "labels_train_noheldout.json" if is_train else "labels_val_noheldout.json"
        _write_json(os.path.join(run_dir, out_name), kept)
        if is_train:
            total_train += len(kept)
        else:
            total_val += len(kept)
        if heldout:
            heldout_by_run[run_dir] = heldout
            total_heldout += len(heldout)

    test_runs = _discover_runs(test_root)
    for run in test_runs:
        run_dir = os.path.join(test_root, run)
        kept, heldout = {}, {}
        for fname in os.listdir(run_dir):
            if not fname.endswith(".graphml"):
                continue
            atype, is_normal = _attack_type_from_filename(fname)
            label = 0 if is_normal else 1
            if atype in holdout_set:
                heldout[fname] = 1
            else:
                kept[fname] = label
        _write_json(os.path.join(run_dir, "labels_test_indist.json"), kept)
        total_test_indist += len(kept)
        if heldout:
            heldout_by_run.setdefault(run_dir, {}).update(heldout)
            total_heldout += len(heldout)

    # Add Normal sessions from every run that contributed a held-out attack,
    # so labels_heldout_eval.json can report precision/recall, not just
    # recall-on-attacks-only.
    for run_dir, heldout in heldout_by_run.items():
        for fname in os.listdir(run_dir):
            if fname.endswith(".graphml") and "_Normal" in fname and fname not in heldout:
                heldout[fname] = 0
        _write_json(os.path.join(run_dir, "labels_heldout_eval.json"), heldout)

    print(f"\nWrote per-run label files under {dev_root} and {test_root}:")
    print(f"  labels_train_noheldout.json   total sessions: {total_train}")
    print(f"  labels_val_noheldout.json     total sessions: {total_val}")
    print(f"  labels_test_indist.json       total sessions: {total_test_indist}")
    print(f"  labels_heldout_eval.json      total sessions: {total_heldout}  "
          f"(across {len(heldout_by_run)} run dirs that had a held-out family present)")
    if total_heldout == 0:
        print(f"\n  WARNING: none of {sorted(holdout_set)} were found anywhere. "
              f"Re-check spelling against --inventory output (case-sensitive, "
              f"underscored).")

    print("\nNext steps:")
    print("  1. Train using *_noheldout.json label files (see the printed --train-dir/")
    print("     --train-labels/--val-dir/--val-labels command below).")
    print("  2. Evaluate twice: once on labels_test_indist.json (comparable to your old")
    print("     number, same overlap caveat), once on labels_heldout_eval.json (the")
    print("     number that actually reflects unseen-attack generalization).")

    train_dirs = [os.path.join(dev_root, r) for r in dev_runs if _run_num(r) <= TRAIN_VAL_SPLIT]
    val_dirs = [os.path.join(dev_root, r) for r in dev_runs if _run_num(r) > TRAIN_VAL_SPLIT]
    print("\n  python3 algorithm_4_hybrid.py --mode train \\")
    print(f"    --train-dir {','.join(train_dirs)} \\")
    print(f"    --train-labels {','.join(os.path.join(d, 'labels_train_noheldout.json') for d in train_dirs)} \\")
    print(f"    --val-dir {','.join(val_dirs)} \\")
    print(f"    --val-labels {','.join(os.path.join(d, 'labels_val_noheldout.json') for d in val_dirs)} \\")
    print("    --model-path casce_gat_noheldout.pt --epochs 50")

    heldout_dirs = list(heldout_by_run.keys())
    print("\n  python3 algorithm_4_hybrid.py --mode evaluate \\")
    print(f"    --input-dir {','.join(heldout_dirs)} \\")
    print(f"    --labels {','.join(os.path.join(d, 'labels_heldout_eval.json') for d in heldout_dirs)} \\")
    print("    --model-path casce_gat_noheldout.pt --outdir eval_heldout")


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output-root", default="output",
                   help="Directory containing dataset_dev/ and dataset_test/ (default: output)")
    p.add_argument("--inventory", action="store_true",
                   help="Print attack-family counts per split and exit (run this first).")
    p.add_argument("--holdout-types", default=None,
                   help="Comma-separated attack family names (exact match to filename label, "
                        "e.g. 'Data_Exfiltration,Ingress_Tool_Transfer') to exclude from all "
                        "training and validation.")
    return p.parse_args()


def main():
    args = parse_args()
    if args.inventory or not args.holdout_types:
        _inventory(args.output_root)
        if not args.holdout_types:
            print("\n(Pass --holdout-types \"Family1,Family2\" to actually build the split.)")
        return
    holdout_types = [t.strip() for t in args.holdout_types.split(",") if t.strip()]
    _build_split(args.output_root, holdout_types)


if __name__ == "__main__":
    main()