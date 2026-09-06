#!/usr/bin/env python3
"""
CASCE — End-to-End Pipeline Orchestrator
==========================================

Runs the full pipeline using the `jobs` branch's main.py (Algorithms 1-3)
and then trains + evaluates the Algorithm 4 GAT on the output.

The enriched graphs from main.py are already in output/dataset_dev/run_*/
and output/dataset_test/run_*/. This script handles:
  - Generating labels.json files from the filenames (label is embedded)
  - Training with proper train/val/test split (no data leakage)
  - Evaluating on the held-out test set

Split Strategy (run-level, no data leakage):
  - Training:   dataset_dev runs 1 through 42  (75% of 56 runs)
  - Validation:  dataset_dev runs 43 through 56 (25% of 56 runs)
  - Test:        dataset_test (all 24 runs — held out, never seen in training)

Usage:
    python3 run_pipeline.py --stage all
    python3 run_pipeline.py --stage graphs     # Run main.py (Algorithms 1, 2, 3)
    python3 run_pipeline.py --stage labels     # Generate labels.json
    python3 run_pipeline.py --stage train      # Train Algorithm 4 GAT
    python3 run_pipeline.py --stage evaluate   # Evaluate on test set
    python3 run_pipeline.py --stage tune       # Tune thresholds on validation set
    python3 run_pipeline.py --stage stats      # Print dataset statistics
"""

import os
import json
import argparse
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')

DEV_OUTPUT = os.path.join(OUTPUT_DIR, 'dataset_dev')
TEST_OUTPUT = os.path.join(OUTPUT_DIR, 'dataset_test')

# Number used to split dev runs into train vs validation
# Runs 1..TRAIN_VAL_SPLIT are training, runs TRAIN_VAL_SPLIT+1..end are validation
TRAIN_VAL_SPLIT = 42


def _discover_runs(base_path):
    """Discover all run_* directories and return them sorted numerically."""
    if not os.path.isdir(base_path):
        return []
    runs = []
    for d in os.listdir(base_path):
        if d.startswith('run_') and os.path.isdir(os.path.join(base_path, d)):
            runs.append(d)
    runs.sort(key=lambda x: int(x.split('_')[1]))
    return runs


def _run_num(run_name):
    """Extract the numeric part from run_N."""
    return int(run_name.split('_')[1])


def run_cmd(cmd, desc):
    """Run a subprocess command with error handling."""
    print(f"\n{'='*60}")
    print(f"  {desc}")
    print(f"  CMD: {' '.join(cmd)}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, cwd=BASE_DIR, capture_output=False)
    if result.returncode != 0:
        print(f"[ERROR] Command failed with return code {result.returncode}")
        return False
    return True


def stage_graphs():
    """Run Algorithms 1, 2, and 3 via main.py."""
    print("\n" + "="*60)
    print("  STAGE: Building & Enriching Graphs (main.py)")
    print("="*60)
    return run_cmd([sys.executable, 'main.py'], "Executing main.py (Algorithms 1-3)")


def stage_labels():
    """Generate labels.json files from the enriched graph filenames."""
    print("\n" + "="*60)
    print("  STAGE: Generating labels.json for GAT")
    print("="*60)

    for base_path, split_name in [(DEV_OUTPUT, 'dataset_dev'), (TEST_OUTPUT, 'dataset_test')]:
        runs = _discover_runs(base_path)
        for run in runs:
            run_dir = os.path.join(base_path, run)
            out_json = os.path.join(run_dir, 'labels.json')

            labels_json = {}
            for fname in os.listdir(run_dir):
                if not fname.endswith('.graphml'):
                    continue
                # Label is embedded in filename: enriched_session_XXXXX_LabelName.graphml
                label = 0 if '_Normal' in fname else 1
                labels_json[fname] = label

            if labels_json:
                with open(out_json, 'w') as f:
                    json.dump(labels_json, f, indent=2)

                n_pos = sum(1 for v in labels_json.values() if v == 1)
                n_neg = sum(1 for v in labels_json.values() if v == 0)
                print(f"  {split_name}/{run}: {len(labels_json)} graphs ({n_neg} Normal, {n_pos} Malicious)")

    return True


def _collect_split_paths(base_path, runs, filename=None):
    """Collect comma-separated paths for a list of run directories."""
    paths = []
    for run in runs:
        p = os.path.join(base_path, run)
        if filename:
            p = os.path.join(p, filename)
        if os.path.exists(p):
            paths.append(p)
    return ','.join(paths)


def stage_train():
    """Train Algorithm 4 GAT with proper train/val split."""
    print("\n" + "="*60)
    print("  STAGE: Training GAT (Algorithm 4)")
    print("="*60)

    all_dev_runs = _discover_runs(DEV_OUTPUT)
    train_runs = [r for r in all_dev_runs if _run_num(r) <= TRAIN_VAL_SPLIT]
    val_runs = [r for r in all_dev_runs if _run_num(r) > TRAIN_VAL_SPLIT]

    print(f"  Training runs:   {len(train_runs)} ({train_runs[0]}..{train_runs[-1]})")
    print(f"  Validation runs: {len(val_runs)} ({val_runs[0]}..{val_runs[-1]})")

    train_dirs = _collect_split_paths(DEV_OUTPUT, train_runs)
    val_dirs = _collect_split_paths(DEV_OUTPUT, val_runs)
    train_labels = _collect_split_paths(DEV_OUTPUT, train_runs, 'labels.json')
    val_labels = _collect_split_paths(DEV_OUTPUT, val_runs, 'labels.json')
    model_path = os.path.join(BASE_DIR, 'casce_gat.pt')

    if not train_dirs:
        print("[ERROR] No training data found — run 'labels' stage first")
        return False

    return run_cmd(
        [sys.executable, 'algorithm_4_hybrid.py', '--mode', 'train',
         '--train-dir', train_dirs,
         '--val-dir', val_dirs,
         '--train-labels', train_labels,
         '--val-labels', val_labels,
         '--model-path', model_path,
         '--epochs', '50'],
        "Training CasceHeteroGAT"
    )


def stage_evaluate():
    """Evaluate on held-out test set."""
    print("\n" + "="*60)
    print("  STAGE: Evaluating on Test Set")
    print("="*60)

    test_runs = _discover_runs(TEST_OUTPUT)
    test_dirs = _collect_split_paths(TEST_OUTPUT, test_runs)
    test_labels = _collect_split_paths(TEST_OUTPUT, test_runs, 'labels.json')
    model_path = os.path.join(BASE_DIR, 'casce_gat.pt')

    if not test_dirs:
        print("[ERROR] No test data found — run 'labels' stage first")
        return False

    return run_cmd(
        [sys.executable, 'algorithm_4_hybrid.py', '--mode', 'evaluate',
         '--input-dir', test_dirs,
         '--labels', test_labels,
         '--model-path', model_path],
        "Evaluating on held-out test set"
    )


def stage_tune():
    """Tune thresholds on validation set."""
    print("\n" + "="*60)
    print("  STAGE: Tuning Thresholds on Validation Set")
    print("="*60)

    all_dev_runs = _discover_runs(DEV_OUTPUT)
    val_runs = [r for r in all_dev_runs if _run_num(r) > TRAIN_VAL_SPLIT]

    val_dirs = _collect_split_paths(DEV_OUTPUT, val_runs)
    val_labels = _collect_split_paths(DEV_OUTPUT, val_runs, 'labels.json')
    model_path = os.path.join(BASE_DIR, 'casce_gat.pt')

    if not val_dirs:
        print("[ERROR] No validation data found — run 'labels' stage first")
        return False

    return run_cmd(
        [sys.executable, 'algorithm_4_hybrid.py', '--mode', 'tune',
         '--input-dir', val_dirs,
         '--labels', val_labels,
         '--model-path', model_path],
        "Tuning thresholds on validation set"
    )


def stage_stats():
    """Print dataset statistics."""
    print("\n" + "="*60)
    print("  Dataset Statistics")
    print("="*60)

    for base_path, split_name in [(DEV_OUTPUT, 'dataset_dev'), (TEST_OUTPUT, 'dataset_test')]:
        runs = _discover_runs(base_path)
        total_normal = 0
        total_attack = 0
        attack_types = {}

        for run in runs:
            run_dir = os.path.join(base_path, run)
            for fname in os.listdir(run_dir):
                if not fname.endswith('.graphml'):
                    continue
                if '_Normal' in fname:
                    total_normal += 1
                else:
                    total_attack += 1
                    # Extract attack type from filename
                    # enriched_session_XXXXX_Attack_Type.graphml
                    parts = fname.replace('enriched_session_', '').replace('.graphml', '').split('_', 1)
                    if len(parts) > 1:
                        atype = parts[1]
                    else:
                        atype = 'Unknown'
                    attack_types[atype] = attack_types.get(atype, 0) + 1

        total = total_normal + total_attack
        print(f"\n  {split_name}: {len(runs)} runs, {total} total graphs")
        print(f"    Normal:    {total_normal}")
        print(f"    Malicious: {total_attack}")
        if attack_types:
            print(f"    Attack type breakdown:")
            for atype, count in sorted(attack_types.items(), key=lambda x: -x[1]):
                print(f"      {atype}: {count}")

    # Show split info
    all_dev_runs = _discover_runs(DEV_OUTPUT)
    train_runs = [r for r in all_dev_runs if _run_num(r) <= TRAIN_VAL_SPLIT]
    val_runs = [r for r in all_dev_runs if _run_num(r) > TRAIN_VAL_SPLIT]
    test_runs = _discover_runs(TEST_OUTPUT)
    print(f"\n  Split Strategy:")
    print(f"    Training:   {len(train_runs)} dev runs (run_1..run_{TRAIN_VAL_SPLIT})")
    print(f"    Validation: {len(val_runs)} dev runs (run_{TRAIN_VAL_SPLIT+1}..run_{_run_num(all_dev_runs[-1]) if all_dev_runs else '?'})")
    print(f"    Test:       {len(test_runs)} test runs (held out)")


def parse_args():
    p = argparse.ArgumentParser(description="CASCE End-to-End Pipeline Orchestrator")
    p.add_argument('--stage', default='all',
                   choices=['all', 'graphs', 'labels', 'train', 'evaluate', 'tune', 'stats', 'infer'],
                   help='Pipeline stage to run')
    return p.parse_args()


def main():
    args = parse_args()

    if args.stage == 'stats':
        stage_stats()
        return

    stages = {
        'graphs': [stage_graphs],
        'labels': [stage_labels],
        'train': [stage_train],
        'evaluate': [stage_evaluate],
        'tune': [stage_tune],
        'infer': [stage_graphs, stage_labels, stage_evaluate],
        'all': [stage_labels, stage_train, stage_evaluate],
    }

    for stage_fn in stages[args.stage]:
        if not stage_fn():
            print("\n[PIPELINE] Stage failed — stopping.")
            sys.exit(1)

    print("\n[PIPELINE] Complete.")


if __name__ == '__main__':
    main()
