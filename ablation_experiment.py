#!/usr/bin/env python3
"""
CASCE Ablation Experiment: OS-only vs DB-only vs Cross-layer
==============================================================
Compares the three detection settings on the SAME sessions, using the
project's existing pipeline and trained GAT detector:

    OS-only      : eBPF/kernel graph      -> Detector
    DB-only      : PostgreSQL graph       -> Detector
    Full CASCE   : eBPF + PostgreSQL graph -> Detector   (cross-layer)

It does NOT re-train separate models. It takes the already-enriched
cross-layer graphs (built by main.py / Algorithms 1-3) and derives the
OS-only / DB-only variants by dropping the other layer's node types.
The same trained GAT (casce_gat.pt) then scores all three, and we read
Precision / Recall / F1 / FPR / AUPRC straight out of the existing
evaluate_model() in algorithm_4_hybrid.py.

Usage:
    python3 ablation_experiment.py                 # uses dataset_test
    python3 ablation_experiment.py --split dev     # uses dataset_dev
"""

import os
import sys
import json
import argparse
import subprocess
import networkx as nx

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
ABLATION_DIR = os.path.join(BASE_DIR, "ablation_output")
MODEL_PATH = os.path.join(BASE_DIR, "casce_gat.pt")

# Node types belonging to each layer (see schema.py / graphsops.py).
# "Session" is the correlation anchor and "Behavior" is the abstracted
# cross-layer summary node added by Algorithm 3 -- both are kept only
# in the full cross-layer setting.
OS_TYPES = {"Session", "Process", "File", "Endpoint"}
DB_TYPES = {"Session", "Role", "Query", "Table"}
# Full/cross-layer setting = the enriched graph as-is (no filtering).

SETTINGS = ["OS-only", "DB-only", "Cross-layer"]


def discover_runs(base_path):
    if not os.path.isdir(base_path):
        return []
    runs = [d for d in os.listdir(base_path)
            if d.startswith("run_") and os.path.isdir(os.path.join(base_path, d))]
    runs.sort(key=lambda x: int(x.split("_")[1]))
    return runs


def ensure_graphs_and_labels(split_name):
    """Make sure enriched cross-layer graphs + labels.json exist for this split."""
    split_out = os.path.join(OUTPUT_DIR, split_name)
    if not os.path.isdir(split_out) or not discover_runs(split_out):
        print(f"[setup] No graphs found for {split_name} -- running main.py to build them...")
        subprocess.run([sys.executable, "main.py"], cwd=BASE_DIR, check=True)

    for run in discover_runs(split_out):
        run_dir = os.path.join(split_out, run)
        labels_path = os.path.join(run_dir, "labels.json")
        graphmls = [f for f in os.listdir(run_dir) if f.endswith(".graphml")]
        if not graphmls:
            continue
        if not os.path.exists(labels_path):
            labels = {f: (0 if "_Normal" in f else 1) for f in graphmls}
            with open(labels_path, "w") as fh:
                json.dump(labels, fh, indent=2)


def filter_graph(G, keep_types):
    """Return the subgraph containing only nodes whose 'type' is in keep_types."""
    keep_nodes = [n for n, d in G.nodes(data=True) if d.get("type") in keep_types]
    return G.subgraph(keep_nodes).copy()


def build_ablation_variant(split_name, setting):
    """Create filtered graphml copies (+ labels.json) for one setting; return dir list."""
    split_out = os.path.join(OUTPUT_DIR, split_name)
    dest_root = os.path.join(ABLATION_DIR, setting.replace("-", "_"), split_name)
    dirs = []

    for run in discover_runs(split_out):
        src_dir = os.path.join(split_out, run)
        dst_dir = os.path.join(dest_root, run)
        os.makedirs(dst_dir, exist_ok=True)

        labels_src = os.path.join(src_dir, "labels.json")
        if not os.path.exists(labels_src):
            continue

        for fname in os.listdir(src_dir):
            if not fname.endswith(".graphml"):
                continue
            G = nx.read_graphml(os.path.join(src_dir, fname))
            if setting == "OS-only":
                G = filter_graph(G, OS_TYPES)
            elif setting == "DB-only":
                G = filter_graph(G, DB_TYPES)
            # "Cross-layer" -> keep the graph unmodified (full CASCE graph)
            nx.write_graphml(G, os.path.join(dst_dir, fname))

        # labels apply unchanged -- same sessions, same ground truth
        with open(labels_src) as fh:
            labels = json.load(fh)
        with open(os.path.join(dst_dir, "labels.json"), "w") as fh:
            json.dump(labels, fh, indent=2)

        dirs.append(dst_dir)

    return dirs


def run_evaluation(dirs, outdir):
    """Call the project's existing evaluator (algorithm_4_hybrid.py --mode evaluate)."""
    input_dir = ",".join(dirs)
    labels = ",".join(os.path.join(d, "labels.json") for d in dirs)
    os.makedirs(outdir, exist_ok=True)

    subprocess.run(
        [sys.executable, "algorithm_4_hybrid.py", "--mode", "evaluate",
         "--input-dir", input_dir,
         "--labels", labels,
         "--model-path", MODEL_PATH,
         "--outdir", outdir],
        cwd=BASE_DIR, check=True,
    )

    with open(os.path.join(outdir, "evaluation_results.json")) as fh:
        return json.load(fh)


def print_comparison(results):
    cols = ["Precision", "Recall", "F1", "FPR", "AUPRC"]
    keymap = {
        "Precision": "precision", "Recall": "recall", "F1": "f1_score",
        "FPR": "false_positive_rate", "AUPRC": "pr_auc",
    }
    header = f"{'Setting':<14}" + "".join(f"{c:>10}" for c in cols)
    print("\n" + header)
    print("-" * len(header))
    for setting in SETTINGS:
        r = results[setting]
        row = f"{setting:<14}" + "".join(f"{r[keymap[c]]:>10.3f}" for c in cols)
        print(row)


def main():
    parser = argparse.ArgumentParser(description="OS-only vs DB-only vs Cross-layer ablation")
    parser.add_argument("--split", choices=["dev", "test"], default="test", help="Which dataset split to evaluate on (default: test)")
    args = parser.parse_args()
    split_name = f"dataset_{args.split}"

    ensure_graphs_and_labels(split_name)

    results = {}
    for setting in SETTINGS:
        print(f"\n[{setting}] Building filtered graphs...")
        dirs = build_ablation_variant(split_name, setting)
        if not dirs:
            print(f"[{setting}] No data found -- skipping.")
            continue

        print(f"[{setting}] Running detector...")
        outdir = os.path.join(ABLATION_DIR, setting.replace("-", "_"), "eval")
        results[setting] = run_evaluation(dirs, outdir)

    print_comparison(results)

    with open(os.path.join(ABLATION_DIR, "comparison_summary.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nFull results saved to {os.path.join(ABLATION_DIR, 'comparison_summary.json')}")


if __name__ == "__main__":
    main()