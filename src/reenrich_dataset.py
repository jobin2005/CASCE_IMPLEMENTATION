#!/usr/bin/env python3
"""
reenrich_dataset.py
===================

Re-enriches all existing .graphml files in output/dataset_dev and output/dataset_test
using Algorithm 3 with synchronized timestamps and multi-edge relation support.

This strips out any outdated Behavior nodes / precedes edges and generates
fresh, calibrated Behavior abstractions with valid chronological chains directly
from the base provenance graphs.

Usage:
    python3 reenrich_dataset.py
    python3 reenrich_dataset.py --dir output/dataset_dev
"""

import os
import sys
import argparse
from pathlib import Path
import networkx as nx

import algorithm_3_abstract
from main import sanitize_for_graphml

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"


def reenrich_file(filepath: Path, templates: list) -> tuple[int, int]:
    """Re-enriches a single graphml file. Returns (num_behaviors, num_precedes)."""
    try:
        raw_g = nx.read_graphml(filepath)
        g = nx.MultiDiGraph(raw_g)
    except Exception as e:
        print(f"  [ERROR] Failed to read {filepath}: {e}")
        return 0, 0

    # 1. Isolate the base provenance graph (remove any previous Behavior abstractions)
    base_nodes = [n for n, d in g.nodes(data=True) if d.get("type") != "Behavior"]
    g_base = g.subgraph(base_nodes).copy()

    # 2. Re-abstract with synchronized timestamps and fixed relation rules
    g_enriched = algorithm_3_abstract.abstract_session_graph(g_base, templates)
    g_enriched = sanitize_for_graphml(g_enriched)

    # 3. Write back enriched graph
    nx.write_graphml(g_enriched, filepath)

    beh_count = sum(1 for _, d in g_enriched.nodes(data=True) if d.get("type") == "Behavior")
    precedes_count = sum(1 for _, _, d in g_enriched.edges(data=True) if d.get("relation") == "precedes")
    return beh_count, precedes_count


def reenrich_directory(target_dir: Path, templates: list):
    if not target_dir.exists():
        print(f"Directory not found: {target_dir}")
        return

    graph_files = sorted(target_dir.glob("**/*.graphml"))
    if not graph_files:
        print(f"No .graphml files found in {target_dir}")
        return

    print(f"\nRe-enriching {len(graph_files)} graphs in {target_dir.name}...")
    total_beh = 0
    total_precedes = 0

    for idx, f in enumerate(graph_files, 1):
        beh, prec = reenrich_file(f, templates)
        total_beh += beh
        total_precedes += prec
        if idx % 500 == 0 or idx == len(graph_files):
            print(f"  [{idx}/{len(graph_files)}] Processed... (Behaviors so far: {total_beh}, Precedes edges: {total_precedes})")

    print(f"Completed {target_dir.name}: Total Behaviors = {total_beh}, Total Precedes = {total_precedes}")


def main():
    parser = argparse.ArgumentParser(description="Re-enrich output datasets with Algorithm 3")
    parser.add_argument("--dir", default=None, help="Target directory (defaults to both output/dataset_dev and output/dataset_test)")
    args = parser.parse_args()

    templates = algorithm_3_abstract.initialize_templates()
    print(f"Initialized {len(templates)} MITRE ATT&CK templates.")

    if args.dir:
        reenrich_directory(Path(args.dir).resolve(), templates)
    else:
        dev_dir = DEFAULT_OUTPUT_DIR / "dataset_dev"
        test_dir = DEFAULT_OUTPUT_DIR / "dataset_test"
        if dev_dir.exists():
            reenrich_directory(dev_dir, templates)
        if test_dir.exists():
            reenrich_directory(test_dir, templates)

    print("\nDataset re-enrichment complete.")


if __name__ == "__main__":
    main()
