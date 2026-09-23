#!/usr/bin/env python3
"""Graph Builder Script for CASCE Telemetry Data.

Constructs 1:1 heterogeneous NetworkX session graphs from synthesized log events
(postgres_events.json & kernel_events.json) using Algorithm 1 & Algorithm 2, and
saves them as GraphML (.graphml) and JSON (.json) files under <run_dir>/graphs/.
"""

import sys
import json
from pathlib import Path
import networkx as nx

# Add repo root to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithm_1 import run_one, save_run_output
from algorithm2 import run as run_alg2


def build_graphs(run_dir: Path):
    run_dir = Path(run_dir).resolve()
    if not run_dir.exists():
        print(f"Error: Run directory '{run_dir}' does not exist.")
        sys.exit(1)

    print(f"=== Building Heterogeneous Graphs for {run_dir.name} ===")

    # Step 1: Run Algorithm 1 (Session-Anchored Correlation)
    master_log, correlated = run_one(run_dir)
    print(f"Algorithm 1 Complete: Correlated {len(correlated)} events across {len({sk for sk, _ in correlated})} sessions.")

    # Save temporary correlation tables
    tmp_dir = run_dir / ".tmp_alg1"
    save_run_output(run_dir.name, master_log, correlated, tmp_dir)

    event_table_path = tmp_dir / f"{run_dir.name}_event_table.json"
    correlation_path = tmp_dir / f"{run_dir.name}_session_correlation.csv"
    labels_path = run_dir / "labels.csv"

    # Step 2: Run Algorithm 2 (Heterogeneous Graph Materialization)
    out_graphs_dir = run_dir / "graphs"
    out_graphs_dir.mkdir(parents=True, exist_ok=True)

    active_graphs, manifest_rows, orphans, errors = run_alg2(
        event_table_path=event_table_path,
        correlation_path=correlation_path,
        out_dir=out_graphs_dir,
        run_id=run_dir.name,
        labels_path=labels_path if labels_path.exists() else None
    )

    # Step 3: Export GraphML (.graphml) files for PyTorch / NetworkX
    graphml_dir = out_graphs_dir / "graphml"
    graphml_dir.mkdir(parents=True, exist_ok=True)

    saved_graphml_count = 0
    for session_key, G in active_graphs.items():
        graphml_path = graphml_dir / f"{run_dir.name}_session_{session_key}.graphml"
        
        # Prepare graph for GraphML export (convert dict attrs to strings)
        G_export = G.copy()
        for n, d in G_export.nodes(data=True):
            for k, v in list(d.items()):
                if isinstance(v, (dict, list, tuple)):
                    d[k] = json.dumps(v)
                elif v is None:
                    d[k] = ""
        
        for u, v, k, d in G_export.edges(keys=True, data=True):
            for ek, ev in list(d.items()):
                if isinstance(ev, (dict, list, tuple)):
                    d[ek] = json.dumps(ev)
                elif ev is None:
                    d[ek] = ""

        nx.write_graphml(G_export, graphml_path)
        saved_graphml_count += 1

    print(f"\nSUCCESS: Materialized {len(active_graphs)} JSON graph files in '{out_graphs_dir}'")
    print(f"SUCCESS: Materialized {saved_graphml_count} GraphML files in '{graphml_dir}'")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python datagen/build_graphs.py <run_dir>")
        sys.exit(1)
    build_graphs(Path(sys.argv[1]))
