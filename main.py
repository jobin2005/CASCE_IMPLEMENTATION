
"""
main.py
=======

Master execution pipeline for CASCE.
Creates exactly the enriched .graphml graphs from dataset_dev and
dataset_test runs required to train/test the Algorithm 4 PyG GAT model!

Usage:
    python3 main.py                  # run every dataset_dev/dataset_test run_*
    python3 main.py path/to/run_dir  # run a single run directory
"""

from __future__ import annotations

import sys
import json
import tempfile
from pathlib import Path

import networkx as nx

import algorithm_1
import algorithm2
import algorithm_3_abstract


PROJECT_ROOT = Path(__file__).resolve().parent

DATASET_DEV = PROJECT_ROOT / "dataset_dev"
DATASET_TEST = PROJECT_ROOT / "dataset_test"
OUTPUT_DIR = PROJECT_ROOT / "output"


def sanitize_for_graphml(G: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """
    NetworkX GraphML exporter throws errors if node or edge attributes
    contain complex native Python lists, dicts, or booleans.
    Convert them to GraphML-safe strings.
    """

    for n, data in G.nodes(data=True):
        temp_data = list(data.items())

        for k, v in temp_data:
            if isinstance(v, (list, dict, bool)):
                G.nodes[n][k] = str(v)
            elif v is None:
                G.nodes[n][k] = ""

    for u, v, k, data in G.edges(data=True, keys=True):
        temp_data = list(data.items())

        for attr_k, attr_v in temp_data:
            if isinstance(attr_v, (list, dict, bool)):
                G[u][v][k][attr_k] = str(attr_v)
            elif attr_v is None:
                G[u][v][k][attr_k] = ""

    return G


def main() -> None:

    # -------------------------------------------------------------
    # Select runs
    # -------------------------------------------------------------
    if len(sys.argv) > 1:
        run_dirs = [Path(sys.argv[1]).resolve()]
    else:
        run_dirs = (
            sorted(DATASET_DEV.glob("run_*"))
            + sorted(DATASET_TEST.glob("run_*"))
        )

    if not run_dirs:
        print(
            f"No run_* directories found under "
            f"{DATASET_DEV} or {DATASET_TEST}"
        )
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    templates = algorithm_3_abstract.initialize_templates()

    # -------------------------------------------------------------
    # Process every run
    # -------------------------------------------------------------
    for run_dir in run_dirs:

        # Full run name expected by Algorithm 4 preparation
        #
        # Example:
        # dataset_dev_run_001
        # dataset_test_run_001
        if run_dir.parent.name in ("dataset_dev", "dataset_test"):
            run_name = f"{run_dir.parent.name}_{run_dir.name}"
        else:
            run_name = run_dir.name

        print(
            f"\n{'=' * 50}\n"
            f"Starting End-to-End Pipeline for: {run_name}\n"
            f"{'=' * 50}"
        )

        # Secure diagnostic temporary allocation
        with tempfile.TemporaryDirectory() as tmpdirname:

            tmp_root = Path(tmpdirname)

            # =====================================================
            # STAGE 1: Algorithm 1
            # =====================================================
            print("[1/3] Running Algorithm 1 (SAC)")

            master_log, correlated = algorithm_1.run_one(run_dir)

            algorithm_1.save_run_output(
                run_name,
                master_log,
                correlated,
                tmp_root
            )

            event_table_path = (
                tmp_root / f"{run_name}_event_table.json"
            )

            correlation_path = (
                tmp_root / f"{run_name}_session_correlation.csv"
            )

            # =====================================================
            # STAGE 2: Algorithm 2
            # =====================================================
            print("[2/3] Running Algorithm 2 (Graph Construction)")

            alg2_out_dir = (
                tmp_root / f"{run_name}_alg2_graphs"
            )

            labels_path = (
                run_dir / "labels.csv"
                if (run_dir / "labels.csv").exists()
                else None
            )

            (
                active_graphs,
                manifest_rows,
                orphans,
                parse_errs
            ) = algorithm2.run(
                event_table_path,
                correlation_path,
                alg2_out_dir,
                run_name,
                labels_path
            )

            print(
                f"     => Generated "
                f"{len(active_graphs)} base session graphs "
                f"natively in RAM"
            )

            # =====================================================
            # STAGE 3: Algorithm 3
            # =====================================================
            print(
                "[3/3] Running Algorithm 3 "
                "(Behavior Abstraction & Serialization)"
            )

            # -----------------------------------------------------
            # IMPORTANT:
            # Keep the GraphML location expected by the existing
            # Algorithm 4 preparation code.
            #
            # dataset_dev/enriched_graphs/graphml/
            # dataset_test/enriched_graphs/graphml/
            # -----------------------------------------------------
            alg3_out_dir = (
                run_dir.parent
                / "enriched_graphs"
                / "graphml"
            )

            alg3_out_dir.mkdir(
                parents=True,
                exist_ok=True
            )

            for session_key, G_s in active_graphs.items():

                # Algorithm 3 returns:
                #   enriched graph
                #   detected behaviors
                G_enriched, detected_behaviors = (
                    algorithm_3_abstract.abstract_session_graph(
                        G_s,
                        templates
                    )
                )

                G_enriched = sanitize_for_graphml(
                    G_enriched
                )

                # -------------------------------------------------
                # Get label from Algorithm 2 manifest
                # -------------------------------------------------
                label = "unknown"

                for row in manifest_rows:
                    if row["session_key"] == session_key:
                        label = row["label"]
                        break

                # -------------------------------------------------
                # IMPORTANT:
                # Do NOT overwrite run_name here.
                #
                # run_name must remain:
                #   dataset_dev_run_001
                #   dataset_test_run_001
                #
                # This matches prepare_algo4_dataset.py:
                #
                # enriched_<run_name>_<pid>_<label>.graphml
                # -------------------------------------------------
                out_file = alg3_out_dir / (
    f"enriched_{run_dir.name}_{session_key}_"
    f"{label.replace(' ', '_')}.graphml"
)

                nx.write_graphml(
                    G_enriched,
                    out_file
                )

                print(
                    f"     [+] Wrote {out_file.name} "
                    f"(Nodes: "
                    f"{G_enriched.number_of_nodes()}, "
                    f"Edges: "
                    f"{G_enriched.number_of_edges()})"
                )


if __name__ == "__main__":
    main()
