#!/usr/bin/env python3
"""Re-render all existing graph.png files in graph_catalog and paper_4case_suite
using the improved render_graph function — without re-running the full pipeline.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the parent directory is importable for generate_case_catalog.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_case_catalog import render_graph

ROOT = Path(__file__).resolve().parent

CATALOG = ROOT / "graph_catalog"
PAPER_SUITE = ROOT / "paper_4case_suite"


def rerender_dir(base_dir: Path) -> int:
    """Walk all subdirectories that contain a graphml/ folder, re-render graph.png."""
    count = 0
    for case_dir in sorted(base_dir.rglob("graphml")):
        parent = case_dir.parent
        graphml_files = sorted(case_dir.glob("*.graphml"))
        if not graphml_files:
            continue
        graphml = graphml_files[0]
        out_png = parent / "graph.png"

        # Derive a title from the parent directory name.
        title = parent.name.replace("_", " ").title()
        # Try to load a nicer title from summary.json if available.
        summary_path = parent / "summary.json"
        if summary_path.exists():
            import json
            try:
                data = json.loads(summary_path.read_text())
                title = data.get("scenario_id", data.get("case_id", title))
            except Exception:
                pass

        print(f"[rerender] {graphml.name} → {out_png}")
        render_graph(graphml, out_png, title=title)
        count += 1
    return count


def rerender_paper_suite(base_dir: Path) -> int:
    """Re-render paper_4case_suite graphs which store GraphML in algo3/ dirs."""
    count = 0
    for case_dir in sorted(base_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        algo3 = case_dir / "algo3"
        if not algo3.exists():
            continue
        graphml_files = sorted(algo3.glob("*.graphml"))
        if not graphml_files:
            continue
        graphml = graphml_files[0]
        out_png = case_dir / "graph.png"
        title = case_dir.name
        print(f"[rerender] {graphml.name} → {out_png}")
        render_graph(graphml, out_png, title=title)
        count += 1
    return count


def main():
    total = 0
    if CATALOG.exists():
        for sub in ["seen_attacks", "seen_benign", "unseen_attacks", "unseen_benign"]:
            d = CATALOG / sub
            if d.exists():
                total += rerender_dir(d)

    if PAPER_SUITE.exists():
        total += rerender_paper_suite(PAPER_SUITE)

    print(f"\n✓ Re-rendered {total} graphs.")


if __name__ == "__main__":
    main()
