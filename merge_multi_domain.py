#!/usr/bin/env python3
"""Merge multiple CASCE generated corpus directories into one unified dataset.

Takes N generated corpus directories (e.g. from different domains) and
produces a single merged directory suitable for prepare_algo4_dataset.py
and algorithm_4_hybrid.py training.

Usage:
    python merge_multi_domain.py \
        --inputs datagen/generated/banking_large datagen/generated/healthcare_large \
                 datagen/generated/ecommerce_large datagen/generated/logistics_large \
        --output datagen/generated/merged_all

What it does:
  1. Copies all run_* directories (re-numbered sequentially)
  2. Merges enriched_graphs/graphml/ files
  3. Merges labels.csv files
  4. Writes a merge_manifest.json with provenance

Then you can run:
    python prepare_algo4_dataset.py datagen/generated/merged_all
    python algorithm_4_hybrid.py --mode train ...
"""

import argparse
import json
import shutil
import sys
from pathlib import Path


def merge_corpora(input_dirs: list, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    merged_graphml = output_dir / "enriched_graphs" / "graphml"
    merged_graphml.mkdir(parents=True, exist_ok=True)

    manifest = {"sources": [], "runs": []}
    run_counter = 0
    total_graphml = 0
    total_labels = 0

    for src_dir in input_dirs:
        src_dir = Path(src_dir).resolve()
        if not src_dir.exists():
            print(f"  ⚠ Skipping missing directory: {src_dir}")
            continue

        source_info = {"path": str(src_dir), "runs": []}

        # Find all run_* directories
        run_dirs = sorted(
            [d for d in src_dir.iterdir() if d.is_dir() and d.name.startswith("run_")],
            key=lambda x: int(x.name.split("_")[1])
        )

        for run_dir in run_dirs:
            run_counter += 1
            new_run_name = f"run_{run_counter:03d}"
            new_run_dir = output_dir / new_run_name
            old_run_name = run_dir.name

            # Copy the entire run directory
            if new_run_dir.exists():
                shutil.rmtree(new_run_dir)
            shutil.copytree(run_dir, new_run_dir)

            source_info["runs"].append({
                "original": old_run_name,
                "merged_as": new_run_name
            })

            # Copy GraphML files into the merged enriched_graphs dir
            graphml_src = run_dir / "graphs" / "graphml"
            if graphml_src.exists():
                for gf in graphml_src.glob("*.graphml"):
                    # Rename to include the new run number
                    new_name = gf.name.replace(old_run_name, new_run_name)
                    dest = merged_graphml / new_name
                    shutil.copy2(gf, dest)
                    total_graphml += 1

            # Also check for enriched graphml at the corpus level
            corpus_graphml = src_dir / "enriched_graphs" / "graphml"
            if corpus_graphml.exists():
                for gf in corpus_graphml.glob("*.graphml"):
                    if old_run_name in gf.name:
                        new_name = gf.name.replace(old_run_name, new_run_name)
                        dest = merged_graphml / new_name
                        if not dest.exists():
                            shutil.copy2(gf, dest)
                            total_graphml += 1

            # Count labels
            labels_csv = new_run_dir / "labels.csv"
            if labels_csv.exists():
                with open(labels_csv) as f:
                    total_labels += sum(1 for line in f) - 1  # minus header

            print(f"  ✓ {src_dir.name}/{old_run_name} → {new_run_name}")

        manifest["sources"].append(source_info)

    manifest["total_runs"] = run_counter
    manifest["total_graphml_files"] = total_graphml
    manifest["total_labeled_sessions"] = total_labels

    manifest_path = output_dir / "merge_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\n{'='*60}")
    print(f"  MERGE SUMMARY")
    print(f"{'='*60}")
    print(f"  Sources:     {len(input_dirs)}")
    print(f"  Total runs:  {run_counter}")
    print(f"  GraphML:     {total_graphml} files")
    print(f"  Labels:      {total_labels} sessions")
    print(f"  Output:      {output_dir}")
    print(f"  Manifest:    {manifest_path}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Merge multiple CASCE generated corpus directories into one")
    parser.add_argument("--inputs", nargs="+", required=True,
                        help="Input corpus directories to merge")
    parser.add_argument("--output", required=True,
                        help="Output merged directory")
    args = parser.parse_args()

    merge_corpora(args.inputs, Path(args.output))


if __name__ == "__main__":
    main()
