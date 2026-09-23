#!/usr/bin/env python3
"""
CASCE — Family-Aware Dataset Splitter for Algorithm 4
=======================================================

Creates leakage-safe Train / Validation / Test splits for the
Algorithm 4 HeteroGAT.

IMPORTANT:
------------
The split is performed by FAMILY, not by individual graph and not
by run number.

Therefore:

    Same family -> SAME split

A family can NEVER appear in both:
    Train and Validation
    Train and Test
    Validation and Test

The test dataset is treated as an external held-out dataset.

If a family appears in both dataset_dev and dataset_test, that family
is removed from the development data so that the final test set remains
family-independent.

Expected structure:

output/
├── dataset_dev/
│   ├── run_1/
│   │   ├── labels.csv
│   │   └── expectation_manifest.json
│   ├── run_2/
│   └── enriched_graphs/
│       └── graphml/
│
└── dataset_test/
    ├── run_1/
    │   ├── labels.csv
    │   └── expectation_manifest.json
    └── enriched_graphs/
        └── graphml/

Output:

dataset_dev/algo4_splits/
    train_labels.json
    val_labels.json

dataset_test/algo4_splits/
    test_labels.json

dataset_dev/algo4_splits/
    split_metadata.json
"""

import argparse
import csv
import json
import random
from pathlib import Path
from collections import defaultdict


# ============================================================
# Manifest loading
# ============================================================

def load_family_map(dataset_root: Path):
    """
    Build:

        (run_name, backend_pid) -> family_id

    from expectation_manifest.json files.
    """

    family_map = {}

    manifest_files = sorted(
        dataset_root.glob("run_*/expectation_manifest.json")
    )

    if not manifest_files:
        raise FileNotFoundError(
            f"No expectation_manifest.json files found under "
            f"'{dataset_root}/run_*/'"
        )

    for manifest_file in manifest_files:

        run_name = manifest_file.parent.name

        with open(manifest_file, "r") as f:
            manifest = json.load(f)

        scenarios = manifest.get("scenarios", {})

        for scenario_name, scenario_data in scenarios.items():

            family_id = scenario_data.get("family_id")

            if not family_id:
                raise ValueError(
                    f"Missing family_id in {manifest_file} "
                    f"for scenario '{scenario_name}'"
                )

            sessions = scenario_data.get("sessions", {})

            for session_name, session_data in sessions.items():

                backend_pid = session_data.get("backend_pid")

                if backend_pid is None:
                    raise ValueError(
                        f"Missing backend_pid in {manifest_file} "
                        f"for session '{session_name}'"
                    )

                key = (run_name, str(backend_pid))

                if key in family_map:
                    old_family = family_map[key]

                    if old_family != family_id:
                        raise ValueError(
                            f"Conflicting family IDs for {key}: "
                            f"{old_family} vs {family_id}"
                        )

                family_map[key] = family_id

    print(
        f"Loaded {len(family_map)} session -> family mappings "
        f"from {len(manifest_files)} manifests."
    )

    return family_map


# ============================================================
# Label loading
# ============================================================

def load_labels(dataset_root: Path):
    """
    Build:

        (run_name, backend_pid) -> 0/1
    """

    labels = {}

    label_files = sorted(
        dataset_root.glob("run_*/labels.csv")
    )

    if not label_files:
        raise FileNotFoundError(
            f"No labels.csv files found under '{dataset_root}/run_*/'"
        )

    for label_file in label_files:

        run_name = label_file.parent.name

        with open(label_file, "r", newline="") as f:

            reader = csv.DictReader(f)

            if not reader.fieldnames:
                raise ValueError(
                    f"Empty labels.csv: {label_file}"
                )

            for row in reader:

                sid = row.get("session_id")

                if sid is None or sid == "":
                    continue

                raw_label = str(row.get("label", "")).strip().lower()

                if raw_label in ("attack", "malicious"):
                    label = 1
                else:
                    label = 0

                labels[(run_name, str(sid))] = label

    print(
        f"Loaded {len(labels)} session labels "
        f"from {len(label_files)} labels.csv files."
    )

    return labels


# ============================================================
# Graph matching
# ============================================================

def find_graphs_for_session(graphml_dir: Path, run_name: str, pid: str):
    """
    Match GraphML files generated by main.py.

    Current main.py naming pattern:

        enriched_<run_name>_<session_key>_<label>.graphml

    Example:

        enriched_dataset_dev_run_1_20000_Benign.graphml
    """

    prefix = f"enriched_{run_name}_{pid}_"

    matches = sorted(
        p for p in graphml_dir.glob(f"{prefix}*.graphml")
        if p.is_file()
    )

    return matches


# ============================================================
# Collect dataset
# ============================================================

def collect_dataset(dataset_root: Path):
    """
    Return:

        families[family_id] = [
            {
                "filename": ...,
                "label": 0/1,
                "run": ...,
                "pid": ...
            }
        ]
    """

    graphml_dir = dataset_root / "enriched_graphs" / "graphml"

    if not graphml_dir.exists():
        raise FileNotFoundError(
            f"GraphML directory not found:\n{graphml_dir}"
        )

    family_map = load_family_map(dataset_root)
    labels = load_labels(dataset_root)

    families = defaultdict(list)

    matched_graphs = 0
    missing_family = 0
    missing_label = 0
    duplicate_graphs = 0

    # Iterate over all known sessions from labels.csv
    for (run_name, pid), label in labels.items():

        family_id = family_map.get((run_name, pid))

        if family_id is None:
            missing_family += 1

            print(
                f"[WARNING] No family_id for "
                f"{run_name}, PID={pid}"
            )

            continue

        graph_files = find_graphs_for_session(
            graphml_dir,
            run_name,
            pid
        )

        if not graph_files:
            print(
                f"[WARNING] No GraphML found for "
                f"{run_name}, PID={pid}"
            )
            continue

        if len(graph_files) > 1:
            duplicate_graphs += len(graph_files) - 1

        for graph_file in graph_files:

            families[family_id].append(
                {
                    "filename": graph_file.name,
                    "label": label,
                    "run": run_name,
                    "pid": pid
                }
            )

            matched_graphs += 1

    print()
    print("=" * 70)
    print(f"Dataset: {dataset_root}")
    print("=" * 70)
    print(f"Families discovered : {len(families)}")
    print(f"Graphs matched      : {matched_graphs}")
    print(f"Missing family IDs  : {missing_family}")
    print(f"Extra graph matches : {duplicate_graphs}")

    if missing_family > 0:
        raise RuntimeError(
            "Some sessions do not have a family_id. "
            "Family-aware splitting cannot safely continue."
        )

    if matched_graphs == 0:
        raise RuntimeError(
            f"No GraphML files were matched in {dataset_root}"
        )

    return families


# ============================================================
# Split statistics
# ============================================================

def split_stats(name, graph_dict):

    total = len(graph_dict)

    malicious = sum(
        1 for label in graph_dict.values()
        if label == 1
    )

    benign = total - malicious

    print(
        f"{name:<12}: "
        f"{total:>6} graphs | "
        f"Malicious={malicious:>6} | "
        f"Benign={benign:>6}"
    )

    if total > 0:
        print(
            f"{'':12}  "
            f"Malicious ratio = {malicious / total:.3f}"
        )


# ============================================================
# Main split
# ============================================================

def prepare_splits(
    dev_root: Path,
    test_root: Path,
    train_ratio=0.80,
    seed=42
):

    print("\n" + "=" * 70)
    print("CASCE FAMILY-AWARE SPLITTING")
    print("=" * 70)

    # --------------------------------------------------------
    # Load development dataset
    # --------------------------------------------------------

    dev_families = collect_dataset(dev_root)

    # --------------------------------------------------------
    # Load test dataset
    # --------------------------------------------------------

    test_families = collect_dataset(test_root)

    dev_family_ids = set(dev_families.keys())
    test_family_ids = set(test_families.keys())

    overlapping_test_families = (
        dev_family_ids & test_family_ids
    )

    print("\n" + "=" * 70)
    print("FAMILY LEAKAGE CHECK")
    print("=" * 70)

    print(f"Development families : {len(dev_family_ids)}")
    print(f"Test families        : {len(test_family_ids)}")
    print(
        f"Overlapping families : "
        f"{len(overlapping_test_families)}"
    )

    # --------------------------------------------------------
    # Protect test set
    # --------------------------------------------------------

    if overlapping_test_families:

        print(
            "\n[WARNING] The following families exist in BOTH "
            "development and test:"
        )

        for fid in sorted(overlapping_test_families):
            print(f"    {fid}")

        print(
            "\nThese families will be REMOVED from development "
            "training/validation data."
        )

        for fid in overlapping_test_families:
            del dev_families[fid]

    else:

        print(
            "[OK] No family overlap between development and test."
        )

    # --------------------------------------------------------
    # Split remaining DEV families
    # --------------------------------------------------------

    remaining_family_ids = sorted(dev_families.keys())

    if len(remaining_family_ids) < 2:
        raise RuntimeError(
            "Not enough independent families remaining "
            "for train/validation splitting."
        )

    rng = random.Random(seed)

    rng.shuffle(remaining_family_ids)

    n_train = int(
        len(remaining_family_ids) * train_ratio
    )

    # Ensure both train and validation receive at least one family
    n_train = max(
        1,
        min(
            n_train,
            len(remaining_family_ids) - 1
        )
    )

    train_families = set(
        remaining_family_ids[:n_train]
    )

    val_families = set(
        remaining_family_ids[n_train:]
    )

    # --------------------------------------------------------
    # Build graph-level label dictionaries
    # --------------------------------------------------------

    train_labels = {}
    val_labels = {}
    test_labels = {}

    for family_id in train_families:

        for item in dev_families[family_id]:

            train_labels[item["filename"]] = item["label"]

    for family_id in val_families:

        for item in dev_families[family_id]:

            val_labels[item["filename"]] = item["label"]

    for family_id in test_family_ids:

        for item in test_families[family_id]:

            test_labels[item["filename"]] = item["label"]

    # --------------------------------------------------------
    # FINAL OVERLAP VERIFICATION
    # --------------------------------------------------------

    assert train_families.isdisjoint(
        val_families
    ), "TRAIN/VAL FAMILY LEAKAGE!"

    assert train_families.isdisjoint(
        test_family_ids
    ), "TRAIN/TEST FAMILY LEAKAGE!"

    assert val_families.isdisjoint(
        test_family_ids
    ), "VAL/TEST FAMILY LEAKAGE!"

    # --------------------------------------------------------
    # Output directories
    # --------------------------------------------------------

    dev_split_dir = (
        dev_root / "algo4_splits"
    )

    test_split_dir = (
        test_root / "algo4_splits"
    )

    dev_split_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    test_split_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save labels
    # --------------------------------------------------------

    (dev_split_dir / "train_labels.json").write_text(
        json.dumps(
            train_labels,
            indent=2,
            sort_keys=True
        )
    )

    (dev_split_dir / "val_labels.json").write_text(
        json.dumps(
            val_labels,
            indent=2,
            sort_keys=True
        )
    )

    (test_split_dir / "test_labels.json").write_text(
        json.dumps(
            test_labels,
            indent=2,
            sort_keys=True
        )
    )

    # --------------------------------------------------------
    # Save metadata
    # --------------------------------------------------------

    metadata = {

        "seed": seed,

        "train_ratio": train_ratio,

        "split_method":
            "family_aware",

        "development_families_original":
            sorted(
                dev_family_ids |
                overlapping_test_families
            ),

        "excluded_from_dev_due_to_test_overlap":
            sorted(
                overlapping_test_families
            ),

        "train_families":
            sorted(train_families),

        "validation_families":
            sorted(val_families),

        "test_families":
            sorted(test_family_ids),

        "family_overlap_after_split": {

            "train_val":
                sorted(
                    train_families &
                    val_families
                ),

            "train_test":
                sorted(
                    train_families &
                    test_family_ids
                ),

            "val_test":
                sorted(
                    val_families &
                    test_family_ids
                )
        }
    }

    (dev_split_dir / "split_metadata.json").write_text(
        json.dumps(
            metadata,
            indent=2
        )
    )

    # --------------------------------------------------------
    # Print results
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL FAMILY-AWARE SPLIT")
    print("=" * 70)

    print(
        f"Train families      : "
        f"{len(train_families)}"
    )

    print(
        f"Validation families : "
        f"{len(val_families)}"
    )

    print(
        f"Test families        : "
        f"{len(test_family_ids)}"
    )

    print()

    split_stats(
        "Train",
        train_labels
    )

    split_stats(
        "Validation",
        val_labels
    )

    split_stats(
        "Test",
        test_labels
    )

    # --------------------------------------------------------
    # Final leakage assertion
    # --------------------------------------------------------

    if (
        train_families &
        val_families
    ):
        raise RuntimeError(
            "FATAL: Train/Validation family overlap!"
        )

    if (
        train_families &
        test_family_ids
    ):
        raise RuntimeError(
            "FATAL: Train/Test family overlap!"
        )

    if (
        val_families &
        test_family_ids
    ):
        raise RuntimeError(
            "FATAL: Validation/Test family overlap!"
        )

    print("\n" + "=" * 70)
    print("✓ FAMILY-AWARE SPLIT SUCCESSFUL")
    print("✓ NO FAMILY OVERLAP BETWEEN TRAIN / VAL / TEST")
    print("=" * 70)

    print(
        f"\nTrain labels : "
        f"{dev_split_dir / 'train_labels.json'}"
    )

    print(
        f"Val labels   : "
        f"{dev_split_dir / 'val_labels.json'}"
    )

    print(
        f"Test labels  : "
        f"{test_split_dir / 'test_labels.json'}"
    )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Create family-aware CASCE "
            "Algorithm 4 train/val/test splits."
        )
    )

    parser.add_argument(
        "--dev-root",
        default="output/dataset_dev",
        help="Development dataset root"
    )

    parser.add_argument(
        "--test-root",
        default="output/dataset_test",
        help="Held-out test dataset root"
    )

    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.80,
        help="Fraction of non-test development families for training"
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed"
    )

    args = parser.parse_args()

    if not 0.5 <= args.train_ratio < 1.0:
        raise SystemExit(
            "--train-ratio must be >= 0.5 and < 1.0"
        )

    prepare_splits(
        Path(args.dev_root),
        Path(args.test_root),
        train_ratio=args.train_ratio,
        seed=args.seed
    )


if __name__ == "__main__":
    main()