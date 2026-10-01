#!/usr/bin/env python3
"""
Leave-one-template-out: copy training/validation label files without any graph
of the held-out scenario family -- full sessions AND their prefixes (including
the benign padding prefixes), so the model never sees that family at all.

A graph's family comes from its run's expectation_manifest.json
(scenario_id minus the instance number, e.g. banking_priv_abuse). Graphs of
runs without a manifest (live pgbench captures) are kept.

  python3 make_holdout_labels.py --family banking_priv_abuse --dataset-root dataset_dev \\
      --in dataset_dev/algo4_splits/train_labels.json training_v2/dev_train_prefixes/labels.json \\
      --out-dir training_v2/holdout_priv_abuse
"""
import argparse
import json
import re
from pathlib import Path


def family_index(dataset_root: Path):
    """(run, backend_pid) -> family, from every run's expectation manifest."""
    out = {}
    for manifest in dataset_root.glob("run_*/expectation_manifest.json"):
        run = manifest.parent.name
        for scenario_id, sc in json.loads(manifest.read_text())["scenarios"].items():
            fam = re.sub(r"_\d+$", "", scenario_id)
            for sess in sc["sessions"].values():
                out[(run, int(sess["backend_pid"]))] = fam
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--family", required=True, help="e.g. banking_priv_abuse")
    ap.add_argument("--dataset-root", type=Path, default=Path("dataset_dev"))
    ap.add_argument("--in", dest="inputs", nargs="+", required=True, type=Path,
                    help="label JSON files (graph file -> 0/1)")
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args()

    fams = family_index(args.dataset_root)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path in args.inputs:
        labels = json.loads(path.read_text())
        kept, dropped = {}, 0
        for fname, y in labels.items():
            m = re.match(r"enriched_(run_\d+)_(\d+)_", fname)
            if m and fams.get((m.group(1), int(m.group(2)))) == args.family:
                dropped += 1
                continue
            kept[fname] = y
        # name the copy after its source, e.g. dev_train_prefixes__labels.json
        out = args.out_dir / f"{path.parent.name}__{path.name}"
        out.write_text(json.dumps(kept, indent=1))
        n_mal = sum(kept.values())
        print(f"{path} -> {out}: kept {len(kept)} ({n_mal} malicious), dropped {dropped} of {args.family}")


if __name__ == "__main__":
    main()
