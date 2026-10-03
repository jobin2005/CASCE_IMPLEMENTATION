#!/usr/bin/env python3
"""
Template-disjoint folds (leave-one-template-out): every fold tests on scenario
TEMPLATES that never appear in its training or validation data, instead of new
seeds of templates the model was trained on.

Fold i over the sorted malicious templates M and benign templates B:
  test        M[i]       + B[i % |B|]
  validation  M[i+1]     + B[(i+1) % |B|]       (θ_A and early stopping)
  training    every other template
Training/validation use dataset_dev full-session graphs + their prefix graphs
(build_training_graphs.py --no-full over all dev runs) + the live pgbench sets,
exactly as for casce_gat_v2. The test set is every full-session graph of the
two test templates from dataset_dev AND dataset_test (the template is unseen,
so both are unseen data; dataset_test alone has as few as 3 sessions per template).

  python3 make_template_folds.py --out-dir training_v2/loto --definitions loto/folds.json
"""
import argparse
import json
import re
from pathlib import Path

from holdout_report import session_index

GRAPH_RE = re.compile(r"enriched_(run_\d+)_(\d+)_(?:p\d+_)?(Benign|Malicious)\.graphml$")


def graphs(graph_dir: Path, sessions):
    """graph file -> (template, label) for every graph in graph_dir whose session is in a manifest."""
    out = {}
    for p in sorted(graph_dir.glob("*.graphml")):
        m = GRAPH_RE.match(p.name)
        if m:
            out[p.name] = (sessions[(m.group(1), int(m.group(2)))][0], int(m.group(3) == "Malicious"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dev-root", type=Path, default=Path("dataset_dev"))
    ap.add_argument("--test-root", type=Path, default=Path("dataset_test"))
    ap.add_argument("--prefix-dir", type=Path, default=Path("training_v2/dev_all_prefixes/graphml"))
    ap.add_argument("--out-dir", type=Path, default=Path("training_v2/loto"))
    ap.add_argument("--definitions", type=Path, default=Path("loto/folds.json"))
    args = ap.parse_args()

    dev_s, test_s = session_index(args.dev_root), session_index(args.test_root)
    dev_full = graphs(args.dev_root / "enriched_graphs/graphml", dev_s)
    test_full = graphs(args.test_root / "enriched_graphs/graphml", test_s)
    prefixes = graphs(args.prefix_dir, dev_s)

    # a template's class is the label of its full sessions (all sessions of a template share it)
    tpl_class = {}
    for tpl, y in list(dev_full.values()) + list(test_full.values()):
        assert tpl_class.setdefault(tpl, y) == y, f"template {tpl} has sessions of both classes"
    mal = sorted(t for t, y in tpl_class.items() if y == 1)
    ben = sorted(t for t, y in tpl_class.items() if y == 0)

    definitions = []
    for i, test_mal in enumerate(mal):
        f = {"fold": test_mal.replace("banking_", ""),
             "test": [test_mal, ben[i % len(ben)]],
             "val": [mal[(i + 1) % len(mal)], ben[(i + 1) % len(ben)]]}
        f["train"] = sorted(t for t in tpl_class if t not in f["test"] + f["val"])

        def pick(src, tpls):
            return {g: y for g, (t, y) in src.items() if t in tpls}

        files = {
            "train_full": pick(dev_full, f["train"]), "train_prefixes": pick(prefixes, f["train"]),
            "val_full": pick(dev_full, f["val"]), "val_prefixes": pick(prefixes, f["val"]),
            "test_dev": pick(dev_full, f["test"]), "test_test": pick(test_full, f["test"]),
        }
        fold_dir = args.out_dir / f["fold"]
        fold_dir.mkdir(parents=True, exist_ok=True)
        for name, labels in files.items():
            (fold_dir / f"{name}.json").write_text(json.dumps(labels, indent=1))
        f["counts"] = {name: [len(v), sum(v.values())] for name, v in files.items()}  # [graphs, malicious]
        (fold_dir / "fold.json").write_text(json.dumps(f, indent=2))
        definitions.append(f)
        print(f"{f['fold']:18s} test={f['test']} val={f['val']} "
              + " ".join(f"{k}={n}/{m}" for k, (n, m) in f["counts"].items()))

    args.definitions.parent.mkdir(parents=True, exist_ok=True)
    args.definitions.write_text(json.dumps({"malicious_templates": mal, "benign_templates": ben,
                                            "folds": definitions}, indent=2))
    print(f"Saved {args.definitions}")


if __name__ == "__main__":
    main()
