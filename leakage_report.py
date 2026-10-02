#!/usr/bin/env python3
"""
Train/test overlap diagnostics for the Algorithm 4 splits (documentation only;
nothing here feeds training or scoring).

Answers: which templates are in each split, how many test graphs have a
training graph with the same SQL sequence (exact / literals masked), which
node types and strings occur in only one class, and how much of a held-out
template's SQL is still covered by the templates kept in training.

  python3 leakage_report.py --holdout-family banking_priv_abuse \\
      --holdout-train-labels training_v2/holdout_priv_abuse/algo4_splits__train_labels.json \\
      --out eval_test_report_v2/leakage_report.json
"""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

import networkx as nx

from holdout_report import session_index


def norm_sql(q):
    """Mask quoted literals and numbers (passwords, ids, amounts, branch codes)."""
    return re.sub(r"\b\d+(\.\d+)?\b", "N", re.sub(r"'[^']*'", "'S'", q.strip().lower()))


def graph_info(path):
    G = nx.read_graphml(path)
    queries = sorted(
        (float(d.get("timestamp_unix") or d.get("timestamp") or 0), d["query"])
        for _, d in G.nodes(data=True) if d.get("type") == "Query" and d.get("query"))
    seq = [q for _, q in queries]
    return {
        "sql": hashlib.md5("\n".join(seq).encode()).hexdigest(),
        "sql_norm": hashlib.md5("\n".join(norm_sql(q) for q in seq).encode()).hexdigest(),
        "stmts_norm": {norm_sql(q) for q in seq},
        "node_types": {d.get("type") for _, d in G.nodes(data=True)},
        "files": {n for n, d in G.nodes(data=True) if d.get("type") == "File"},
        "roles": {d.get("role_name") for _, d in G.nodes(data=True) if d.get("type") == "Role"},
    }


def load_split(label_file, graph_dir, sessions):
    out = {}
    for fname, y in json.loads(Path(label_file).read_text()).items():
        m = re.match(r"enriched_(run_\d+)_(\d+)_", fname)
        tpl = sessions[(m.group(1), int(m.group(2)))][0]
        out[fname] = {"y": int(y), "template": tpl, **graph_info(Path(graph_dir) / fname)}
    return out


def match_counts(test, pool):
    res = {}
    for key in ("sql", "sql_norm"):
        index = collections.defaultdict(set)
        for g in pool.values():
            index[g[key]].add(g["y"])
        hits = [g for g in test.values() if g[key] in index]
        res[key] = {
            "test_graphs_matched": len(hits), "of": len(test),
            "malicious_matched": sum(g["y"] for g in hits), "of_malicious": sum(g["y"] for g in test.values()),
            "label_conflicts": sum(1 for g in hits if index[g[key]] != {g["y"]}),
            "per_template": dict(sorted(collections.Counter(g["template"] for g in hits).items())),
        }
    return res


def class_exclusive(graphs, field):
    by_class = {0: collections.Counter(), 1: collections.Counter()}
    for g in graphs.values():
        for v in g[field]:
            by_class[g["y"]][v] += 1
    return {
        "malicious_only": {k: v for k, v in by_class[1].items() if k not in by_class[0]},
        "benign_only": {k: v for k, v in by_class[0].items() if k not in by_class[1]},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dev-root", type=Path, default=Path("dataset_dev"))
    ap.add_argument("--test-root", type=Path, default=Path("dataset_test"))
    ap.add_argument("--holdout-family", default=None)
    ap.add_argument("--holdout-train-labels", default=None)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    dev_s, test_s = session_index(args.dev_root), session_index(args.test_root)
    dev_graphs = args.dev_root / "enriched_graphs/graphml"
    splits = {
        "train": load_split(args.dev_root / "algo4_splits/train_labels.json", dev_graphs, dev_s),
        "val": load_split(args.dev_root / "algo4_splits/val_labels.json", dev_graphs, dev_s),
        "test": load_split(args.test_root / "algo4_splits/test_labels.json",
                           args.test_root / "enriched_graphs/graphml", test_s),
    }
    templates = {name: dict(sorted(collections.Counter(g["template"] for g in s.values()).items()))
                 for name, s in splits.items()}
    out = {
        "templates_per_split": templates,
        "test_templates_not_in_train": sorted(set(templates["test"]) - set(templates["train"])),
        "test_vs_train_sql_matches": match_counts(splits["test"], splits["train"]),
        "test_vs_train_val_sql_matches": match_counts(splits["test"], {**splits["train"], **splits["val"]}),
        "class_exclusive_node_types_all_splits": class_exclusive(
            {**splits["train"], **splits["val"], **splits["test"]}, "node_types"),
        "class_exclusive_file_paths": class_exclusive({**splits["train"], **splits["test"]}, "files"),
        "class_exclusive_role_names": class_exclusive({**splits["train"], **splits["test"]}, "roles"),
    }

    if args.holdout_family and args.holdout_train_labels:
        ho_train = load_split(args.holdout_train_labels, dev_graphs, dev_s)
        assert not any(g["template"] == args.holdout_family for g in ho_train.values())
        held = {k: g for k, g in splits["test"].items() if g["template"] == args.holdout_family}
        kept_stmts = collections.defaultdict(set)
        for g in ho_train.values():
            for s in g["stmts_norm"]:
                kept_stmts[s].add(g["template"])
        held_stmts = set().union(*(g["stmts_norm"] for g in held.values()))
        out["holdout"] = {
            "family": args.holdout_family,
            "holdout_train_graphs_of_family": 0,
            "test_graphs_of_family": len(held),
            "test_vs_holdout_train_sql_matches": match_counts(held, ho_train),
            "family_statements_also_in_holdout_train": {
                s[:160]: sorted(kept_stmts.get(s, ())) for s in sorted(held_stmts)},
            "family_statements_unseen": sum(1 for s in held_stmts if s not in kept_stmts),
            "family_statements_total": len(held_stmts),
            "holdout_train_graphs_with_pattern": {
                pat: dict(sorted(collections.Counter(
                    g["template"] for g in ho_train.values()
                    if any(re.search(rx, s) for s in g["stmts_norm"])).items()))
                for pat, rx in {"CREATE ROLE": r"create role", "ALTER ROLE": r"alter role",
                                "SUPERUSER": r"superuser", "pg_authid": r"pg_authid"}.items()},
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(json.dumps({k: out[k] for k in ("templates_per_split", "test_templates_not_in_train",
                                         "test_vs_train_sql_matches")}, indent=1))
    if "holdout" in out:
        h = out["holdout"]
        print(f"holdout {h['family']}: {h['family_statements_unseen']}/{h['family_statements_total']} "
              f"normalized statements unseen in holdout train; patterns kept: {h['holdout_train_graphs_with_pattern']}")
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
