#!/usr/bin/env python3
"""
Summarize the template-disjoint (leave-one-template-out) runs: per fold and
over all folds, mean ± std across seeds of the metrics on UNSEEN templates,
plus the pooled confusion matrix.

  python3 loto_summary.py --out loto/loto_summary.json
"""
import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

KEYS = ("recall", "fpr", "precision", "f1", "roc_auc", "pr_auc")


def mean_std(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return [round(statistics.mean(xs), 4), round(statistics.stdev(xs), 4) if len(xs) > 1 else 0.0]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dir", type=Path, default=Path("loto"))
    ap.add_argument("--out", type=Path, default=Path("loto/loto_summary.json"))
    args = ap.parse_args()

    runs = defaultdict(dict)   # fold -> seed -> report
    for p in sorted(args.dir.glob("*_s*.report.json")):
        fold, seed = re.match(r"(.+)_s(\d+)\.report\.json$", p.name).groups()
        runs[fold][int(seed)] = json.loads(p.read_text())

    folds, pooled = {}, defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for fold, by_seed in sorted(runs.items()):
        r0 = next(iter(by_seed.values()))
        folds[fold] = {
            "test_templates": r0["test_templates"], "val_templates": r0["val_templates"],
            "seeds": sorted(by_seed),
            "theta": {s: r["theta"] for s, r in sorted(by_seed.items())},
            "unseen": {k: mean_std([r["unseen"].get(k) for r in by_seed.values()]) for k in KEYS},
            "unseen_gat_only_roc_auc": mean_std([r["unseen_gat_only"].get("roc_auc") for r in by_seed.values()]),
            "seen_test_f1": mean_std([r["seen_test"]["f1"] for r in by_seed.values()]),
            "per_seed_cm": {s: {k: r["unseen"][k] for k in ("tp", "fp", "fn", "tn")}
                            for s, r in sorted(by_seed.items())},
        }
        for s, r in by_seed.items():
            for k in ("tp", "fp", "fn", "tn"):
                pooled[s][k] += r["unseen"][k]

    # macro average over folds (each fold = one unseen attack template), per seed then across seeds
    seeds = sorted({s for f in runs.values() for s in f})
    macro = {}
    for k in KEYS:
        per_seed = []
        for s in seeds:
            vals = [runs[f][s]["unseen"].get(k) for f in runs if s in runs[f]]
            vals = [v for v in vals if v is not None]
            if vals and all(s in runs[f] for f in runs):
                per_seed.append(statistics.mean(vals))
        macro[k] = mean_std(per_seed)

    out = {"n_folds": len(folds), "seeds": seeds, "macro_over_folds": macro,
           "pooled_confusion_per_seed": dict(pooled), "folds": folds}
    args.out.write_text(json.dumps(out, indent=2))

    print(f"{'fold (unseen attack)':20s} {'seeds':>5s} {'recall':>13s} {'FPR':>13s} {'F1':>13s} {'ROC-AUC':>13s} {'seen-test F1':>13s}")
    fmt = lambda v: f"{v[0]:.3f}±{v[1]:.3f}" if v else "-"
    for fold, f in folds.items():
        u = f["unseen"]
        print(f"{fold:20s} {len(f['seeds']):5d} {fmt(u['recall']):>13s} {fmt(u['fpr']):>13s} "
              f"{fmt(u['f1']):>13s} {fmt(u['roc_auc']):>13s} {fmt(f['seen_test_f1']):>13s}")
    print(f"{'MACRO (complete seeds)':20s} {len(seeds):5d} {fmt(macro['recall']):>13s} {fmt(macro['fpr']):>13s} "
          f"{fmt(macro['f1']):>13s} {fmt(macro['roc_auc']):>13s}")
    for s, cm in sorted(pooled.items()):
        print(f"pooled confusion seed {s}: TN={cm['tn']} FP={cm['fp']} FN={cm['fn']} TP={cm['tp']}")
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
