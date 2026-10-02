#!/usr/bin/env python3
"""
Collect holdout_report.py outputs across seeds into one table (mean +- std).

The original seed-42 models are read from the H1 report (both models in one
file); retrained seeds from models_seeds/<config>_s<seed>.report.json.

  python3 seed_summary.py --out models_seeds/seed_summary.json
"""
import argparse
import json
import re
import statistics
from pathlib import Path

ORIGINAL = Path("eval_test_report_holdout_priv_abuse/holdout_report.json")
ORIGINAL_NAMES = {"holdout": "holdout_priv_abuse", "v2": "v2"}
TEMPLATES = {"priv_abuse": "banking_priv_abuse:escalate_and_dump",
             "etl_exfil_mal": "banking_etl_exfil_mal:replication"}


def row(res, theta):
    out = {"theta": theta}
    for part in ("all_test", "heldout_vs_benign", "seen_templates"):
        for k in ("precision", "recall", "f1", "fpr", "roc_auc"):
            out[f"{part}.{k}"] = res[part].get(k)
    for short, key in TEMPLATES.items():
        t = res["per_template"][key]
        out[f"{short}.detected"] = t["detected"]
        out[f"{short}.n"] = t["n"]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--seeds-dir", type=Path, default=Path("models_seeds"))
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    runs = {}  # config -> {seed label -> row}
    orig = json.loads(ORIGINAL.read_text())
    for name, res in orig["models"].items():
        runs.setdefault(ORIGINAL_NAMES[name], {})["42 (original)"] = row(res, orig["theta"])
    for path in sorted(args.seeds_dir.glob("*_s*.report.json")):
        config, seed = re.match(r"(.+)_s(\d+)\.report$", path.stem).groups()
        rep = json.loads(path.read_text())
        runs.setdefault(config, {})[seed] = row(rep["models"][config], rep["theta"])

    summary = {}
    for config, seeds in runs.items():
        keys = next(iter(seeds.values())).keys()
        agg = {}
        for k in keys:
            vals = [r[k] for r in seeds.values() if r[k] is not None]
            if vals:
                agg[k] = {"mean": round(statistics.mean(vals), 4),
                          "std": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0,
                          "min": min(vals), "max": max(vals)}
        summary[config] = {"n_seeds": len(seeds), "per_seed": seeds, "aggregate": agg}

    args.out.write_text(json.dumps(summary, indent=2))
    for config, s in summary.items():
        print(f"\n{config} ({s['n_seeds']} seeds)")
        print(f"  {'seed':14s} {'θ':>5s} {'all R':>6s} {'all F1':>6s} {'all AUC':>7s} "
              f"{'priv_abuse':>10s} {'etl_exfil':>9s} {'FPR':>5s}")
        for seed, r in s["per_seed"].items():
            print(f"  {seed:14s} {r['theta']:5.2f} {r['all_test.recall']:6.3f} {r['all_test.f1']:6.3f} "
                  f"{r['all_test.roc_auc']:7.4f} {r['priv_abuse.detected']:>4d}/{r['priv_abuse.n']:<5d} "
                  f"{r['etl_exfil_mal.detected']:>3d}/{r['etl_exfil_mal.n']:<5d} {r['all_test.fpr']:5.3f}")
        a = s["aggregate"]
        print(f"  {'mean±std':14s}       {a['all_test.recall']['mean']:.3f}±{a['all_test.recall']['std']:.3f} "
              f"F1 {a['all_test.f1']['mean']:.3f}±{a['all_test.f1']['std']:.3f} "
              f"priv_abuse recall {a['heldout_vs_benign.recall']['mean']:.3f}±{a['heldout_vs_benign.recall']['std']:.3f}")
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
