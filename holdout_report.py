#!/usr/bin/env python3
"""
Per-template evaluation of trained models on a labeled test set, for the
leave-one-template-out experiment: how well is the HELD-OUT template detected
(vs. all benign test graphs), and how do the seen templates fare.

Scores every graph with algorithm_4_hybrid.detect() (the same fused risk that
--mode evaluate thresholds), so the all-test row matches --mode evaluate.

  python3 holdout_report.py --family banking_priv_abuse --theta 0.55 \\
      --model holdout=casce_gat_holdout_priv_abuse.pt --model v2=casce_gat_v2.pt \\
      --out eval_test_report_holdout_priv_abuse/holdout_report.json
"""
import argparse
import json
import re
import statistics
from pathlib import Path

import networkx as nx
from sklearn.metrics import average_precision_score, roc_auc_score

import algorithm_4_hybrid as alg4


def session_index(dataset_root: Path):
    """(run, backend_pid) -> (template, session key, scenario_id), from the expectation manifests."""
    out = {}
    for manifest in dataset_root.glob("run_*/expectation_manifest.json"):
        run = manifest.parent.name
        for scenario_id, sc in json.loads(manifest.read_text())["scenarios"].items():
            fam = re.sub(r"_\d+$", "", scenario_id)
            for key, sess in sc["sessions"].items():
                out[(run, int(sess["backend_pid"]))] = (fam, key, scenario_id)
    return out


def metrics(rows, theta, score="risk"):
    """Binary metrics at theta plus threshold-free AUCs over rows of {y, risk, gat}."""
    y = [r["y"] for r in rows]
    s = [r[score] for r in rows]
    tp = sum(1 for t, v in zip(y, s) if t == 1 and v >= theta)
    fp = sum(1 for t, v in zip(y, s) if t == 0 and v >= theta)
    fn = sum(1 for t, v in zip(y, s) if t == 1 and v < theta)
    tn = sum(1 for t, v in zip(y, s) if t == 0 and v < theta)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    out = {
        "n": len(y), "n_malicious": sum(y), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(2 * prec * rec / max(1e-9, prec + rec), 4),
        "accuracy": round((tp + tn) / max(1, len(y)), 4),
        "fpr": round(fp / max(1, fp + tn), 4),
    }
    if 0 < sum(y) < len(y):
        out["roc_auc"] = round(roc_auc_score(y, s), 4)
        out["pr_auc"] = round(average_precision_score(y, s), 4)
        pos = [v for t, v in zip(y, s) if t == 1]
        neg = [v for t, v in zip(y, s) if t == 0]
        out["min_malicious_score"] = min(pos)
        out["max_benign_score"] = max(neg)
        out["margin"] = round(min(pos) - max(neg), 4)
    return out


def score_model(model_path, rows):
    model = alg4.load_model(model_path)
    scored = []
    for r in rows:
        a = alg4.detect(nx.read_graphml(r["path"]), model, session_id=r["graph"])
        scored.append({**r, "risk": a["risk"], "gat": a["gat_score"], "rule": a["rule_score"]})
    return scored


def report(scored, family, theta):
    benign = [r for r in scored if r["y"] == 0]
    held = [r for r in scored if r["template"] == family]
    seen = [r for r in scored if r["template"] != family]
    per_template = {}
    for tpl in sorted({(r["template"], r["session"], r["y"]) for r in scored}):
        grp = [r for r in scored if (r["template"], r["session"], r["y"]) == tpl]
        name = f"{tpl[0]}:{tpl[1]}" + ("" if tpl[2] else " (benign)")
        hit = sum(1 for r in grp if r["risk"] >= theta)
        per_template[name] = {
            "n": len(grp), "label": tpl[2],
            ("detected" if tpl[2] else "false_alarms"): hit,
            "risk_min": min(r["risk"] for r in grp), "risk_median": statistics.median(r["risk"] for r in grp),
            "risk_max": max(r["risk"] for r in grp),
            "gat_min": min(r["gat"] for r in grp), "gat_median": statistics.median(r["gat"] for r in grp),
        }
    return {
        "all_test": metrics(scored, theta),
        "heldout_vs_benign": metrics(held + benign, theta),
        "heldout_vs_benign_gat_only": metrics(held + benign, theta, score="gat"),
        "seen_templates": metrics(seen, theta),
        "per_template": per_template,
        "missed_malicious": [
            {k: r[k] for k in ("graph", "scenario_id", "session", "risk", "gat", "rule")}
            for r in scored if r["y"] == 1 and r["risk"] < theta
        ],
        "false_alarms": [
            {k: r[k] for k in ("graph", "scenario_id", "session", "risk", "gat", "rule")}
            for r in scored if r["y"] == 0 and r["risk"] >= theta
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--family", required=True, help="held-out template, e.g. banking_priv_abuse")
    ap.add_argument("--theta", type=float, required=True, help="alert threshold tuned on validation")
    ap.add_argument("--model", action="append", required=True, help="name=path.pt (repeatable)")
    ap.add_argument("--dataset-root", type=Path, default=Path("dataset_test"))
    ap.add_argument("--graph-dir", type=Path, default=Path("dataset_test/enriched_graphs/graphml"))
    ap.add_argument("--labels", type=Path, default=Path("dataset_test/algo4_splits/test_labels.json"))
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    sessions = session_index(args.dataset_root)
    rows = []
    for fname, y in sorted(json.loads(args.labels.read_text()).items()):
        m = re.match(r"enriched_(run_\d+)_(\d+)_", fname)
        fam, key, scenario_id = sessions[(m.group(1), int(m.group(2)))]
        rows.append({"graph": fname, "path": args.graph_dir / fname, "y": int(y),
                     "template": fam, "session": key, "scenario_id": scenario_id})

    out = {"family": args.family, "theta": args.theta, "labels": str(args.labels),
           "n_heldout_test_graphs": sum(1 for r in rows if r["template"] == args.family),
           "models": {}}
    for spec in args.model:
        name, path = spec.split("=", 1)
        out["models"][name] = {"model_path": path, **report(score_model(path, rows), args.family, args.theta)}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    for name, res in out["models"].items():
        for part in ("all_test", "heldout_vs_benign", "seen_templates"):
            r = res[part]
            print(f"{name:8s} {part:18s} n={r['n']:3d} P={r['precision']:.3f} R={r['recall']:.3f} "
                  f"F1={r['f1']:.3f} FPR={r['fpr']:.3f} ROC-AUC={r.get('roc_auc', '-')} PR-AUC={r.get('pr_auc', '-')}")
        print(f"{name:8s} missed: {[(m['scenario_id'], m['session'], m['risk']) for m in res['missed_malicious']]}")
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
