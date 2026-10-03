#!/usr/bin/env python3
"""
Score one template-disjoint fold (see make_template_folds.py): metrics on the
fold's UNSEEN test templates, plus the dataset_test graphs of the templates it
was trained on (in-distribution reference).

  python3 fold_report.py --fold-dir training_v2/loto/priv_abuse --model loto/priv_abuse_s1.pt \\
      --theta 0.55 --out loto/priv_abuse_s1.report.json
"""
import argparse
import json
import statistics
from pathlib import Path

from holdout_report import metrics, score_model, session_index
from make_template_folds import graphs


def per_template(rows, theta):
    out = {}
    for tpl in sorted({r["template"] for r in rows}):
        grp = [r for r in rows if r["template"] == tpl]
        y = grp[0]["y"]
        out[tpl] = {"n": len(grp), "label": y,
                    ("detected" if y else "false_alarms"): sum(r["risk"] >= theta for r in grp),
                    "risk_min": min(r["risk"] for r in grp),
                    "risk_median": statistics.median(r["risk"] for r in grp),
                    "risk_max": max(r["risk"] for r in grp)}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--fold-dir", type=Path, required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--theta", type=float, required=True, help="θ_A tuned on the fold's validation templates")
    ap.add_argument("--dev-root", type=Path, default=Path("dataset_dev"))
    ap.add_argument("--test-root", type=Path, default=Path("dataset_test"))
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    fold = json.loads((args.fold_dir / "fold.json").read_text())
    dev_dir, test_dir = args.dev_root / "enriched_graphs/graphml", args.test_root / "enriched_graphs/graphml"
    unseen = [{"graph": g, "path": dev_dir / g, "y": y, "template": t, "source": "dataset_dev"}
              for g, (t, y) in graphs(dev_dir, session_index(args.dev_root)).items() if t in fold["test"]]
    unseen += [{"graph": g, "path": test_dir / g, "y": y, "template": t, "source": "dataset_test"}
               for g, (t, y) in graphs(test_dir, session_index(args.test_root)).items() if t in fold["test"]]
    seen = [{"graph": g, "path": test_dir / g, "y": y, "template": t, "source": "dataset_test"}
            for g, (t, y) in graphs(test_dir, session_index(args.test_root)).items() if t in fold["train"]]

    scored = score_model(args.model, unseen + seen)
    unseen_s, seen_s = scored[:len(unseen)], scored[len(unseen):]
    keep = ("graph", "template", "source", "risk", "gat", "rule")
    out = {
        "fold": fold["fold"], "test_templates": fold["test"], "val_templates": fold["val"],
        "model": args.model, "theta": args.theta,
        "unseen": metrics(unseen_s, args.theta),
        "unseen_gat_only": metrics(unseen_s, args.theta, score="gat"),
        "seen_test": metrics(seen_s, args.theta),
        "per_template_unseen": per_template(unseen_s, args.theta),
        "per_template_seen_test": per_template(seen_s, args.theta),
        "unseen_errors": [{k: r[k] for k in keep} for r in unseen_s if (r["risk"] >= args.theta) != bool(r["y"])],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    u, s = out["unseen"], out["seen_test"]
    print(f"{fold['fold']}: UNSEEN n={u['n']} TP={u['tp']} FN={u['fn']} FP={u['fp']} TN={u['tn']} "
          f"R={u['recall']} FPR={u['fpr']} F1={u['f1']} ROC-AUC={u.get('roc_auc')} | "
          f"seen-test F1={s['f1']} FPR={s['fpr']}")


if __name__ == "__main__":
    main()
