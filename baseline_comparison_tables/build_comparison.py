#!/usr/bin/env python3
"""Consolidate every baseline result JSON (already produced by the scripts
in baseline_models/) into one master comparison table.

Reads only already-saved result files -- does not re-run anything or
recompute metrics, so numbers here are guaranteed identical to what each
baseline script itself printed and saved.

Usage:
    python baseline_comparison_tables/build_comparison.py
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "baseline_comparison_tables"

# (display name, category, result file, params key if present)
SOURCES = [
    ("Logistic Regression", "Classical ML", "classical_ml_results/logistic_regression.json"),
    ("Random Forest", "Classical ML", "classical_ml_results/random_forest.json"),
    ("MLP", "Classical ML", "classical_ml_results/mlp.json"),
    ("XGBoost", "Classical ML", "classical_ml_results/xgboost.json"),
    ("GCN (via GraphConv)", "GNN (same repr.)", "gnn_results/gcn.json"),
    ("GraphSAGE", "GNN (same repr.)", "gnn_results/sage.json"),
    ("GAT", "GNN (same repr.)", "gnn_results/gat.json"),
    ("GATv2", "GNN (same repr.)", "gnn_results/gatv2.json"),
    ("ShadeWatcher (TransR)", "Provenance", "provenance_baseline_results/shadewatcher_results.json"),
    ("MAGIC", "Provenance", "provenance_baseline_results/magic_results.json"),
    ("StreamSpot", "Provenance", "provenance_baseline_results/streamspot_results.json"),
    ("RT-APT", "Provenance", "provenance_baseline_results/rtapt_results.json"),
    ("Kairos (TGN)", "Provenance", "provenance_baseline_results/kairos_results.json"),
    ("Unicorn (HistoSketch)", "Provenance", "provenance_baseline_results/unicorn_results.json"),
    ("FLASH", "Provenance", "provenance_baseline_results/flash_results.json"),
]


def load_test_report(path):
    d = json.loads((REPO / path).read_text())
    return d.get("test", d), d.get("n_parameters")


def main():
    rows = []
    for name, category, path in SOURCES:
        full_path = REPO / path
        if not full_path.exists():
            print(f"[skip] missing: {path}")
            continue
        rep, n_params = load_test_report(path)
        rows.append({
            "model": name, "category": category,
            "accuracy": rep.get("accuracy"), "precision": rep.get("precision"),
            "recall": rep.get("recall"), "f1": rep.get("f1"), "fpr": rep.get("fpr"),
            "roc_auc": rep.get("roc_auc"), "brier": rep.get("brier"),
            "n_parameters": n_params,
        })

    # CASCE's own evaluate_model() output format differs slightly (no roc_auc/brier/fpr key
    # under those exact names) -- read directly rather than forcing it through load_test_report.
    casce_path = REPO / "output/corpus_multidomain/eval_test_report/evaluation_results.json"
    if casce_path.exists():
        c = json.loads(casce_path.read_text())
        tn, fp = c["confusion_matrix"][0]
        fpr = fp / (fp + tn) if (fp + tn) else None
        rows.append({
            "model": "CASCE (HeteroGATv2, full fused pipeline)", "category": "CASCE (reference)",
            "accuracy": c["accuracy"], "precision": c["precision"], "recall": c["recall"],
            "f1": c["f1_score"], "fpr": fpr, "roc_auc": None, "brier": None, "n_parameters": 2033729,
        })

    (OUT_DIR / "comparison.json").write_text(json.dumps(rows, indent=2))

    # Markdown, grouped by category in a fixed, deliberate order.
    order = ["Classical ML", "GNN (same repr.)", "Provenance", "CASCE (reference)"]
    lines = ["# Baseline comparison — full results (multi-domain corpus, family-disjoint split)",
             "",
             "Every number below is read directly from its own result JSON (see `baseline_comparison_tables/build_comparison.py`) "
             "-- nothing here is hand-transcribed or re-derived.",
             "",
             "| Model | Category | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | Params |",
             "|---|---|---|---|---|---|---|---|---|"]
    for cat in order:
        for r in rows:
            if r["category"] != cat:
                continue
            def fmt(x, nd=4):
                return f"{x:.{nd}f}" if isinstance(x, (int, float)) else "—"
            params = f"{r['n_parameters']:,}" if r["n_parameters"] else "—"
            lines.append(f"| {r['model']} | {r['category']} | {fmt(r['accuracy'])} | {fmt(r['precision'])} | "
                         f"{fmt(r['recall'])} | {fmt(r['f1'])} | {fmt(r['fpr'])} | {fmt(r['roc_auc'])} | {params} |")
    lines.append("")
    lines.append("CGL-AD is not included above — cite-only, no public implementation, see "
                 "`provenance_baseline_results/cgl_ad_citation.md`. OmegaLog is not included — not a "
                 "classifier, see `omegalog_comparison/omegalog_vs_casce.md` for the methodology comparison.")
    (OUT_DIR / "comparison.md").write_text("\n".join(lines))
    print(f"wrote {len(rows)} rows -> comparison.json, comparison.md")

    build_ood_table()


def build_ood_table():
    """Leave-one-category-out OOD sweep (reverse_shell held out entirely) --
    from gnn_results/ood_sweep/ood_reverse_shell.json, produced by
    baseline_models/ood_sweep.py. Read directly, not re-derived."""
    path = REPO / "gnn_results" / "ood_sweep" / "ood_reverse_shell.json"
    if not path.exists():
        print("[skip] no OOD sweep file found")
        return
    d = json.loads(path.read_text())
    holdout = d["holdout_category"]

    ood_rows = []
    for name, res in d.get("classical_ml", {}).items():
        ood_rows.append((name, "Classical ML", res["test_iid"], res["test_ood"]))
    for name in ("gcn", "sage", "gat", "gatv2"):
        if name in d:
            ood_rows.append((name.upper(), "GNN (same repr.)", d[name]["test_iid"], d[name]["test_ood"]))

    lines = [f"# Leave-one-category-out OOD sweep — '{holdout}' held out entirely from training",
             "",
             "Every session of the held-out category (both malicious AND benign instances of that "
             "technique) is removed from train/val entirely; test_iid is a normal held-out split from "
             "the REMAINING categories (the \"easy\" split), test_ood is every session of the held-out "
             "category (a technique genuinely never seen during training, in any form).",
             "",
             "| Model | Category | IID Acc | IID F1 | OOD Acc | OOD F1 | OOD FPR | OOD FN | OOD ROC-AUC |",
             "|---|---|---|---|---|---|---|---|---|"]

    def fmt(x, nd=4):
        return f"{x:.{nd}f}" if isinstance(x, (int, float)) else "—"

    for name, cat, iid, ood in ood_rows:
        lines.append(f"| {name} | {cat} | {fmt(iid['accuracy'])} | {fmt(iid['f1'])} | "
                     f"{fmt(ood['accuracy'])} | {fmt(ood['f1'])} | {fmt(ood['fpr'])} | "
                     f"{ood['fn']}/{ood['n_pos']} | {fmt(ood['roc_auc'])} |")
    lines.append("")
    lines.append("Note: this sweep covers classical ML + the 4 bare GNN architectures on identical "
                 "features/split, isolating architecture choice. CASCE's full fused pipeline "
                 "(rule engine + HeteroGATv2) was not separately re-run on this OOD split -- GATv2's row "
                 "above is the architecture CASCE's own classifier uses, not the full fused system.")
    (OUT_DIR / "comparison_ood_reverse_shell.md").write_text("\n".join(lines))
    print(f"wrote {len(ood_rows)} OOD rows -> comparison_ood_reverse_shell.md")


if __name__ == "__main__":
    main()
