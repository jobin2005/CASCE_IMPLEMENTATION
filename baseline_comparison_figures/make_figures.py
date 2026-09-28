#!/usr/bin/env python3
"""Generate comparison figures from the already-consolidated result tables
(baseline_comparison_tables/comparison.json and
comparison_ood_reverse_shell.md's source data). Reads saved results only --
does not re-run or recompute anything.

Usage:
    python baseline_comparison_figures/make_figures.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "baseline_comparison_figures"

CATEGORY_COLOR = {
    "Classical ML": "#4C72B0",
    "GNN (same repr.)": "#DD8452",
    "Provenance": "#55A868",
    "CASCE (reference)": "#C44E52",
}


def fig_metric_bar(rows, metric, title, fname, skip_none=True):
    data = [(r["model"], r["category"], r[metric]) for r in rows if not skip_none or r[metric] is not None]
    data.sort(key=lambda x: (list(CATEGORY_COLOR.keys()).index(x[1]), -(x[2] or 0)))
    names = [d[0] for d in data]
    values = [d[2] for d in data]
    colors = [CATEGORY_COLOR[d[1]] for d in data]

    fig, ax = plt.subplots(figsize=(10.5, max(4, 0.4 * len(names))))
    y_pos = range(len(names))
    ax.barh(y_pos, values, color=colors)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel(metric.replace("_", "-").upper())
    ax.set_title(title)
    ax.set_xlim(0, 1.05)
    for i, v in enumerate(values):
        ax.text(v + 0.01, i, f"{v:.3f}", va="center", fontsize=8)

    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in CATEGORY_COLOR.values()]
    ax.legend(handles, CATEGORY_COLOR.keys(), loc="upper left", bbox_to_anchor=(1.0, 1.0), fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT_DIR / fname, dpi=150)
    plt.close(fig)
    print(f"wrote {fname}")


def fig_iid_vs_ood():
    path = REPO / "gnn_results" / "ood_sweep" / "ood_reverse_shell.json"
    d = json.loads(path.read_text())
    entries = []
    for name, res in d.get("classical_ml", {}).items():
        entries.append((name, res["test_iid"]["accuracy"], res["test_ood"]["accuracy"]))
    for name in ("gcn", "sage", "gat", "gatv2"):
        if name in d:
            entries.append((name.upper(), d[name]["test_iid"]["accuracy"], d[name]["test_ood"]["accuracy"]))

    names = [e[0] for e in entries]
    iid = [e[1] for e in entries]
    ood = [e[2] for e in entries]
    x = range(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width / 2 for i in x], iid, width, label="test_iid (easy split)", color="#4C72B0")
    ax.bar([i + width / 2 for i in x], ood, width, label="test_ood ('reverse_shell' held out entirely)", color="#C44E52")
    ax.axhline(0.5, color="gray", linestyle="--", linewidth=1, label="chance (0.5)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=20)
    ax.set_ylabel("Accuracy")
    ax.set_ylim(0, 1.05)
    ax.set_title("IID vs. leave-one-category-out OOD accuracy\n(reverse_shell held out entirely from training)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "iid_vs_ood_reverse_shell.png", dpi=150)
    plt.close(fig)
    print("wrote iid_vs_ood_reverse_shell.png")


def main():
    rows = json.loads((REPO / "baseline_comparison_tables" / "comparison.json").read_text())
    fig_metric_bar(rows, "f1", "F1 score — all baselines vs. CASCE\n(multi-domain corpus, family-disjoint split)",
                   "f1_comparison.png")
    fig_metric_bar(rows, "roc_auc", "ROC-AUC — all baselines with a threshold-free score\n"
                   "(CASCE's fused-pipeline eval doesn't report ROC-AUC in this format, omitted here, not zero)",
                   "roc_auc_comparison.png")
    fig_iid_vs_ood()


if __name__ == "__main__":
    main()
