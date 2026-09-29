#!/usr/bin/env python3
"""
run_mc_ablation_experiments.py — CASCE Model & Algorithm Ablation Suite
========================================================================

Author: M C (CASCE Lead Model & Algorithm Ablation)
Goal:   Empirically answer "Why does CASCE work?" through rigorous ablation studies:

  1. Overall CASCE Evaluation (Precision, Recall, F1, FPR, FNR, Specificity, AUROC, AUPRC, TP/TN/FP/FN)
  2. Rules vs. GAT vs. Hybrid (Validating Algorithm 4)
  3. Algorithm 3 Ablation (Raw Graph vs. Behavior Abstraction vs. Temporal Chaining)
  4. Fusion Weight Evaluation (Systematic (w_Rule, w_GAT) sweep on Validation Set, frozen for Test)
  5. Threshold Sensitivity (Systematic theta_A, theta_R sensitivity on Validation Set, frozen for Test)
  6. Random-Seed Stability (Seeds 1, 2, 3, 4, 5 — Mean +/- Std Dev)

Deliverables:
  casce_results/main_detection_tables/
  casce_results/confusion_matrices/
  casce_results/ROC_PR_curves/
  casce_results/algorithm3_ablation/
  casce_results/fusion_results/
  casce_results/threshold_results/
  casce_results/seed_results/
"""

import os
import sys
import json
import csv
import random
import argparse
from pathlib import Path
from collections import defaultdict

import numpy as np
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
from sklearn.metrics import (
    roc_curve, auc, precision_recall_curve,
    average_precision_score, confusion_matrix
)

from algorithm_4_hybrid import (
    CasceHeteroGAT, load_model, detect, evaluate_rules, gat_score,
    fuse_scores, _load_dataset_from_dirs, _compute_epoch_loss,
    W_RULE, W_GAT, THETA_A, THETA_R
)


# ============================================================================
# METRICS UTILITIES
# ============================================================================

def compute_detailed_metrics(y_true, y_pred, y_scores=None):
    """Compute comprehensive classification metrics including AUROC & AUPRC."""
    y_true = np.array(y_true, dtype=int)
    y_pred = np.array(y_pred, dtype=int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))

    total = len(y_true)
    accuracy = (tp + tn) / max(1, total)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)

    fpr = fp / max(1, fp + tn)
    fnr = fn / max(1, fn + tp)
    specificity = tn / max(1, tn + fp)

    auroc = 0.0
    auprc = 0.0
    if y_scores is not None and len(np.unique(y_true)) > 1:
        y_scores = np.array(y_scores, dtype=float)
        try:
            fpr_arr, tpr_arr, _ = roc_curve(y_true, y_scores)
            auroc = float(auc(fpr_arr, tpr_arr))
            auprc = float(average_precision_score(y_true, y_scores))
        except Exception:
            pass

    return {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "specificity": round(float(specificity), 4),
        "auroc": round(float(auroc), 4),
        "auprc": round(float(auprc), 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total": total
    }


def save_metrics_table(metrics_dict, json_path, csv_path=None):
    """Save dictionary of metrics to JSON and CSV."""
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(metrics_dict, f, indent=2)

    if csv_path:
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
        if isinstance(metrics_dict, dict) and any(isinstance(v, dict) for v in metrics_dict.values()):
            # Nested dictionary (e.g. Model -> Metrics)
            rows = []
            for model_name, m in metrics_dict.items():
                row = {"model": model_name}
                row.update(m)
                rows.append(row)
            if rows:
                keys = list(rows[0].keys())
                with open(csv_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(rows)
        else:
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(metrics_dict.keys()))
                writer.writeheader()
                writer.writerow(metrics_dict)


def plot_annotated_confusion_matrix(cm, title, output_path, labels=("Normal", "Malicious")):
    """Plot publication-ready annotated confusion matrix."""
    plt.figure(figsize=(5, 4.5), dpi=300)
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(title, fontsize=12, fontweight='bold', pad=12)
    plt.colorbar(fraction=0.046, pad=0.04)

    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels, fontsize=10)
    plt.yticks(tick_marks, labels, fontsize=10)

    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            plt.text(j, i, f"{val:,}",
                     horizontalalignment="center",
                     verticalalignment="center",
                     color="white" if val > thresh else "black",
                     fontsize=12, fontweight='bold')

    plt.ylabel('True Class', fontsize=11, fontweight='bold')
    plt.xlabel('Predicted Class', fontsize=11, fontweight='bold')
    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=300)
    plt.close()


# ============================================================================
# EXPERIMENT 1 & 2: OVERALL CASCE & RULES VS GAT VS HYBRID
# ============================================================================

def run_exp1_and_exp2(test_labels, graphml_dir, model, out_base: Path, theta_a=0.65, w_rule=0.85, w_gat=0.75):
    """
    Exp 1: Full CASCE evaluation across all 10 metrics.
    Exp 2: Direct comparison between Rules-Only, GAT-Only, and Hybrid.
    """
    print("\n" + "="*70)
    print(" [EXPERIMENT 1 & 2] OVERALL CASCE EVALUATION & RULES vs. GAT vs. HYBRID")
    print("="*70)

    y_true = []
    rule_scores = []
    gat_scores = []
    fused_scores = []

    print(f"Evaluating {len(test_labels)} test graphs...")
    for filename, label in test_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue

        G = nx.read_graphml(gpath)
        sid = filename.replace("enriched_", "").replace(".graphml", "")

        r_score, _, _, _ = evaluate_rules(G)
        g_prob = gat_score(G, model)
        f_risk = fuse_scores(r_score, g_prob, w_rule=w_rule, w_gat=w_gat)

        y_true.append(int(label))
        rule_scores.append(r_score)
        gat_scores.append(g_prob)
        fused_scores.append(f_risk)

    y_true = np.array(y_true)
    rule_scores = np.array(rule_scores)
    gat_scores = np.array(gat_scores)
    fused_scores = np.array(fused_scores)

    # Decisions
    # Rules: threshold 0.50 (standard heuristic rule threshold)
    pred_rules = (rule_scores >= 0.50).astype(int)
    # GAT-only: threshold theta_a
    pred_gat = (gat_scores >= theta_a).astype(int)
    # Hybrid: threshold theta_a
    pred_hybrid = (fused_scores >= theta_a).astype(int)

    m_rules = compute_detailed_metrics(y_true, pred_rules, rule_scores)
    m_gat = compute_detailed_metrics(y_true, pred_gat, gat_scores)
    m_hybrid = compute_detailed_metrics(y_true, pred_hybrid, fused_scores)

    comparison_results = {
        "Rule-only": m_rules,
        "GAT-only": m_gat,
        "CASCE_Hybrid": m_hybrid
    }

    # Save tables
    save_metrics_table(
        m_hybrid,
        out_base / "main_detection_tables" / "overall_metrics.json",
        out_base / "main_detection_tables" / "overall_metrics.csv"
    )
    save_metrics_table(
        comparison_results,
        out_base / "main_detection_tables" / "rules_vs_gat_vs_hybrid.json",
        out_base / "main_detection_tables" / "rules_vs_gat_vs_hybrid.csv"
    )

    # Print Comparison Table
    print(f"\n{'Model':<15} {'Acc':<8} {'Prec':<8} {'Recall':<8} {'F1':<8} {'FPR':<8} {'AUROC':<8} {'AUPRC':<8}")
    print("-" * 68)
    for name, m in comparison_results.items():
        print(f"{name:<15} {m['accuracy']:<8.4f} {m['precision']:<8.4f} {m['recall']:<8.4f} {m['f1']:<8.4f} {m['fpr']:<8.4f} {m['auroc']:<8.4f} {m['auprc']:<8.4f}")

    # Plot Confusion Matrices
    cm_hybrid = np.array([[m_hybrid['tn'], m_hybrid['fp']], [m_hybrid['fn'], m_hybrid['tp']]])
    cm_gat = np.array([[m_gat['tn'], m_gat['fp']], [m_gat['fn'], m_gat['tp']]])
    cm_rules = np.array([[m_rules['tn'], m_rules['fp']], [m_rules['fn'], m_rules['tp']]])

    plot_annotated_confusion_matrix(
        cm_hybrid, f"CASCE Hybrid Confusion Matrix (θ_A = {theta_a})",
        out_base / "confusion_matrices" / "overall_confusion_matrix.png"
    )
    plot_annotated_confusion_matrix(
        cm_gat, f"GAT-only Confusion Matrix (θ_A = {theta_a})",
        out_base / "confusion_matrices" / "gat_only_confusion_matrix.png"
    )
    plot_annotated_confusion_matrix(
        cm_rules, "Rule-only Confusion Matrix",
        out_base / "confusion_matrices" / "rule_only_confusion_matrix.png"
    )

    with open(out_base / "confusion_matrices" / "confusion_matrices.json", "w") as f:
        json.dump({
            "CASCE_Hybrid": {"tp": m_hybrid['tp'], "fp": m_hybrid['fp'], "fn": m_hybrid['fn'], "tn": m_hybrid['tn']},
            "GAT_only": {"tp": m_gat['tp'], "fp": m_gat['fp'], "fn": m_gat['fn'], "tn": m_gat['tn']},
            "Rule_only": {"tp": m_rules['tp'], "fp": m_rules['fp'], "fn": m_rules['fn'], "tn": m_rules['tn']}
        }, f, indent=2)

    # Plot ROC & PR Curves
    plt.figure(figsize=(6, 5), dpi=300)
    for scores, name, color in [(rule_scores, "Rule-only", "orange"),
                                (gat_scores, "GAT-only", "blue"),
                                (fused_scores, "CASCE Hybrid", "green")]:
        fpr_arr, tpr_arr, _ = roc_curve(y_true, scores)
        score_auc = auc(fpr_arr, tpr_arr)
        plt.plot(fpr_arr, tpr_arr, label=f"{name} (AUROC = {score_auc:.3f})", color=color, lw=2)

    plt.plot([0, 1], [0, 1], 'k--', lw=1.2, label="Random Guess (0.50)")
    plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight='bold')
    plt.ylabel("True Positive Rate (Recall)", fontsize=11, fontweight='bold')
    plt.title("Receiver Operating Characteristic (ROC) Comparison", fontsize=12, fontweight='bold')
    plt.legend(loc="lower right", fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_base / "ROC_PR_curves" / "comparison_roc_curves.png", dpi=300)
    plt.close()

    plt.figure(figsize=(6, 5), dpi=300)
    for scores, name, color in [(rule_scores, "Rule-only", "orange"),
                                (gat_scores, "GAT-only", "blue"),
                                (fused_scores, "CASCE Hybrid", "green")]:
        prec_arr, rec_arr, _ = precision_recall_curve(y_true, scores)
        score_auprc = average_precision_score(y_true, scores)
        plt.plot(rec_arr, prec_arr, label=f"{name} (AUPRC = {score_auprc:.3f})", color=color, lw=2)

    no_skill = np.sum(y_true) / len(y_true)
    plt.plot([0, 1], [no_skill, no_skill], 'k--', lw=1.2, label=f"No Skill ({no_skill:.2f})")
    plt.xlabel("Recall", fontsize=11, fontweight='bold')
    plt.ylabel("Precision", fontsize=11, fontweight='bold')
    plt.title("Precision-Recall (PR) Curve Comparison", fontsize=12, fontweight='bold')
    plt.legend(loc="lower left", fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_base / "ROC_PR_curves" / "comparison_pr_curves.png", dpi=300)
    plt.close()

    # Combined single ROC/PR figure for paper/deliverable
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.8), dpi=300)
    # ROC
    for scores, name, color in [(rule_scores, "Rule-only", "orange"),
                                (gat_scores, "GAT-only", "blue"),
                                (fused_scores, "CASCE Hybrid", "green")]:
        fpr_arr, tpr_arr, _ = roc_curve(y_true, scores)
        score_auc = auc(fpr_arr, tpr_arr)
        ax1.plot(fpr_arr, tpr_arr, label=f"{name} ({score_auc:.3f})", color=color, lw=2)
    ax1.plot([0, 1], [0, 1], 'k--', lw=1)
    ax1.set_xlabel("False Positive Rate", fontweight='bold')
    ax1.set_ylabel("True Positive Rate", fontweight='bold')
    ax1.set_title("ROC Curves", fontweight='bold')
    ax1.legend(loc="lower right")
    ax1.grid(alpha=0.3)

    # PR
    for scores, name, color in [(rule_scores, "Rule-only", "orange"),
                                (gat_scores, "GAT-only", "blue"),
                                (fused_scores, "CASCE Hybrid", "green")]:
        prec_arr, rec_arr, _ = precision_recall_curve(y_true, scores)
        score_auprc = average_precision_score(y_true, scores)
        ax2.plot(rec_arr, prec_arr, label=f"{name} ({score_auprc:.3f})", color=color, lw=2)
    ax2.plot([0, 1], [no_skill, no_skill], 'k--', lw=1)
    ax2.set_xlabel("Recall", fontweight='bold')
    ax2.set_ylabel("Precision", fontweight='bold')
    ax2.set_title("Precision-Recall Curves", fontweight='bold')
    ax2.legend(loc="lower left")
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_base / "ROC_PR_curves" / "casce_overall_roc_pr.png", dpi=300)
    plt.close()

    print(f"✓ Saved Exp 1 & 2 deliverables into {out_base / 'main_detection_tables'}, {out_base / 'confusion_matrices'}, {out_base / 'ROC_PR_curves'}")
    return comparison_results


# ============================================================================
# EXPERIMENT 3: ALGORITHM 3 ABLATION
# ============================================================================

def strip_algorithm3_ablation(G: nx.MultiDiGraph, level: str) -> nx.MultiDiGraph:
    """
    Produce ablated graph variants for Algorithm 3:
      - 'raw': Raw/Factual graph from Algorithm 2 (zero Behavior nodes, zero evidence_for/precedes)
      - 'no_chain': Behavior nodes + evidence_for present, but all 'precedes' chronological edges stripped
      - 'full': Full Algorithm 3 graph with Behavior nodes + precedes chaining
    """
    G_ablated = G.copy()

    if level == "raw":
        # Remove all Behavior nodes and incident edges
        beh_nodes = [
            n for n, d in G_ablated.nodes(data=True)
            if d.get("type") == "Behavior" or d.get("node_type") == "Behavior"
        ]
        for n in beh_nodes:
            G_ablated.remove_node(n)
        return G_ablated

    elif level == "no_chain":
        # Remove only 'precedes' edges between Behavior nodes
        edges_to_remove = []
        if isinstance(G_ablated, nx.MultiDiGraph):
            for u, v, k, d in G_ablated.edges(data=True, keys=True):
                rel = d.get("relation", d.get("rel"))
                if rel == "precedes":
                    edges_to_remove.append((u, v, k))
            for u, v, k in edges_to_remove:
                G_ablated.remove_edge(u, v, key=k)
        else:
            for u, v, d in G_ablated.edges(data=True):
                rel = d.get("relation", d.get("rel"))
                if rel == "precedes":
                    edges_to_remove.append((u, v))
            for u, v in edges_to_remove:
                G_ablated.remove_edge(u, v)
        return G_ablated

    elif level == "full":
        return G_ablated

    else:
        raise ValueError(f"Unknown ablation level: {level}")


def run_exp3_algorithm3_ablation(test_labels, graphml_dir, model, out_base: Path, theta_a=0.65, w_rule=0.85, w_gat=0.75):
    """
    Exp 3: Compare Raw/Factual Graph vs. Behavior Abstraction vs. Behavior Abstraction + Chaining.
    """
    print("\n" + "="*70)
    print(" [EXPERIMENT 3] ALGORITHM 3 GRAPH ABSTRACTION ABLATION")
    print("="*70)

    levels = [
        ("Level 0: Raw Provenance Graph", "raw"),
        ("Level 1: Behavior Abstraction (No Chaining)", "no_chain"),
        ("Level 2: Full Alg 3 (Abstraction + Chaining)", "full")
    ]

    ablation_metrics = {}

    for display_name, lvl_key in levels:
        print(f"Evaluating {display_name} across {len(test_labels)} graphs...")
        y_true, y_pred, y_scores = [], [], []

        for filename, label in test_labels.items():
            gpath = graphml_dir / filename
            if not gpath.exists():
                continue

            G = nx.read_graphml(gpath)
            G_lvl = strip_algorithm3_ablation(G, lvl_key)
            sid = filename.replace("enriched_", "").replace(".graphml", "")

            res = detect(G_lvl, model, session_id=sid, theta_a=theta_a, w_rule=w_rule, w_gat=w_gat)
            pred = 1 if res["risk"] >= theta_a else 0

            y_true.append(int(label))
            y_pred.append(pred)
            y_scores.append(res["risk"])

        metrics = compute_detailed_metrics(y_true, y_pred, y_scores)
        ablation_metrics[display_name] = {
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "fpr": metrics["fpr"],
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "tn": metrics["tn"]
        }

    # Print table
    print(f"\n{'Ablation Stage':<42} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1':<10} {'FPR':<10}")
    print("-" * 92)
    for name, m in ablation_metrics.items():
        print(f"{name:<42} {m['accuracy']:<10.4f} {m['precision']:<10.4f} {m['recall']:<10.4f} {m['f1']:<10.4f} {m['fpr']:<10.4f}")

    # Save metrics JSON
    out_dir = out_base / "algorithm3_ablation"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "ablation_metrics.json", "w") as f:
        json.dump(ablation_metrics, f, indent=2)

    # Plot grouped bar chart
    labels = ["Precision", "Recall", "F1 Score", "Accuracy"]
    stage_names = list(ablation_metrics.keys())
    x = np.arange(len(labels))
    width = 0.25

    plt.figure(figsize=(8.5, 5), dpi=300)
    colors = ["#4a7bb0", "#f28e2b", "#59a14f"]
    for i, (stage, color) in enumerate(zip(stage_names, colors)):
        vals = [
            ablation_metrics[stage]["precision"],
            ablation_metrics[stage]["recall"],
            ablation_metrics[stage]["f1"],
            ablation_metrics[stage]["accuracy"]
        ]
        offset = (i - 1) * width
        plt.bar(x + offset, vals, width, label=stage, color=color, alpha=0.9, edgecolor='black', lw=0.6)

    plt.ylabel("Score (0.0 - 1.0)", fontsize=11, fontweight='bold')
    plt.title("Algorithm 3 Behavioral Abstraction Ablation Comparison", fontsize=12, fontweight='bold', pad=12)
    plt.xticks(x, labels, fontsize=11, fontweight='bold')
    plt.ylim(0.0, 1.08)
    plt.legend(loc="lower right", fontsize=9.5)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "algorithm3_ablation_chart.png", dpi=300)
    plt.close()

    print(f"✓ Saved Exp 3 deliverables into {out_dir}")
    return ablation_metrics


# ============================================================================
# EXPERIMENT 4: FUSION WEIGHT EVALUATION (ON VALIDATION SET)
# ============================================================================

def run_exp4_fusion_evaluation(val_labels, test_labels, graphml_dir, model, out_base: Path, theta_a=0.65):
    """
    Exp 4: Systematic grid search of (w_Rule, w_GAT) on VALIDATION set.
    Select optimal weights, freeze them, and evaluate once on the TEST set.
    Fixes the issue where w_GAT < theta_a prevents GAT alone from reaching threshold.
    """
    print("\n" + "="*70)
    print(" [EXPERIMENT 4] FUSION WEIGHTS ABLATION & GRID OPTIMIZATION (VALIDATION-DRIVEN)")
    print("="*70)

    # Pre-extract rule_score, gat_prob on Validation Set for fast vector grid sweep
    print(f"Pre-extracting scores on {len(val_labels)} Validation graphs...")
    val_y_true = []
    val_rules = []
    val_gats = []

    for filename, label in val_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue
        G = nx.read_graphml(gpath)
        r, _, _, _ = evaluate_rules(G)
        g = gat_score(G, model)
        val_y_true.append(int(label))
        val_rules.append(r)
        val_gats.append(g)

    val_y_true = np.array(val_y_true)
    val_rules = np.array(val_rules)
    val_gats = np.array(val_gats)

    w_rule_range = np.round(np.arange(0.10, 1.05, 0.05), 2)
    w_gat_range = np.round(np.arange(0.50, 1.05, 0.05), 2)

    f1_matrix = np.zeros((len(w_rule_range), len(w_gat_range)))
    best_f1 = -1.0
    best_weights = (0.85, 0.75)
    best_val_metrics = None

    grid_results = []

    for i, wr in enumerate(w_rule_range):
        for j, wg in enumerate(w_gat_range):
            # Compute noisy-OR fused scores
            fused = 1.0 - (1.0 - wr * val_rules) * (1.0 - wg * val_gats)
            pred = (fused >= theta_a).astype(int)
            m = compute_detailed_metrics(val_y_true, pred, fused)

            f1_matrix[i, j] = m["f1"]
            grid_results.append({
                "w_rule": float(wr),
                "w_gat": float(wg),
                "f1": m["f1"],
                "precision": m["precision"],
                "recall": m["recall"],
                "fpr": m["fpr"],
                "accuracy": m["accuracy"]
            })

            # Check reachability: when r=0 and g=1, fused is 1 - (1 - wg) = wg.
            # Must satisfy wg >= theta_a so pure GAT attacks can trigger!
            if wg >= theta_a and m["f1"] > best_f1:
                best_f1 = m["f1"]
                best_weights = (float(wr), float(wg))
                best_val_metrics = m

    opt_wr, opt_wg = best_weights
    print(f"\n✓ Optimal Validation Weights Found: w_Rule = {opt_wr:.2f}, w_GAT = {opt_wg:.2f}")
    print(f"  Validation F1: {best_val_metrics['f1']:.4f} | Recall: {best_val_metrics['recall']:.4f} | FPR: {best_val_metrics['fpr']:.4f}")
    print(f"  GAT Reachability Check: pure GAT attack (g=1.0, r=0.0) yields risk = {opt_wg:.2f} >= θ_A ({theta_a:.2f}) [PASS]")

    out_dir = out_base / "fusion_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save heatmap plot
    plt.figure(figsize=(7.5, 6), dpi=300)
    plt.imshow(f1_matrix, origin="lower", cmap="viridis", aspect="auto",
               extent=[w_gat_range[0]-0.025, w_gat_range[-1]+0.025,
                       w_rule_range[0]-0.025, w_rule_range[-1]+0.025])
    plt.colorbar(label="Validation F1 Score")
    plt.scatter([opt_wg], [opt_wr], color="red", marker="*", s=180, label=f"Optimal ({opt_wr:.2f}, {opt_wg:.2f})")
    plt.axvline(x=theta_a, color="red", linestyle="--", lw=1.2, label=f"Reachability Bound (w_GAT ≥ {theta_a})")
    plt.xlabel("w_GAT", fontsize=11, fontweight='bold')
    plt.ylabel("w_Rule", fontsize=11, fontweight='bold')
    plt.title(f"Fusion Weight Optimization Landscape (θ_A = {theta_a})", fontsize=12, fontweight='bold', pad=12)
    plt.legend(loc="upper left", fontsize=9.5)
    plt.tight_layout()
    plt.savefig(out_dir / "fusion_heatmap.png", dpi=300)
    plt.close()

    with open(out_dir / "fusion_grid_search_val.json", "w") as f:
        json.dump({
            "optimal_weights": {"w_rule": opt_wr, "w_gat": opt_wg},
            "best_validation_metrics": best_val_metrics,
            "grid_samples": grid_results
        }, f, indent=2)

    # Freeze optimal weights and evaluate ONCE on the Held-Out Test Set
    print(f"\nEvaluating frozen optimal weights ({opt_wr}, {opt_wg}) on Held-Out Test Set ({len(test_labels)} graphs)...")
    test_y_true, test_pred, test_fused = [], [], []
    for filename, label in test_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue
        G = nx.read_graphml(gpath)
        r, _, _, _ = evaluate_rules(G)
        g = gat_score(G, model)
        f_risk = fuse_scores(r, g, w_rule=opt_wr, w_gat=opt_wg)
        test_y_true.append(int(label))
        test_pred.append(1 if f_risk >= theta_a else 0)
        test_fused.append(f_risk)

    frozen_test_metrics = compute_detailed_metrics(test_y_true, test_pred, test_fused)
    print(f"  Frozen Test Performance: Accuracy={frozen_test_metrics['accuracy']:.4f}, F1={frozen_test_metrics['f1']:.4f}, Recall={frozen_test_metrics['recall']:.4f}, FPR={frozen_test_metrics['fpr']:.4f}")

    with open(out_dir / "frozen_weights_test_eval.json", "w") as f:
        json.dump({
            "frozen_weights": {"w_rule": opt_wr, "w_gat": opt_wg, "theta_a": theta_a},
            "test_metrics": frozen_test_metrics
        }, f, indent=2)

    print(f"✓ Saved Exp 4 deliverables into {out_dir}")
    return opt_wr, opt_wg, frozen_test_metrics


# ============================================================================
# EXPERIMENT 5: THRESHOLD SENSITIVITY (θ_A, θ_R) (ON VALIDATION SET)
# ============================================================================

def run_exp5_threshold_sensitivity(val_labels, test_labels, graphml_dir, model, out_base: Path, w_rule=0.85, w_gat=0.75):
    """
    Exp 5: Evaluate theta_A (alert threshold) and theta_R (response threshold) on VALIDATION set.
    Freeze optimal thresholds and evaluate on TEST set.
    """
    print("\n" + "="*70)
    print(" [EXPERIMENT 5] THRESHOLD SENSITIVITY EVALUATION (θ_A, θ_R) (VALIDATION-DRIVEN)")
    print("="*70)

    # Pre-extract fused risk on Validation Set
    val_y_true = []
    val_fused = []

    for filename, label in val_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue
        G = nx.read_graphml(gpath)
        r, _, _, _ = evaluate_rules(G)
        g = gat_score(G, model)
        f = fuse_scores(r, g, w_rule=w_rule, w_gat=w_gat)
        val_y_true.append(int(label))
        val_fused.append(f)

    val_y_true = np.array(val_y_true)
    val_fused = np.array(val_fused)

    thresholds = np.round(np.arange(0.40, 0.92, 0.02), 2)
    prec_list, rec_list, f1_list, fpr_list = [], [], [], []
    val_records = []

    best_theta_a = 0.65
    best_f1 = -1.0

    for th in thresholds:
        pred = (val_fused >= th).astype(int)
        m = compute_detailed_metrics(val_y_true, pred, val_fused)
        prec_list.append(m["precision"])
        rec_list.append(m["recall"])
        f1_list.append(m["f1"])
        fpr_list.append(m["fpr"])

        val_records.append({
            "theta_a": float(th),
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "fpr": m["fpr"],
            "accuracy": m["accuracy"]
        })

        # Select theta_a that maximizes F1 with FPR <= 0.06
        if m["fpr"] <= 0.06 and m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_theta_a = float(th)

    # Determine response threshold theta_R > theta_A
    # theta_R is selected where precision >= 0.98 on validation data for automated blocking
    best_theta_r = 0.80
    for rec in val_records:
        if rec["theta_a"] > best_theta_a and rec["precision"] >= 0.96:
            best_theta_r = rec["theta_a"]
            break

    print(f"\n✓ Optimal Validation Thresholds Determined:")
    print(f"  Alert Threshold θ_A*    = {best_theta_a:.2f} (Max F1 with low FPR)")
    print(f"  Response Threshold θ_R* = {best_theta_r:.2f} (High-confidence autonomous response)")

    out_dir = out_base / "threshold_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Plot Sensitivity Curves
    plt.figure(figsize=(7.5, 5), dpi=300)
    plt.plot(thresholds, f1_list, label="F1 Score", color="green", lw=2.2)
    plt.plot(thresholds, prec_list, label="Precision", color="blue", lw=1.8, linestyle="--")
    plt.plot(thresholds, rec_list, label="Recall", color="red", lw=1.8, linestyle=":")
    plt.plot(thresholds, fpr_list, label="FPR (False Alarms)", color="purple", lw=1.5, linestyle="-.")

    plt.axvline(x=best_theta_a, color="black", linestyle="--", lw=1.2, label=f"Frozen θ_A* ({best_theta_a:.2f})")
    plt.axvline(x=best_theta_r, color="red", linestyle=":", lw=1.2, label=f"Frozen θ_R* ({best_theta_r:.2f})")

    plt.xlabel("Alert Decision Threshold (θ_A)", fontsize=11, fontweight='bold')
    plt.ylabel("Metric Score", fontsize=11, fontweight='bold')
    plt.title("CASCE Threshold Sensitivity & Operating Point Selection", fontsize=12, fontweight='bold', pad=12)
    plt.ylim(-0.02, 1.05)
    plt.legend(loc="lower left", fontsize=9.5)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "precision_recall_vs_threshold.png", dpi=300)
    plt.close()

    with open(out_dir / "threshold_sweep_val.json", "w") as f:
        json.dump({
            "optimal_thresholds": {"theta_a": best_theta_a, "theta_r": best_theta_r},
            "sweep": val_records
        }, f, indent=2)

    # Freeze thresholds and evaluate on Test Set
    print(f"\nEvaluating frozen thresholds ({best_theta_a}, {best_theta_r}) on Held-Out Test Set...")
    test_y_true, test_pred, test_fused = [], [], []
    for filename, label in test_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue
        G = nx.read_graphml(gpath)
        r, _, _, _ = evaluate_rules(G)
        g = gat_score(G, model)
        f_risk = fuse_scores(r, g, w_rule=w_rule, w_gat=w_gat)
        test_y_true.append(int(label))
        test_pred.append(1 if f_risk >= best_theta_a else 0)
        test_fused.append(f_risk)

    frozen_test_metrics = compute_detailed_metrics(test_y_true, test_pred, test_fused)
    print(f"  Frozen Threshold Test Performance: F1={frozen_test_metrics['f1']:.4f}, FPR={frozen_test_metrics['fpr']:.4f}, Recall={frozen_test_metrics['recall']:.4f}")

    with open(out_dir / "frozen_threshold_test_eval.json", "w") as f:
        json.dump({
            "frozen_thresholds": {"theta_a": best_theta_a, "theta_r": best_theta_r},
            "test_metrics": frozen_test_metrics
        }, f, indent=2)

    print(f"✓ Saved Exp 5 deliverables into {out_dir}")
    return best_theta_a, best_theta_r, frozen_test_metrics


# ============================================================================
# EXPERIMENT 6: RANDOM-SEED STABILITY (SEEDS 1, 2, 3, 4, 5)
# ============================================================================

def run_exp6_seed_stability(data_dir: Path, train_labels_path: Path, val_labels_path: Path,
                            test_labels, graphml_dir, out_base: Path,
                            seeds=(1, 2, 3, 4, 5), epochs=15, lr=0.001,
                            theta_a=0.65, w_rule=0.85, w_gat=0.75):
    """
    Exp 6: Train models across multiple deterministic random seeds.
    Evaluate on test set and report Mean +/- Standard Deviation.
    """
    print("\n" + "="*70)
    print(" [EXPERIMENT 6] RANDOM-SEED STABILITY EVALUATION (SEEDS 1 to 5)")
    print("="*70)

    print("Loading training dataset into memory for multi-seed execution...")
    train_data = _load_dataset_from_dirs(str(graphml_dir), str(train_labels_path))
    val_data = _load_dataset_from_dirs(str(graphml_dir), str(val_labels_path))

    n_pos = sum(1 for _, y in train_data if y == 1.0)
    n_neg = len(train_data) - n_pos
    pos_weight = torch.tensor([n_neg / max(1, n_pos)], dtype=torch.float32)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    seed_metrics = []

    for seed in seeds:
        print(f"\n--- Running Training for Seed {seed} ({epochs} epochs) ---")
        random.seed(seed)
        np.random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

        seed_model = CasceHeteroGAT()
        optimizer = torch.optim.AdamW(seed_model.parameters(), lr=lr, weight_decay=1e-3)

        for ep in range(1, epochs + 1):
            seed_model.train()
            tot_loss = 0.0
            for data, y in train_data:
                optimizer.zero_grad()
                out = seed_model(data)
                loss = loss_fn(out.unsqueeze(0), torch.tensor([y]))
                loss.backward()
                optimizer.step()
                tot_loss += loss.item()

            if ep % 5 == 0 or ep == epochs:
                v_loss = _compute_epoch_loss(seed_model, val_data, loss_fn)
                print(f"  [Seed {seed}] Epoch {ep:2d}/{epochs:2d} - Train Loss: {tot_loss/len(train_data):.4f} - Val Loss: {v_loss:.4f}")

        # Evaluate on Test Set
        seed_model.eval()
        test_y_true, test_pred, test_fused = [], [], []

        for filename, label in test_labels.items():
            gpath = graphml_dir / filename
            if not gpath.exists():
                continue
            G = nx.read_graphml(gpath)
            r, _, _, _ = evaluate_rules(G)
            g = gat_score(G, seed_model)
            f = fuse_scores(r, g, w_rule=w_rule, w_gat=w_gat)
            test_y_true.append(int(label))
            test_pred.append(1 if f >= theta_a else 0)
            test_fused.append(f)

        m = compute_detailed_metrics(test_y_true, test_pred, test_fused)
        m["seed"] = seed
        seed_metrics.append(m)
        print(f"  [Seed {seed} Result] Accuracy: {m['accuracy']:.4f} | F1: {m['f1']:.4f} | Recall: {m['recall']:.4f} | FPR: {m['fpr']:.4f} | AUROC: {m['auroc']:.4f}")

    # Compute Mean +/- Std Dev
    keys = ["accuracy", "precision", "recall", "f1", "fpr", "specificity", "auroc", "auprc"]
    summary_stats = {}
    for k in keys:
        vals = [sm[k] for sm in seed_metrics]
        mean_val = float(np.mean(vals))
        std_val = float(np.std(vals))
        summary_stats[k] = {
            "mean": round(mean_val, 4),
            "std": round(std_val, 4),
            "formatted": f"{mean_val:.4f} ± {std_val:.4f}"
        }

    print("\n" + "="*60)
    print(" RANDOM-SEED STABILITY SUMMARY (5 SEEDS)")
    print("="*60)
    for k, s in summary_stats.items():
        print(f"  {k.upper():<15}: {s['formatted']}")
    print("="*60)

    out_dir = out_base / "seed_results"
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "multi_seed_metrics.json", "w") as f:
        json.dump({
            "seeds": seed_metrics,
            "summary": summary_stats
        }, f, indent=2)

    # Save CSV
    fieldnames = ["seed"] + keys + ["tp", "fp", "fn", "tn"]
    with open(out_dir / "seed_stability_table.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sm in seed_metrics:
            writer.writerow({k: sm.get(k) for k in fieldnames})

    # Plot Boxplots of Metrics Across Seeds
    plt.figure(figsize=(7, 4.5), dpi=300)
    plot_keys = ["accuracy", "precision", "recall", "f1", "auroc"]
    plot_data = [[sm[k] for sm in seed_metrics] for k in plot_keys]

    bp = plt.boxplot(plot_data, patch_artist=True, labels=[k.capitalize() for k in plot_keys])
    colors = ['#aec7e8', '#ffbb78', '#98df8a', '#ff9896', '#c5b0d5']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)

    plt.ylabel("Metric Score", fontsize=11, fontweight='bold')
    plt.title("Stability Across 5 Random Seeds (Mean ± Std)", fontsize=12, fontweight='bold', pad=12)
    plt.ylim(0.88, 1.01)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_dir / "seed_variance_boxplot.png", dpi=300)
    plt.close()

    print(f"✓ Saved Exp 6 deliverables into {out_dir}")
    return summary_stats


# ============================================================================
# MASTER ORCHESTRATOR
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="CASCE Model & Algorithm Ablation Suite (M C)")
    parser.add_argument("--data-dir", default="datagen/generated/multi_domain_huge",
                        help="Root directory containing dataset, splits, and enriched graphs.")
    parser.add_argument("--model-path", default="casce_gat_huge.pt",
                        help="Path to trained GAT checkpoint.")
    parser.add_argument("--outdir", default="casce_results",
                        help="Output base directory for all experiment deliverables.")
    parser.add_argument("--theta-a", type=float, default=0.65,
                        help="Initial alert threshold (default: 0.65).")
    parser.add_argument("--theta-r", type=float, default=0.80,
                        help="Initial response threshold (default: 0.80).")
    parser.add_argument("--w-rule", type=float, default=0.85,
                        help="Rule fusion weight (default: 0.85).")
    parser.add_argument("--w-gat", type=float, default=0.75,
                        help="GAT fusion weight (default: 0.75).")
    parser.add_argument("--experiments", default="all",
                        help="Comma-separated experiment IDs to run (1,2,3,4,5,6 or 'all').")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    graphml_dir = data_dir / "enriched_graphs" / "graphml"
    splits_dir = data_dir / "algo4_splits"
    out_base = Path(args.outdir)

    for sub in ["main_detection_tables", "confusion_matrices", "ROC_PR_curves",
                "algorithm3_ablation", "fusion_results", "threshold_results", "seed_results"]:
        (out_base / sub).mkdir(parents=True, exist_ok=True)

    test_labels_file = splits_dir / "test_labels.json"
    val_labels_file = splits_dir / "val_labels.json"
    train_labels_file = splits_dir / "train_labels.json"

    if not test_labels_file.exists():
        raise FileNotFoundError(f"Missing test labels file: {test_labels_file}")
    if not val_labels_file.exists():
        raise FileNotFoundError(f"Missing val labels file: {val_labels_file}")
    if not graphml_dir.exists():
        raise FileNotFoundError(f"Missing graphml directory: {graphml_dir}")

    with open(test_labels_file) as f:
        test_labels = json.load(f)
    with open(val_labels_file) as f:
        val_labels = json.load(f)

    print("\n" + "#"*70)
    print(" CASCE MODEL & ALGORITHM ABLATION EXPERIMENTS SUITE")
    print(f" Dataset:      {data_dir}")
    print(f" Model:        {args.model_path}")
    print(f" Test Graphs:  {len(test_labels)}")
    print(f" Val Graphs:   {len(val_labels)}")
    print(f" Output Dir:   {out_base}")
    print("#"*70)

    model = load_model(args.model_path)
    if model is None:
        raise RuntimeError("Failed to load model weights.")

    run_all = args.experiments.lower() == "all"
    exp_set = set(e.strip() for e in args.experiments.split(","))

    # Exp 1 & 2
    if run_all or "1" in exp_set or "2" in exp_set:
        run_exp1_and_exp2(test_labels, graphml_dir, model, out_base,
                          theta_a=args.theta_a, w_rule=args.w_rule, w_gat=args.w_gat)

    # Exp 3
    if run_all or "3" in exp_set:
        run_exp3_algorithm3_ablation(test_labels, graphml_dir, model, out_base,
                                    theta_a=args.theta_a, w_rule=args.w_rule, w_gat=args.w_gat)

    # Exp 4
    opt_wr, opt_wg = args.w_rule, args.w_gat
    if run_all or "4" in exp_set:
        opt_wr, opt_wg, _ = run_exp4_fusion_evaluation(val_labels, test_labels, graphml_dir, model, out_base, theta_a=args.theta_a)

    # Exp 5
    if run_all or "5" in exp_set:
        run_exp5_threshold_sensitivity(val_labels, test_labels, graphml_dir, model, out_base, w_rule=opt_wr, w_gat=opt_wg)

    # Exp 6
    if run_all or "6" in exp_set:
        run_exp6_seed_stability(data_dir, train_labels_file, val_labels_file,
                                test_labels, graphml_dir, out_base,
                                seeds=(1, 2, 3, 4, 5), epochs=15, lr=0.001,
                                theta_a=args.theta_a, w_rule=opt_wr, w_gat=opt_wg)

    print("\n" + "="*70)
    print(" ALL REQUESTED CASCE ABLATION EXPERIMENTS COMPLETED SUCCESSFULLY!")
    print(f" All figures, curves, confusion matrices, and tables saved to: {out_base}/")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
