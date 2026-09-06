#!/usr/bin/env python3
"""
CASCE — Evaluation Script
==========================

Standalone script for evaluating the trained CASCE hybrid detector
on labeled datasets. Reports per-class and binary metrics.

Usage:
    python3 evaluate.py \
        --input-dirs pipeline_output/test/run_1/enriched,pipeline_output/test/run_2/enriched,pipeline_output/test/run_3/enriched \
        --label-files pipeline_output/test/run_1/labels.json,pipeline_output/test/run_2/labels.json,pipeline_output/test/run_3/labels.json \
        --model-path casce_gat.pt
"""

import os
import csv
import json
import argparse
import sys

# Add current dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from algorithm_4_hybrid import (
    detect, load_model, THETA_A, THETA_R, TORCH_AVAILABLE
)

import networkx as nx


def load_detailed_labels(label_csv_paths):
    """Load multi-class labels from CSV files (session_id -> label string).

    Returns dict: session_id_str -> label_string
    """
    all_labels = {}
    csv_paths = [p.strip() for p in label_csv_paths.split(',') if p.strip()]
    for csv_path in csv_paths:
        if not os.path.exists(csv_path):
            print(f"[eval] WARNING: {csv_path} not found — skipping.")
            continue
        with open(csv_path, newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                sid = row.get('session_id', '').strip()
                label = row.get('label', '').strip()
                if sid:
                    all_labels[sid] = label
    return all_labels


def evaluate(args):
    """Run full evaluation with per-class and binary metrics."""
    if not TORCH_AVAILABLE:
        print("[eval] WARNING: torch/torch_geometric not available — using heuristic fallback.")
        print("[eval]          Results with heuristic fallback are NOT scientifically valid.")

    model = load_model(args.model_path)

    # Load enriched graphs and binary labels
    dirs = [d.strip() for d in args.input_dirs.split(',') if d.strip()]
    label_files = [f.strip() for f in args.label_files.split(',') if f.strip()]

    # Also load detailed class labels if CSV paths provided
    detailed_labels = {}
    if args.label_csvs:
        detailed_labels = load_detailed_labels(args.label_csvs)

    # Evaluate each graph
    results = []
    for d, lf in zip(dirs, label_files):
        with open(lf) as f:
            labels = json.load(f)
        for filename, label in labels.items():
            path = os.path.join(d, filename)
            if not os.path.exists(path):
                continue
            G = nx.read_graphml(path)
            session_id = filename.replace('enriched_', '').replace('.graphml', '')
            assessment = detect(G, model, session_id=session_id)

            # Extract class label: prefer CSV, else parse from filename
            # Filename format: enriched_session_XXXXX_LabelName.graphml
            if detailed_labels:
                class_label = detailed_labels.get(session_id, 'Normal' if label == 0 else 'Malicious')
            else:
                # Parse label from filename
                parts = filename.replace('enriched_session_', '').replace('.graphml', '').split('_', 1)
                class_label = parts[1].replace('_', ' ') if len(parts) > 1 else ('Normal' if label == 0 else 'Malicious')

            results.append({
                'session_id': session_id,
                'true_binary': int(label),
                'true_class': class_label,
                'pred_binary': 1 if assessment['risk'] >= args.theta_a else 0,
                'risk': assessment['risk'],
                'rule_score': assessment['rule_score'],
                'gat_score': assessment['gat_score'],
                'scenario': assessment.get('scenario'),
                'status': assessment['status'],
            })

    if not results:
        print("[eval] ERROR: No evaluation data found.")
        return

    # --- Binary Metrics ---
    y_true = [r['true_binary'] for r in results]
    y_pred = [r['pred_binary'] for r in results]

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    accuracy = (tp + tn) / max(1, len(y_true))

    print(f"\n{'='*60}")
    print(f"  CASCE EVALUATION REPORT")
    print(f"{'='*60}")
    print(f"\n  Binary Classification (θ_A = {args.theta_a})")
    print(f"  {'─'*40}")
    print(f"  Total samples:  {len(results)}")
    print(f"  Malicious:      {sum(y_true)} ({sum(y_true)/len(y_true)*100:.1f}%)")
    print(f"  Normal:         {len(y_true)-sum(y_true)} ({(len(y_true)-sum(y_true))/len(y_true)*100:.1f}%)")
    print(f"")
    print(f"  Accuracy:       {accuracy:.4f}")
    print(f"  Precision:      {precision:.4f}")
    print(f"  Recall:         {recall:.4f}")
    print(f"  F1-Score:       {f1:.4f}")
    print(f"")
    print(f"  Confusion Matrix:")
    print(f"                  Pred Normal  Pred Malicious")
    print(f"  True Normal        {tn:5d}        {fp:5d}")
    print(f"  True Malicious     {fn:5d}        {tp:5d}")

    # --- Per-Class Detection Rates ---
    classes = sorted(set(r['true_class'] for r in results))
    if len(classes) > 1:
        print(f"\n  Per-Class Detection Rates")
        print(f"  {'─'*40}")
        print(f"  {'Class':<25} {'Total':>5} {'Detected':>8} {'Rate':>6}")

        class_metrics = {}
        for cls in classes:
            cls_results = [r for r in results if r['true_class'] == cls]
            total = len(cls_results)
            if cls == 'Normal':
                # For normal, "correct" means NOT flagged
                correct = sum(1 for r in cls_results if r['pred_binary'] == 0)
                rate = correct / max(1, total)
                print(f"  {cls:<25} {total:>5} {correct:>8} {rate:>6.1%}  (correct normal)")
            else:
                detected = sum(1 for r in cls_results if r['pred_binary'] == 1)
                rate = detected / max(1, total)
                print(f"  {cls:<25} {total:>5} {detected:>8} {rate:>6.1%}")
            class_metrics[cls] = {'total': total, 'rate': round(rate, 4)}

    # --- Save detailed results ---
    output = {
        'threshold': args.theta_a,
        'binary_metrics': {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'confusion_matrix': [[tn, fp], [fn, tp]],
        },
        'per_session': results,
    }
    if len(classes) > 1:
        output['per_class'] = class_metrics

    os.makedirs(args.outdir, exist_ok=True)
    out_path = os.path.join(args.outdir, 'evaluation_report.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Full report saved to {out_path}")
    print(f"{'='*60}\n")


def parse_args():
    p = argparse.ArgumentParser(description="CASCE Evaluation Script")
    p.add_argument('--input-dirs', required=True,
                   help='Comma-separated enriched graph directories')
    p.add_argument('--label-files', required=True,
                   help='Comma-separated label JSON files (binary: 0/1)')
    p.add_argument('--label-csvs', default=None,
                   help='Comma-separated label CSV files (multi-class, for per-class metrics)')
    p.add_argument('--model-path', default='./casce_gat.pt')
    p.add_argument('--theta-a', type=float, default=THETA_A)
    p.add_argument('--outdir', default='./eval_output')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    evaluate(args)
