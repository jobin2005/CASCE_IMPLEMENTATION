"""Shared evaluation metrics for the CASCE detector.

Reports threshold-free (ROC-AUC / PR-AUC) and calibration (Brier / ECE) numbers
next to the thresholded ones, because a single F1@theta hides miscalibration.
Thresholds must be chosen on validation data only -- see best_f1_threshold.
"""

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score


def confusion(y_true, scores, thr):
    y = np.asarray(y_true, dtype=int)
    p = (np.asarray(scores, dtype=float) >= thr).astype(int)
    return (int(((y == 0) & (p == 0)).sum()), int(((y == 0) & (p == 1)).sum()),
            int(((y == 1) & (p == 0)).sum()), int(((y == 1) & (p == 1)).sum()))


def expected_calibration_error(y_true, scores, bins=10):
    y = np.asarray(y_true, dtype=float)
    s = np.clip(np.asarray(scores, dtype=float), 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    for i in range(bins):
        hi = edges[i + 1] if i < bins - 1 else 1.0 + 1e-9
        m = (s >= edges[i]) & (s < hi)
        if m.any():
            ece += m.mean() * abs(y[m].mean() - s[m].mean())
    return float(ece)


def binary_report(y_true, scores, thr):
    """Thresholded + threshold-free + calibration metrics. AUCs are None when
    the set is single-class (they are undefined, not 1.0)."""
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    tn, fp, fn, tp = confusion(y, s, thr)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    both = 0 < y.sum() < len(y)
    return {
        "n": int(len(y)), "n_pos": int(y.sum()), "threshold": float(thr),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / max(1, len(y)),
        "precision": prec, "recall": rec,
        "f1": 2 * prec * rec / max(1e-9, prec + rec),
        "fpr": fp / max(1, fp + tn),
        "roc_auc": float(roc_auc_score(y, s)) if both else None,
        "pr_auc": float(average_precision_score(y, s)) if both else None,
        "brier": float(brier_score_loss(y, np.clip(s, 0, 1))),
        "ece": expected_calibration_error(y, s),
        "single_class": not both,
    }


def best_f1_threshold(y_true, scores, grid=None):
    """Threshold maximising F1. Call on VALIDATION data only."""
    grid = np.linspace(0.05, 0.95, 91) if grid is None else grid
    best, best_f1 = 0.5, -1.0
    for t in grid:
        tn, fp, fn, tp = confusion(y_true, scores, t)
        p, r = tp / max(1, tp + fp), tp / max(1, tp + fn)
        f1 = 2 * p * r / max(1e-9, p + r)
        if f1 > best_f1:
            best, best_f1 = float(t), f1
    return best
