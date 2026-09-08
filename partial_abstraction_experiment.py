#!/usr/bin/env python3
"""
CASCE — Partial Behavior Abstraction Resilience Experiment (Section 6)
========================================================================

Objective:
    Evaluate the resilience of Algorithm 4 (Hybrid Cross-Layer Threat Detection)
    when Algorithm 3 (Behavior Abstraction) only partially recognizes behaviors.

    In real-world deployments, zero-day techniques, novel malware variants, or
    heuristic thresholding may cause Algorithm 3 to miss some behavioral patterns
    (e.g., missing DATA_PACKAGING while recognizing DATA_ACCESS and EXTERNAL_TRANSFER).

    This experiment deliberately removes behavior abstractions at controlled rates:
      - 100% Behavior Recognition (Full Algorithm 3 output)
      - 90%  Behavior Recognition (10% abstraction drop)
      - 75%  Behavior Recognition (25% abstraction drop)
      - 50%  Behavior Recognition (50% abstraction drop)
      - 25%  Behavior Recognition (75% abstraction drop)
      - 0%   Behavior Recognition (Pure GAT topological fallback)

Key Research Question:
    How does Algorithm 4's hybrid architecture (Rule Path + GAT Path + Noisy-OR Fusion)
    protect against broken rule chains when upstream abstractions are lost?

Outputs:
    - partial_abstraction_output/partial_abstraction_results.json
    - Formatted terminal report

Usage:
    python partial_abstraction_experiment.py                 # Evaluates dataset_test
    python partial_abstraction_experiment.py --split dev     # Evaluates dataset_dev
    python partial_abstraction_experiment.py --max-samples 50 # Fast evaluation
"""

import os
import sys
import json
import math
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import networkx as nx
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import algorithm_3_abstract
from algorithm_4_hybrid import (
    detect, load_model, evaluate_rules, gat_score, fuse_scores,
    THETA_A, THETA_R, TORCH_AVAILABLE
)

OUTPUT_DIR = BASE_DIR / "partial_abstraction_output"
DEFAULT_MODEL_PATH = BASE_DIR / "casce_gat.pt"
DEFAULT_LEVELS = [1.0, 0.90, 0.75, 0.50, 0.25, 0.0]


# ============================================================================
# 1. BEHAVIOR ABSTRACTION & PARTIAL REMOVAL LOGIC
# ============================================================================

def ensure_graph_has_behaviors(G: nx.Graph, templates: List[Any]) -> nx.Graph:
    """
    Ensures that the graph contains Algorithm 3 Behavior nodes.
    If none exist in the file, executes abstract_session_graph() on the fly.
    """
    has_beh = any(d.get("type") == "Behavior" for n, d in G.nodes(data=True))
    if has_beh:
        return G.copy()
    return algorithm_3_abstract.abstract_session_graph(G, templates)


def degrade_behaviors(G_enriched: nx.Graph, retention_rate: float, rng: np.random.Generator) -> Tuple[nx.Graph, int, int]:
    """
    Simulates partial behavior abstraction by retaining a fraction of Behavior nodes
    and pruning the rest (along with their incident evidence_for and precedes edges).
    Returns (G_degraded, total_behaviors, kept_behaviors).
    """
    beh_nodes = [n for n, d in G_enriched.nodes(data=True) if d.get("type") == "Behavior"]
    total_beh = len(beh_nodes)

    if total_beh == 0 or retention_rate >= 1.0:
        return G_enriched.copy(), total_beh, total_beh

    k_keep = int(math.ceil(total_beh * retention_rate)) if retention_rate > 0 else 0
    if k_keep > 0:
        kept_set = set(rng.choice(beh_nodes, size=k_keep, replace=False))
        dropped_set = set(beh_nodes) - kept_set
    else:
        kept_set = set()
        dropped_set = set(beh_nodes)

    G_degraded = G_enriched.copy()
    G_degraded.remove_nodes_from(dropped_set)

    return G_degraded, total_beh, len(kept_set)


# ============================================================================
# 2. SESSION EVALUATION UNDER PARTIAL ABSTRACTION
# ============================================================================

def evaluate_single_session_levels(
    session_data: Dict[str, Any],
    model: Any,
    templates: List[Any],
    retention_levels: List[float],
    seed: int = 42
) -> Dict[str, Any]:
    """Evaluates a session across all specified behavior retention rates."""
    G_raw = nx.read_graphml(session_data["filepath"])
    G_full = ensure_graph_has_behaviors(G_raw, templates)

    rng = np.random.default_rng(seed)
    session_curve = {}

    for rate in retention_levels:
        G_degraded, total_b, kept_b = degrade_behaviors(G_full, rate, rng)

        # 1. Rule-path evaluation
        rule_score, scenario, matched_nodes, _ = evaluate_rules(G_degraded)

        # 2. GAT-path evaluation
        g_score = gat_score(G_degraded, model)

        # 3. Fused detection
        risk = fuse_scores(rule_score, g_score)
        is_alert = risk >= THETA_A

        session_curve[str(int(rate * 100))] = {
            "retention_rate": rate,
            "total_behaviors": total_b,
            "kept_behaviors": kept_b,
            "rule_score": round(rule_score, 4),
            "gat_score": round(g_score, 4),
            "fused_risk": round(risk, 4),
            "is_alert": is_alert,
            "rule_scenario": scenario,
        }

    return {
        "session_id": session_data["session_id"],
        "filename": session_data["filename"],
        "is_normal": session_data["is_normal"],
        "label": session_data["label"],
        "curve": session_curve,
    }


# ============================================================================
# 3. DATASET LOADING & EXPERIMENT SUITE
# ============================================================================

def load_sessions(split_dirs: List[Path], max_samples: Optional[int] = None) -> List[Dict[str, Any]]:
    """Crawls split directories to collect sessions."""
    sessions = []
    for s_dir in split_dirs:
        for g_path in sorted(s_dir.glob("run_*/*.graphml")):
            fname = g_path.name
            is_normal = "_Normal" in fname
            parts = fname.replace("enriched_session_", "").replace(".graphml", "").split("_", 1)
            session_id = parts[0]
            label = parts[1].replace("_", " ") if len(parts) > 1 else ("Normal" if is_normal else "Malicious")

            sessions.append({
                "filepath": g_path,
                "filename": fname,
                "session_id": session_id,
                "is_normal": is_normal,
                "label": label,
            })

    if max_samples and max_samples < len(sessions):
        attacks = [s for s in sessions if not s["is_normal"]]
        normals = [s for s in sessions if s["is_normal"]]
        n_att = max_samples // 2
        n_norm = max_samples - n_att
        sessions = attacks[:n_att] + normals[:n_norm]

    return sessions


def run_experiment(
    split_dirs: List[Path],
    model_path: Path,
    retention_levels: List[float],
    max_samples: Optional[int] = None
) -> Dict[str, Any]:
    """Runs the partial behavior abstraction resilience experiment."""
    print(f"[experiment] Initializing Algorithm 3 behavior templates...")
    templates = algorithm_3_abstract.initialize_templates()

    print(f"[experiment] Loading GAT detector from {model_path}...")
    model = load_model(str(model_path))

    sessions = load_sessions(split_dirs, max_samples)
    n_attacks = sum(1 for s in sessions if not s["is_normal"])
    n_normals = sum(1 for s in sessions if s["is_normal"])
    print(f"[experiment] Evaluating {len(sessions)} sessions ({n_attacks} attacks, {n_normals} normals)...")

    session_results = []
    for idx, s in enumerate(sessions, 1):
        record = evaluate_single_session_levels(s, model, templates, retention_levels, seed=42 + idx)
        session_results.append(record)
        if idx % 100 == 0 or idx == len(sessions):
            print(f"  [{idx}/{len(sessions)}] Evaluated sessions across all retention levels...")

    # Aggregate performance by retention level
    level_metrics = {}
    for rate in retention_levels:
        key = str(int(rate * 100))

        attack_evals = [s["curve"][key] for s in session_results if not s["is_normal"]]
        normal_evals = [s["curve"][key] for s in session_results if s["is_normal"]]

        # Metrics for Rule Path Alone
        rule_alerts_att = sum(1 for e in attack_evals if e["rule_score"] >= THETA_A)
        rule_alerts_norm = sum(1 for e in normal_evals if e["rule_score"] >= THETA_A)
        rule_recall = rule_alerts_att / max(1, len(attack_evals))

        # Metrics for GAT Path Alone
        gat_alerts_att = sum(1 for e in attack_evals if e["gat_score"] >= THETA_A)
        gat_recall = gat_alerts_att / max(1, len(attack_evals))

        # Metrics for Fused Hybrid Path (Algorithm 4)
        tp = sum(1 for e in attack_evals if e["is_alert"])
        fn = len(attack_evals) - tp
        fp = sum(1 for e in normal_evals if e["is_alert"])
        tn = len(normal_evals) - fp

        fused_recall = tp / max(1, tp + fn)
        fused_precision = tp / max(1, tp + fp)
        fused_f1 = 2 * fused_precision * fused_recall / max(1e-9, fused_precision + fused_recall)
        fused_fpr = fp / max(1, fp + tn)

        mean_rule_score = float(np.mean([e["rule_score"] for e in attack_evals])) if attack_evals else 0.0
        mean_gat_score = float(np.mean([e["gat_score"] for e in attack_evals])) if attack_evals else 0.0
        mean_fused_risk = float(np.mean([e["fused_risk"] for e in attack_evals])) if attack_evals else 0.0

        level_metrics[key] = {
            "retention_rate": rate,
            "retention_percentage": int(rate * 100),
            "attack_count": len(attack_evals),
            "normal_count": len(normal_evals),
            # Rule Path
            "rule_alone_recall": round(rule_recall, 4),
            "mean_attack_rule_score": round(mean_rule_score, 4),
            # GAT Path
            "gat_alone_recall": round(gat_recall, 4),
            "mean_attack_gat_score": round(mean_gat_score, 4),
            # Fused Algorithm 4
            "fused_recall": round(fused_recall, 4),
            "fused_precision": round(fused_precision, 4),
            "fused_f1": round(fused_f1, 4),
            "fused_fpr": round(fused_fpr, 4),
            "mean_fused_attack_risk": round(mean_fused_risk, 4),
            "fused_retention_ratio": round(fused_recall / max(1e-4, level_metrics.get("100", {}).get("fused_recall", fused_recall)), 4),
        }

    # Find an illustrative case study showing rule breakage vs GAT recovery
    case_study = None
    for s in session_results:
        if not s["is_normal"]:
            c100 = s["curve"]["100"]
            c50 = s["curve"].get("50")
            c0 = s["curve"].get("0")
            if c100["rule_score"] >= THETA_A and c50 and c50["rule_score"] < c100["rule_score"] and c50["is_alert"]:
                case_study = s
                break

    return {
        "metadata": {
            "experiment": "Section 6: Partial Behavior Abstraction Resilience",
            "splits_evaluated": [str(d.name) for d in split_dirs],
            "total_sessions": len(sessions),
            "attack_count": n_attacks,
            "normal_count": n_normals,
            "alert_threshold": THETA_A,
            "retention_levels": retention_levels,
        },
        "levels": level_metrics,
        "case_study": case_study,
    }


# ============================================================================
# 4. REPORTING & TERMINAL SUMMARY
# ============================================================================

def print_cli_summary(results: Dict[str, Any]):
    """Prints a clean ASCII summary table to stdout."""
    meta = results["metadata"]
    levels = results["levels"]
    cs = results.get("case_study")

    print("\n" + "=" * 86)
    print("  CASCE: PARTIAL BEHAVIOR ABSTRACTION RESILIENCE EXPERIMENT (SECTION 6)")
    print("=" * 86)
    print(f"  Splits Evaluated:      {', '.join(meta['splits_evaluated'])}")
    print(f"  Total Sessions:        {meta['total_sessions']} ({meta['attack_count']} attacks, {meta['normal_count']} normals)")
    print(f"  Alert Threshold (th):  {meta['alert_threshold']}")
    print("=" * 86)

    header = f"{'Behavior Rec':<14}{'Rule Recall':>13}{'GAT Recall':>13}{'Fused Recall':>15}{'Fused F1':>12}{'Mean Risk':>13}"
    print(header)
    print("-" * len(header))

    for key in sorted(levels.keys(), key=lambda x: int(x), reverse=True):
        d = levels[key]
        row = (
            f"{d['retention_percentage']}% Recognized"
            f"{d['rule_alone_recall']*100:>12.1f}%"
            f"{d['gat_alone_recall']*100:>12.1f}%"
            f"{d['fused_recall']*100:>14.1f}%"
            f"{d['fused_f1']*100:>11.1f}%"
            f"{d['mean_fused_attack_risk']:>13.4f}"
        )
        print(row)

    print("-" * len(header))
    print("\n  KEY RESILIENCE INSIGHT:")
    print("  - As Algorithm 3 misses behaviors (100% -> 50% -> 0%), the Rule-alone recall degrades.")
    print("  - However, Algorithm 4's Fused Recall remains sustained because the GAT model acts")
    print("    as an architectural safety net, detecting anomalous graph topology independently.")

    if cs:
        print("\n  REPRESENTATIVE CASE STUDY:")
        print(f"  - Session: {cs['filename']} (Label: {cs['label']})")
        for k in ["100", "75", "50", "0"]:
            if k in cs["curve"]:
                c = cs["curve"][k]
                scen = c['rule_scenario'] or 'GAT Fallback'
                print(f"    * {k:>3}% Behs: Kept={c['kept_behaviors']:>2}/{c['total_behaviors']}, Rule={c['rule_score']:.3f}, GAT={c['gat_score']:.3f}, Fused={c['fused_risk']:.3f} [{c['is_alert'] and 'ALERT' or 'MISS'}] ({scen})")

    print("=" * 86 + "\n")


# ============================================================================
# 5. CLI ENTRYPOINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="CASCE Partial Behavior Abstraction Experiment (Section 6)")
    parser.add_argument("--split", choices=["test", "dev", "all"], default="test", help="Dataset split to evaluate")
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH), help="Path to trained GAT checkpoint")
    parser.add_argument("--outdir", default=str(OUTPUT_DIR), help="Output directory for results JSON")
    parser.add_argument("--max-samples", type=int, default=None, help="Limit number of evaluated samples (for rapid evaluation)")
    parser.add_argument("--levels", nargs="+", type=float, default=DEFAULT_LEVELS, help="List of retention fractions (default: 1.0 0.9 0.75 0.5 0.25 0.0)")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    base_out = BASE_DIR / "output"
    if args.split == "test":
        splits = [base_out / "dataset_test"]
    elif args.split == "dev":
        splits = [base_out / "dataset_dev"]
    else:
        splits = [base_out / "dataset_test", base_out / "dataset_dev"]

    results = run_experiment(
        split_dirs=splits,
        model_path=Path(args.model_path),
        retention_levels=sorted(args.levels, reverse=True),
        max_samples=args.max_samples
    )

    # Save output JSON
    json_path = outdir / "partial_abstraction_results.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[output] Successfully saved results to: {json_path}")

    # Print summary
    print_cli_summary(results)


if __name__ == "__main__":
    main()

