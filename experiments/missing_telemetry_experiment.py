#!/usr/bin/env python3
"""
CASCE — Missing Telemetry Resilience Experiment (Section 5)
============================================================

Objective:
    Evaluate the resilience of the CASCE cross-layer detection pipeline under
    varying levels of telemetry loss / dropped events. In production environments,
    telemetry frequently experiences packet loss, ring buffer drops, or deliberate
    attacker impairment.

Evaluated Retention Levels:
    - 100% (Full baseline telemetry)
    - 90%  (Light loss: typical network jitter / logging buffer drops)
    - 75%  (Moderate loss: high-load kernel ring buffer overflow)
    - 50%  (Heavy loss: severe throttling or aggressive attacker evasion)
    - 25%  (Critical loss: fragmentary telemetry)

Evaluated Telemetry Modalities:
    1. Missing DB Events:
       - Drops Query, Table, and Role nodes and their associated edges (executes, accesses).
       - Simulates database audit log drops, log_statement suppression, or sampled query logging.
    2. Missing eBPF Events:
       - Drops Process and File nodes and their associated edges (spawns, opens).
       - Simulates eBPF perf ring buffer overflow under heavy I/O workloads.
    3. Missing Network Events:
       - Drops Endpoint nodes and connects_to edges.
       - Simulates unmonitored egress interfaces, socket tap drops, or packet loss.
    4. Combined / Uniform Telemetry Loss:
       - Uniformly drops events across all non-anchor layers simultaneously.

Output:
    - missing_telemetry_output/missing_telemetry_results.json
    - Formatted ASCII summary table printed to stdout

Usage:
    python missing_telemetry_experiment.py                # Evaluates dataset_test across all modalities
    python missing_telemetry_experiment.py --split dev    # Evaluates dataset_dev
    python missing_telemetry_experiment.py --modality db  # Evaluates missing DB telemetry only
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

from algorithm_4_hybrid import (
    detect, load_model, THETA_A, THETA_R, TORCH_AVAILABLE
)

OUTPUT_DIR = BASE_DIR / "missing_telemetry_output"
DEFAULT_MODEL_PATH = BASE_DIR / "casce_gat.pt"

RETENTION_LEVELS = [1.0, 0.90, 0.75, 0.50, 0.25]
MODALITIES = ["db", "ebpf", "network", "all"]


# ============================================================================
# 1. GRAPH DEGRADATION & TELEMETRY DROPPING LOGIC
# ============================================================================

def get_modality_node_types(modality: str) -> set:
    """Returns the set of node types corresponding to the target telemetry modality."""
    if modality == "db":
        return {"Query", "Table", "Role"}
    elif modality == "ebpf":
        return {"Process", "File"}
    elif modality == "network":
        return {"Endpoint"}
    elif modality == "all":
        return {"Query", "Table", "Role", "Process", "File", "Endpoint"}
    else:
        raise ValueError(f"Unknown modality: {modality}")


def degrade_graph(G: nx.Graph, modality: str, retention_rate: float, rng: np.random.Generator) -> nx.Graph:
    """
    Simulates telemetry event loss by dropping nodes belonging to the target modality
    at the given retention rate.
    """
    if retention_rate >= 1.0:
        return G.copy()

    target_types = get_modality_node_types(modality)
    candidate_nodes = [n for n, d in G.nodes(data=True) if d.get("type") in target_types]

    if not candidate_nodes:
        return G.copy()

    # Determine how many candidate nodes to keep
    k_keep = int(math.ceil(len(candidate_nodes) * retention_rate))
    if k_keep < len(candidate_nodes):
        kept_candidates = set(rng.choice(candidate_nodes, size=k_keep, replace=False))
        dropped_candidates = set(candidate_nodes) - kept_candidates
    else:
        dropped_candidates = set()

    # Also drop Behavior nodes if their supporting evidence was lost
    # (Algorithm 4 rules evaluate evidence_for edges)
    dropped_nodes = set(dropped_candidates)

    remaining_nodes = [n for n in G.nodes() if n not in dropped_nodes]
    return G.subgraph(remaining_nodes).copy()


# ============================================================================
# 2. DATASET INGESTION & BATCH EVALUATION
# ============================================================================

def load_session_metadata(split_dirs: List[Path], max_samples: Optional[int] = None) -> List[Dict[str, Any]]:
    """Crawls split directories to catalog session graphs."""
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
        # Keep balanced sample
        attacks = [s for s in sessions if not s["is_normal"]]
        normals = [s for s in sessions if s["is_normal"]]
        n_att = max_samples // 2
        n_norm = max_samples - n_att
        sessions = attacks[:n_att] + normals[:n_norm]

    return sessions


def evaluate_telemetry_step(
    sessions: List[Dict[str, Any]],
    model: Any,
    modality: str,
    retention_rate: float,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Evaluates detection performance on all sessions under a specific
    telemetry retention rate.
    """
    rng = np.random.default_rng(seed)
    y_true, y_pred, y_scores = [], [], []

    attack_scores = []
    normal_scores = []

    for s in sessions:
        G_raw = nx.read_graphml(s["filepath"])
        G_degraded = degrade_graph(G_raw, modality, retention_rate, rng)

        res = detect(G_degraded, model, session_id=s["filename"])
        is_attack = 0 if s["is_normal"] else 1
        is_alert = 1 if res["risk"] >= THETA_A else 0

        y_true.append(is_attack)
        y_pred.append(is_alert)
        y_scores.append(res["risk"])

        if is_attack:
            attack_scores.append(res["risk"])
        else:
            normal_scores.append(res["risk"])

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    total_attacks = max(1, tp + fn)
    total_normals = max(1, tn + fp)

    recall = tp / total_attacks
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    fpr = fp / total_normals
    accuracy = (tp + tn) / max(1, len(sessions))

    return {
        "retention_rate": retention_rate,
        "retention_percentage": int(retention_rate * 100),
        "total_sessions": len(sessions),
        "attack_count": total_attacks,
        "normal_count": total_normals,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "mean_attack_risk": round(float(np.mean(attack_scores)), 4) if attack_scores else 0.0,
        "mean_normal_risk": round(float(np.mean(normal_scores)), 4) if normal_scores else 0.0,
    }


# ============================================================================
# 3. EXPERIMENT SUITE RUNNER
# ============================================================================

def run_experiment(
    split_dirs: List[Path],
    model_path: Path,
    modalities: List[str],
    retention_levels: List[float],
    max_samples: Optional[int] = None
) -> Dict[str, Any]:
    """Runs the missing telemetry degradation benchmarks across requested modalities."""
    print(f"[experiment] Loading GAT detector from {model_path}...")
    model = load_model(str(model_path))

    sessions = load_session_metadata(split_dirs, max_samples)
    n_attacks = sum(1 for s in sessions if not s["is_normal"])
    n_normals = sum(1 for s in sessions if s["is_normal"])
    print(f"[experiment] Ingested {len(sessions)} sessions ({n_attacks} attacks, {n_normals} normals) across {len(split_dirs)} split(s).")

    results_by_modality = {}

    for mod in modalities:
        print(f"\n[{mod.upper()}] Evaluating missing telemetry curve across {len(retention_levels)} retention levels...")
        mod_curve = []

        baseline_f1 = None
        for r_level in retention_levels:
            metrics = evaluate_telemetry_step(sessions, model, mod, r_level)
            if r_level == 1.0:
                baseline_f1 = metrics["f1_score"]
                metrics["f1_retention_ratio"] = 1.0
            else:
                metrics["f1_retention_ratio"] = round(metrics["f1_score"] / max(1e-4, baseline_f1), 4)

            mod_curve.append(metrics)
            print(f"  Level {int(r_level*100):>3}%: Recall={metrics['recall']*100:>5.1f}%, Precision={metrics['precision']*100:>5.1f}%, F1={metrics['f1_score']*100:>5.1f}%, FPR={metrics['fpr']*100:>5.2f}%")

        results_by_modality[mod] = {
            "modality_name": mod,
            "description": f"Event loss targeted at {mod.upper()} telemetry layer",
            "curve": mod_curve,
        }

    return {
        "metadata": {
            "experiment": "Section 5: Missing Telemetry Resilience Evaluation",
            "splits_evaluated": [str(d.name) for d in split_dirs],
            "total_sessions": len(sessions),
            "attack_count": n_attacks,
            "normal_count": n_normals,
            "alert_threshold": THETA_A,
            "retention_levels": retention_levels,
            "modalities_evaluated": modalities,
        },
        "modality_results": results_by_modality,
    }


# ============================================================================
# 4. REPORTING & TERMINAL SUMMARY
# ============================================================================

def print_cli_summary(results: Dict[str, Any]):
    """Prints a clean ASCII summary table to stdout."""
    meta = results["metadata"]
    mod_results = results["modality_results"]

    print("\n" + "=" * 84)
    print("  CASCE: MISSING TELEMETRY RESILIENCE EXPERIMENT (SECTION 5)")
    print("=" * 84)
    print(f"  Splits:            {', '.join(meta['splits_evaluated'])}")
    print(f"  Total Sessions:    {meta['total_sessions']} ({meta['attack_count']} attacks, {meta['normal_count']} normals)")
    print(f"  Alert Threshold:   {meta['alert_threshold']}")
    print("=" * 84)

    for mod, data in mod_results.items():
        print(f"\n  MODALITY: {mod.upper()} TELEMETRY LOSS")
        print("  " + "-" * 78)
        header = f"  {'Retention':<12}{'Recall':>10}{'Precision':>12}{'F1-Score':>12}{'FPR':>10}{'F1 Retained':>15}"
        print(header)
        print("  " + "-" * 78)

        for step in data["curve"]:
            row = (
                f"  {step['retention_percentage']}% Telemetry"
                f"{step['recall']*100:>9.1f}%"
                f"{step['precision']*100:>11.1f}%"
                f"{step['f1_score']*100:>11.1f}%"
                f"{step['fpr']*100:>9.2f}%"
                f"{step['f1_retention_ratio']*100:>14.1f}%"
            )
            print(row)
        print("  " + "-" * 78)

    print("\n" + "=" * 84 + "\n")


# ============================================================================
# 5. CLI ENTRYPOINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="CASCE Missing Telemetry Resilience Experiment (Section 5)")
    parser.add_argument("--split", choices=["test", "dev", "all"], default="test", help="Dataset split to evaluate")
    parser.add_argument("--modality", choices=["all_modalities", "db", "ebpf", "network", "all"], default="all_modalities", help="Specific telemetry modality to test (default: test all)")
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH), help="Path to trained GAT checkpoint")
    parser.add_argument("--outdir", default=str(OUTPUT_DIR), help="Output directory for results JSON")
    parser.add_argument("--max-samples", type=int, default=None, help="Limit number of evaluated samples (for rapid verification)")
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

    if args.modality == "all_modalities":
        selected_modalities = MODALITIES
    else:
        selected_modalities = [args.modality]

    results = run_experiment(
        split_dirs=splits,
        model_path=Path(args.model_path),
        modalities=selected_modalities,
        retention_levels=RETENTION_LEVELS,
        max_samples=args.max_samples
    )

    # Save output JSON
    json_path = outdir / "missing_telemetry_results.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[output] Successfully saved missing telemetry results to: {json_path}")

    # Print summary table
    print_cli_summary(results)


if __name__ == "__main__":
    main()

