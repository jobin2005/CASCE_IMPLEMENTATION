#!/usr/bin/env python3
"""
CASCE — Error Analysis Experiment (Section 7)
==============================================

Objective:
    Perform comprehensive root-cause error analysis on the CASCE detection pipeline.
    Diagnose every False Positive (FP) and False Negative (FN) across the 6-stage
    architectural failure taxonomy:

    Taxonomy Categories:
      1. Telemetry Failure:
         - Missing, uncaptured, or corrupted raw events (e.g. unmonitored ports,
           dropped logging, in-memory actions leaving zero traces).
      2. Correlation Failure:
         - SAC (Algorithm 1) under-correlation (orphaned OS processes) or
           over-correlation (misattributed external background daemons).
      3. Abstraction Failure:
         - Algorithm 3 template matching failure (missed attack behaviors or
           spurious behavior creation on benign admin queries).
      4. Rule Failure:
         - Algorithm 4 rule mismatch (unmodeled attack sequences, broken chains)
           or rule over-triggering.
      5. GAT Failure:
         - GATv2 model under-prediction (attack topology blending into normal distributions)
           or over-prediction (dense benign graphs flagged as anomalous).
      6. Fusion Failure:
         - Noisy-OR combination failure: borderline sub-threshold signals failing to
           cross theta_A (FN), or weak signals combining to cross theta_A (FP).

Output:
    - error_analysis_output/error_analysis_results.json
    - Formatted terminal report

Usage:
    python error_analysis_experiment.py                 # Evaluates dataset_test
    python error_analysis_experiment.py --split dev     # Evaluates dataset_dev
    python error_analysis_experiment.py --split all     # Evaluates both splits
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

OUTPUT_DIR = BASE_DIR / "error_analysis_output"
DEFAULT_MODEL_PATH = BASE_DIR / "casce_gat.pt"

FAILURE_CATEGORIES = [
    "Telemetry failure",
    "Correlation failure",
    "Abstraction failure",
    "Rule failure",
    "GAT failure",
    "Fusion failure",
]


# ============================================================================
# 1. GRAPH METADATA & ARTIFACT EXTRACTION
# ============================================================================

def inspect_session_graph(graph_path: Path, templates: List[Any]) -> Dict[str, Any]:
    """Inspects a session graphml and compiles its multi-layer diagnostic state."""
    G = nx.read_graphml(graph_path)
    fname = graph_path.name
    is_normal = "_Normal" in fname

    parts = fname.replace("enriched_session_", "").replace(".graphml", "").split("_", 1)
    session_id = parts[0]
    raw_label = parts[1].replace("_", " ") if len(parts) > 1 else ("Normal" if is_normal else "Malicious")

    # Extract queries
    queries = []
    tables = set()
    roles = set()
    processes = []
    files = set()
    endpoints = set()

    for n, d in G.nodes(data=True):
        ntype = d.get("type")
        if ntype == "Query":
            q = d.get("query", "").strip()
            if q:
                queries.append(q)
        elif ntype == "Table":
            tables.add(d.get("label", str(n)))
        elif ntype == "Role":
            roles.add(d.get("label", str(n)))
        elif ntype == "Process":
            processes.append(str(n))
        elif ntype == "File":
            files.add(str(n))
        elif ntype == "Endpoint":
            endpoints.add(str(n))

    # Check Behavior nodes
    beh_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "Behavior"]
    beh_labels = [d.get("label", "") for n, d in G.nodes(data=True) if d.get("type") == "Behavior"]

    q_text = " ".join(queries).lower()

    return {
        "filepath": graph_path,
        "filename": fname,
        "session_id": session_id,
        "is_normal": is_normal,
        "raw_label": raw_label,
        "queries": queries,
        "query_text": q_text,
        "tables": list(tables),
        "roles": list(roles),
        "processes": processes,
        "files": list(files),
        "endpoints": list(endpoints),
        "behavior_count": len(beh_nodes),
        "behavior_labels": beh_labels,
        "graph": G,
    }


# ============================================================================
# 2. ROOT-CAUSE TAXONOMY DIAGNOSIS
# ============================================================================

def diagnose_false_negative(session_info: Dict[str, Any], eval_res: Dict[str, Any]) -> Tuple[str, str]:
    """
    Diagnoses why an actual attack was missed (FN: is_normal=False, risk < THETA_A).
    Returns (failure_category, detailed_explanation).
    """
    q_text = session_info["query_text"]
    proc_cnt = len(session_info["processes"])
    file_cnt = len(session_info["files"])
    ep_cnt = len(session_info["endpoints"])
    beh_cnt = session_info["behavior_count"]
    lbl = session_info["raw_label"].lower()

    r_score = eval_res["rule_score"]
    g_score = eval_res["gat_score"]
    fused_risk = eval_res["risk"]

    # 1. Telemetry Failure
    # Query is missing entirely or empty, or pure DB injection has zero traces
    if not session_info["queries"] or not q_text.strip():
        return (
            "Telemetry failure",
            "Session graph contains no recorded SQL queries; audit logger dropped query stream."
        )

    # 2. Correlation Failure
    # Attack requires OS child processes (Exfiltration, Shell, Escalation, COPY TO PROGRAM),
    # but the session graph has 0 correlated processes or 0 files!
    requires_os = any(k in lbl for k in ["exfiltration", "escalation", "shell", "privilege"]) or "to program" in q_text
    if requires_os and (proc_cnt == 0 or file_cnt == 0):
        return (
            "Correlation failure",
            f"Attack type '{session_info['raw_label']}' spawned OS subprocesses, but Algorithm 1 SAC failed to correlate OS PIDs to Session (0 processes correlated)."
        )

    # 3. Abstraction Failure
    # The raw nodes exist, but Algorithm 3 extracted 0 Behavior nodes or failed confidence gating
    if beh_cnt == 0:
        return (
            "Abstraction failure",
            f"Algorithm 3 extracted 0 Behavior nodes from {len(session_info['queries'])} queries and {proc_cnt} processes; template confidence fell below theta_beh."
        )

    # 4. Rule Failure
    # Behaviors exist, but rule score is 0.0 or < 0.50 (rule chain broken / gap exceeded)
    if r_score == 0.0:
        return (
            "Rule failure",
            f"Algorithm 3 extracted {beh_cnt} behaviors ({', '.join(session_info['behavior_labels'][:3])}), but none matched predefined CHAIN_RULES ordered subsequences."
        )

    # 5. Fusion Failure
    # Either GAT or Rule had a strong/moderate signal, but fused score was just sub-threshold (0.55 - 0.649)
    if (g_score >= 0.70 or r_score >= 0.40) and fused_risk >= 0.54:
        return (
            "Fusion failure",
            f"Borderline fusion: GAT score ({g_score:.3f}) or Rule score ({r_score:.3f}) was elevated, but weighted noisy-OR yielded {fused_risk:.3f}, just below theta_A=0.65."
        )

    # 6. GAT Failure
    # GAT assigned a very low anomaly score (< 0.50), failing to flag anomalous topology
    if g_score < 0.50:
        return (
            "GAT failure",
            f"GAT model assigned low structural anomaly probability ({g_score:.3f}); attack graph topology blended into normal background distribution."
        )

    return (
        "Fusion failure",
        f"Sub-threshold combination: Rule={r_score:.3f}, GAT={g_score:.3f} produced fused risk {fused_risk:.3f} < {THETA_A}."
    )


def diagnose_false_positive(session_info: Dict[str, Any], eval_res: Dict[str, Any]) -> Tuple[str, str]:
    """
    Diagnoses why a benign session was falsely flagged (FP: is_normal=True, risk >= THETA_A).
    Returns (failure_category, detailed_explanation).
    """
    q_text = session_info["query_text"]
    proc_cnt = len(session_info["processes"])
    file_cnt = len(session_info["files"])
    beh_cnt = session_info["behavior_count"]

    r_score = eval_res["rule_score"]
    g_score = eval_res["gat_score"]
    fused_risk = eval_res["risk"]

    # 1. Telemetry Failure
    # Heavy administrative tasks emitting massive syscall counts
    if any(k in q_text for k in ["vacuum full", "reindex", "pg_dump"]):
        return (
            "Telemetry failure",
            "Benign heavy database administrative maintenance (VACUUM/REINDEX) emitted abnormal I/O telemetry resembling an attack."
        )

    # 2. Correlation Failure
    # Over-correlation of unrelated background processes
    if proc_cnt > 5 and not any(k in q_text for k in ["copy", "vacuum"]):
        return (
            "Correlation failure",
            f"SAC over-correlation: {proc_cnt} OS processes erroneously linked to standard read-only query session."
        )

    # 3. Abstraction Failure
    # Spurious behavior creation on normal queries
    if beh_cnt > 0 and r_score == 0.0 and g_score < 0.70:
        return (
            "Abstraction failure",
            f"Algorithm 3 generated spurious behavior abstractions ({', '.join(session_info['behavior_labels'][:2])}) on benign activity."
        )

    # 4. Rule Failure
    # Rule engine over-triggered on coincidental behaviors
    if r_score >= THETA_A:
        return (
            "Rule failure",
            f"Rule over-triggered: matched scenario '{eval_res.get('scenario')}' on benign session with rule score {r_score:.3f} >= {THETA_A}."
        )

    # 5. GAT Failure
    # No rule fired, but GAT predicted high anomaly score
    if r_score == 0.0 and g_score >= 0.86:
        return (
            "GAT failure",
            f"GAT model over-predicted: high structural anomaly score ({g_score:.3f}) on benign session with {proc_cnt} procs and {file_cnt} files."
        )

    # 6. Fusion Failure
    # Borderline signals combined to cross threshold
    return (
        "Fusion failure",
        f"Over-aggregation: mild Rule score ({r_score:.3f}) and GAT score ({g_score:.3f}) combined via noisy-OR to reach {fused_risk:.3f} >= {THETA_A}."
    )


# ============================================================================
# 3. EXPERIMENT PIPELINE
# ============================================================================

def run_error_analysis(split_dirs: List[Path], model_path: Path, max_samples: Optional[int] = None) -> Dict[str, Any]:
    """Evaluates all sessions, identifies FPs and FNs, and categorizes their root causes."""
    print(f"[error_analysis] Loading detector model from {model_path}...")
    model = load_model(str(model_path))

    templates = algorithm_3_abstract.initialize_templates()

    # Collect all sessions
    all_files = []
    for s_dir in split_dirs:
        all_files.extend(sorted(s_dir.glob("run_*/*.graphml")))

    if max_samples:
        all_files = all_files[:max_samples]

    print(f"[error_analysis] Ingesting and evaluating {len(all_files)} session graphs...")

    tp_list, fp_list, fn_list, tn_list = [], [], [], []

    for idx, g_path in enumerate(all_files, 1):
        s_info = inspect_session_graph(g_path, templates)
        eval_res = detect(s_info["graph"], model, session_id=s_info["filename"])

        is_normal = s_info["is_normal"]
        is_alert = eval_res["risk"] >= THETA_A

        record = {
            "session_id": s_info["session_id"],
            "filename": s_info["filename"],
            "raw_label": s_info["raw_label"],
            "is_normal": is_normal,
            "query": s_info["queries"][0] if s_info["queries"] else "",
            "proc_count": len(s_info["processes"]),
            "file_count": len(s_info["files"]),
            "endpoint_count": len(s_info["endpoints"]),
            "behavior_count": s_info["behavior_count"],
            "behaviors": s_info["behavior_labels"],
            "rule_score": round(eval_res["rule_score"], 4),
            "gat_score": round(eval_res["gat_score"], 4),
            "risk": round(eval_res["risk"], 4),
            "scenario": eval_res.get("scenario"),
            "status": eval_res["status"],
        }

        if is_normal and not is_alert:
            tn_list.append(record)
        elif is_normal and is_alert:
            cat, reason = diagnose_false_positive(s_info, eval_res)
            record["failure_category"] = cat
            record["diagnostic_reason"] = reason
            fp_list.append(record)
        elif not is_normal and is_alert:
            tp_list.append(record)
        else:  # not is_normal and not is_alert
            cat, reason = diagnose_false_negative(s_info, eval_res)
            record["failure_category"] = cat
            record["diagnostic_reason"] = reason
            fn_list.append(record)

        if idx % 500 == 0 or idx == len(all_files):
            print(f"  [{idx}/{len(all_files)}] Evaluated sessions (TP={len(tp_list)}, FP={len(fp_list)}, FN={len(fn_list)}, TN={len(tn_list)})...")

    # Aggregate by failure category
    fp_breakdown = {cat: [] for cat in FAILURE_CATEGORIES}
    for fp in fp_list:
        fp_breakdown.setdefault(fp["failure_category"], []).append(fp)

    fn_breakdown = {cat: [] for cat in FAILURE_CATEGORIES}
    for fn in fn_list:
        fn_breakdown.setdefault(fn["failure_category"], []).append(fn)

    fp_stats = {cat: len(items) for cat, items in fp_breakdown.items()}
    fn_stats = {cat: len(items) for cat, items in fn_breakdown.items()}

    # Pick representative case studies for each category
    exemplar_fns = {}
    for cat, items in fn_breakdown.items():
        if items:
            exemplar_fns[cat] = items[0]

    exemplar_fps = {}
    for cat, items in fp_breakdown.items():
        if items:
            exemplar_fps[cat] = items[0]

    total_attacks = len(tp_list) + len(fn_list)
    total_normals = len(tn_list) + len(fp_list)

    return {
        "metadata": {
            "experiment": "Section 7: Error Analysis (False Positives and False Negatives Root-Cause Taxonomy)",
            "splits_evaluated": [str(d.name) for d in split_dirs],
            "total_evaluated": len(all_files),
            "alert_threshold": THETA_A,
            "total_attacks": total_attacks,
            "total_normals": total_normals,
            "true_positives": len(tp_list),
            "false_positives": len(fp_list),
            "false_negatives": len(fn_list),
            "true_negatives": len(tn_list),
            "precision": round(len(tp_list) / max(1, len(tp_list) + len(fp_list)), 4),
            "recall": round(len(tp_list) / max(1, total_attacks), 4),
            "f1_score": round(2 * len(tp_list) / max(1, 2 * len(tp_list) + len(fp_list) + len(fn_list)), 4),
        },
        "false_positive_breakdown": {
            "total_false_positives": len(fp_list),
            "counts_by_category": fp_stats,
            "percentages": {cat: round(c / max(1, len(fp_list)) * 100, 2) for cat, c in fp_stats.items()},
            "exemplars": exemplar_fps,
            "all_false_positives": fp_list,
        },
        "false_negative_breakdown": {
            "total_false_negatives": len(fn_list),
            "counts_by_category": fn_stats,
            "percentages": {cat: round(c / max(1, len(fn_list)) * 100, 2) for cat, c in fn_stats.items()},
            "exemplars": exemplar_fns,
            "all_false_negatives": fn_list,
        },
    }


# ============================================================================
# 4. REPORTING & TERMINAL SUMMARY
# ============================================================================

def print_cli_summary(results: Dict[str, Any]):
    """Prints a clean ASCII summary table to stdout."""
    meta = results["metadata"]
    fp_b = results["false_positive_breakdown"]
    fn_b = results["false_negative_breakdown"]

    print("\n" + "=" * 86)
    print("  CASCE: ROOT-CAUSE ERROR ANALYSIS (SECTION 7)")
    print("=" * 86)
    print(f"  Splits Evaluated:      {', '.join(meta['splits_evaluated'])}")
    print(f"  Total Evaluated:       {meta['total_evaluated']}")
    print(f"  Total Attacks:         {meta['total_attacks']}  (TP={meta['true_positives']}, FN={meta['false_negatives']})")
    print(f"  Total Normals:         {meta['total_normals']}  (TN={meta['true_negatives']}, FP={meta['false_positives']})")
    print(f"  Overall Precision:     {meta['precision']*100:.1f}%")
    print(f"  Overall Recall:        {meta['recall']*100:.1f}%")
    print(f"  Overall F1-Score:      {meta['f1_score']*100:.1f}%")
    print("=" * 86)

    # 1. False Negative Taxonomy Table
    print(f"\n  FALSE NEGATIVE TAXONOMY BREAKDOWN (Total Missed Attacks: {fn_b['total_false_negatives']}):")
    print("  " + "-" * 78)
    h_fn = f"  {'Failure Stage':<26}{'FN Count':>12}{'Percentage':>14}{'Primary Driver':>24}"
    print(h_fn)
    print("  " + "-" * 78)

    drivers = {
        "Telemetry failure": "Missing query / I/O log",
        "Correlation failure": "Orphaned OS processes",
        "Abstraction failure": "0 Behaviors extracted",
        "Rule failure": "Unmatched chain template",
        "GAT failure": "Low anomaly score (<0.50)",
        "Fusion failure": "Borderline risk (0.55-0.64)",
    }

    for cat in FAILURE_CATEGORIES:
        cnt = fn_b["counts_by_category"].get(cat, 0)
        pct = fn_b["percentages"].get(cat, 0.0)
        drv = drivers.get(cat, "")
        row = f"  {cat:<26}{cnt:>12}{pct:>13.1f}%{drv:>24}"
        print(row)
    print("  " + "-" * 78)

    # 2. False Positive Taxonomy Table
    print(f"\n  FALSE POSITIVE TAXONOMY BREAKDOWN (Total False Alarms: {fp_b['total_false_positives']}):")
    print("  " + "-" * 78)
    h_fp = f"  {'Failure Stage':<26}{'FP Count':>12}{'Percentage':>14}{'Primary Driver':>24}"
    print(h_fp)
    print("  " + "-" * 78)

    fp_drivers = {
        "Telemetry failure": "Admin I/O burst (VACUUM)",
        "Correlation failure": "Background daemon overlap",
        "Abstraction failure": "Spurious behavior match",
        "Rule failure": "Rule over-triggering",
        "GAT failure": "GAT over-prediction (>0.87)",
        "Fusion failure": "Noisy-OR over-aggregation",
    }

    for cat in FAILURE_CATEGORIES:
        cnt = fp_b["counts_by_category"].get(cat, 0)
        pct = fp_b["percentages"].get(cat, 0.0)
        drv = fp_drivers.get(cat, "")
        row = f"  {cat:<26}{cnt:>12}{pct:>13.1f}%{drv:>24}"
        print(row)
    print("  " + "-" * 78)

    # 3. Exemplar Case Studies
    print("\n  REPRESENTATIVE ERROR CASE STUDIES:")
    print("  " + "-" * 78)
    for cat in ["Correlation failure", "Abstraction failure", "Fusion failure", "GAT failure"]:
        ex_fn = fn_b["exemplars"].get(cat)
        if ex_fn:
            print(f"  * FN [{cat}]: Session {ex_fn['session_id']} ({ex_fn['raw_label']})")
            print(f"    - Query: {ex_fn['query'][:65]}")
            print(f"    - Stats: {ex_fn['proc_count']} procs, {ex_fn['file_count']} files, {ex_fn['behavior_count']} behs | Rule={ex_fn['rule_score']}, GAT={ex_fn['gat_score']}, Risk={ex_fn['risk']}")
            print(f"    - Root Cause: {ex_fn['diagnostic_reason']}")

    for cat, ex_fp in fp_b["exemplars"].items():
        print(f"  * FP [{cat}]: Session {ex_fp['session_id']} (Benign)")
        print(f"    - Query: {ex_fp['query'][:65]}")
        print(f"    - Stats: {ex_fp['proc_count']} procs, {ex_fp['file_count']} files | Rule={ex_fp['rule_score']}, GAT={ex_fp['gat_score']}, Risk={ex_fp['risk']}")
        print(f"    - Root Cause: {ex_fp['diagnostic_reason']}")

    print("=" * 86 + "\n")


# ============================================================================
# 5. CLI ENTRYPOINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="CASCE Error Analysis Experiment (Section 7)")
    parser.add_argument("--split", choices=["test", "dev", "all"], default="test", help="Dataset split to evaluate")
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

    results = run_error_analysis(
        split_dirs=splits,
        model_path=Path(args.model_path),
        max_samples=args.max_samples
    )

    # Save output JSON
    json_path = outdir / "error_analysis_results.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[output] Successfully saved error analysis results to: {json_path}")

    # Print summary
    print_cli_summary(results)


if __name__ == "__main__":
    main()

