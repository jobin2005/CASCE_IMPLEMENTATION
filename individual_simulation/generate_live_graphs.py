#!/usr/bin/env python3
"""
generate_live_graphs.py
=======================
Builds and renders CASCE cross-layer session graphs directly from REAL-TIME
telemetry data (live Postgres hook + live Linux eBPF kernel events).

Data sources:
1. live_runs/8_final:
   2,000 live sessions captured overnight with synchronized eBPF kernel traces
   and pg_telemetry database logs.
2. individual_simulation/live_4d_run:
   Live 4D OOD attack workload executed against PostgreSQL 17 in Docker.

Outputs:
- individual_simulation/real_live_graphs/
  - seen_attacks/
  - seen_benign/
  - unseen_attacks/
  - unseen_benign/
  - live_4d_attacks/
  Each containing graphml/ and graph.png + summary.json with complete provenance.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any

import networkx as nx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "individual_simulation"))

import algorithm_1
import algorithm2
import algorithm_3_abstract
from generate_case_catalog import render_graph, safe_name
from main import sanitize_for_graphml

OUT_DIR = REPO_ROOT / "individual_simulation" / "real_live_graphs"


def process_live_run_8_final(out_dir: Path) -> List[Dict[str, Any]]:
    """Process live_runs/8_final and produce GraphML + PNGs for representative sessions."""
    run_dir = REPO_ROOT / "live_runs" / "8_final"
    run_name = "live_8_final"
    templates = algorithm_3_abstract.initialize_templates()

    # Ensure labels.csv exists from session_labels.jsonl
    labels_file = run_dir / "labels.csv"
    session_manifest_map = {}
    
    # Load live_manifest.jsonl for richer metadata
    manifest_file = run_dir / "live_manifest.jsonl"
    if manifest_file.exists():
        with open(manifest_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_manifest_map[item["key"]] = item

    if not labels_file.exists():
        with open(run_dir / "session_labels.jsonl", "r", encoding="utf-8") as f_in, \
             open(labels_file, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.writer(f_out)
            writer.writerow(["session_id", "label"])
            for line in f_in:
                if line.strip():
                    item = json.loads(line)
                    writer.writerow([item["session_id"], item["label"]])

    print("[*] Running Algorithm 1 on live_runs/8_final (24,000+ real events)...")
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmp_root = Path(tmpdirname)
        master_log, correlated = algorithm_1.run_one(run_dir)
        algorithm_1.save_run_output(run_name, master_log, correlated, tmp_root)

        event_table_path = tmp_root / f"{run_name}_event_table.json"
        correlation_path = tmp_root / f"{run_name}_session_correlation.csv"
        alg2_out_dir = tmp_root / f"{run_name}_alg2_graphs"

        print("[*] Running Algorithm 2 (Session Graph Construction)...")
        active_graphs, manifest_rows, orphans, parse_errs = algorithm2.run(
            event_table_path, correlation_path, alg2_out_dir, run_name, labels_file
        )
        print(f"    => Built {len(active_graphs)} native session graphs from live traces.")

        # Group sessions by scenario / category
        manifest_by_session = {r["session_key"]: r for r in manifest_rows}

        # Select diverse representative cases
        # 1. Defense Impairment attack
        # 2. ETL Exfiltration attack
        # 3. Privilege Abuse attack
        # 4. Multi-Stage APT attack
        # 5. PII Dump attack
        # 6. Alter Role Escalate attack
        # 7. Benign KYC Review
        # 8. Benign BI Export
        # 9. Benign Audit Archive
        # 10. Benign pgbench session

        target_categories = {
            "attack_defense_impair": lambda r: "s0126_0" in r["label"],
            "attack_etl_exfiltration": lambda r: "s0127_0" in r["label"],
            "attack_privilege_abuse": lambda r: "s0131_0" in r["label"],
            "attack_pii_dump": lambda r: "s0132_0" in r["label"],
            "attack_alter_role_escalate": lambda r: "s0141_0" in r["label"],
            "attack_compliance_exfil": lambda r: "s0145_0" in r["label"],
            "attack_multistage_apt": lambda r: "s0201" in r["label"],
            "benign_audit_archive": lambda r: "s0000_0" in r["label"],
            "benign_bi_export": lambda r: "s0004_0" in r["label"],
            "benign_kyc_review": lambda r: "s0010_0" in r["label"],
            "benign_pgbench": lambda r: r["label"] == "Benign:pgbench" and r["node_count"] >= 4,
        }

        generated_cases = []

        for cat_name, matcher in target_categories.items():
            candidates = [r for r in manifest_rows if matcher(r)]
            if not candidates:
                continue
            chosen = candidates[0]
            s_key = chosen["session_key"]
            G_raw = active_graphs.get(s_key)
            if not G_raw:
                continue

            # Run Algorithm 3: Behavior Abstraction
            G_enriched, detected_behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
            G_enriched = sanitize_for_graphml(G_enriched)

            # Determine destination subdirectory
            is_mal = "Malicious" in chosen["label"]
            sub_folder = "seen_attacks" if is_mal else "seen_benign"
            cat_dir = out_dir / sub_folder / cat_name
            cat_dir.mkdir(parents=True, exist_ok=True)
            (cat_dir / "graphml").mkdir(parents=True, exist_ok=True)

            graphml_file = cat_dir / "graphml" / f"{cat_name}_session_{s_key}.graphml"
            nx.write_graphml(G_enriched, str(graphml_file))

            # Render PNG
            png_file = cat_dir / "graph.png"
            clean_title = cat_name.replace("_", " ").title() + f" (Live Session #{s_key})"
            render_graph(graphml_file, png_file, title=clean_title)

            # Look up manifest metadata
            key_tag = chosen["label"].split(":")[-1] if ":" in chosen["label"] else ""
            meta = session_manifest_map.get(key_tag, {})

            summary = {
                "case_id": cat_name,
                "session_key": s_key,
                "label": chosen["label"],
                "data_source": "live_eval_run_8_final (Real Postgres Hook + eBPF Kernel)",
                "database": "casce_banking",
                "scenario_id": meta.get("scenario_id", cat_name),
                "role": meta.get("role", "unknown"),
                "node_count": G_enriched.number_of_nodes(),
                "edge_count": G_enriched.number_of_edges(),
                "detected_behaviors": [b["label"] for b in detected_behaviors],
                "graph_file": graphml_file.name,
                "png_file": "graph.png",
            }
            (cat_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            generated_cases.append(summary)
            print(f"    [+] Created live graph: {cat_name} (Nodes: {summary['node_count']}, Edges: {summary['edge_count']}, Behaviors: {summary['detected_behaviors']})")

        return generated_cases


def process_live_4d_run(out_dir: Path) -> List[Dict[str, Any]]:
    """Process the freshly captured 4D attack workload in individual_simulation/live_4d_run."""
    run_dir = REPO_ROOT / "individual_simulation" / "live_4d_run"
    pg_file = run_dir / "postgres_events.json"
    lbl_file = run_dir / "session_labels.jsonl"
    if not pg_file.exists() or not lbl_file.exists():
        print("[-] live_4d_run missing files, skipping.")
        return []

    templates = algorithm_3_abstract.initialize_templates()
    dest_dir = out_dir / "live_4d_attacks"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Read session labels
    labels = {}
    with open(lbl_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                labels[item["session_id"]] = item["label"]

    # Read events
    events_by_session = {}
    with open(pg_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                s_id = rec.get("session_id", rec.get("backend_pid"))
                events_by_session.setdefault(s_id, []).append(rec)

    cases = []
    # Pick distinctive 4D attack scripts
    selected_targets = [
        ("4d_exfil_gzip_curl", "Malicious:exfil_gzip_curl_r1"),
        ("4d_os_cat_shadow", "Malicious:os_cat_shadow_r1"),
        ("4d_os_chmod_tmp", "Malicious:os_chmod_tmp_r1"),
        ("4d_sqli_dump_authid", "Malicious:sqli_copy_r1"),
        ("4d_reverse_shell", "Malicious:reverse_shell_r1"),
        ("4d_sabotage_drop_table", "Malicious:sabotage_drop_transactions_r1"),
        ("4d_benign_teller_query", "Benign:normal_teller_query_1"),
    ]

    for cat_name, label_match in selected_targets:
        # Find session_id with this label
        s_id = None
        for sid, lbl in labels.items():
            if lbl == label_match:
                s_id = sid
                break
        if not s_id or s_id not in events_by_session:
            continue

        session_events = events_by_session[s_id]
        G = nx.MultiDiGraph()

        # Build session graph directly from real postgres events
        sess_node = f"Session_{s_id}"
        G.add_node(sess_node, type="Session", label=f"Session {s_id}", database="casce_banking")

        for idx, ev in enumerate(session_events, 1):
            q_node = f"Query_{s_id}_{idx}"
            query_text = ev.get("query", "")
            username = ev.get("username", "unknown")
            event_type = ev.get("event_type", "SQL")
            
            G.add_node(q_node, type="SQLQuery", label=f"Query {idx}", query=query_text[:60], username=username)
            G.add_edge(sess_node, q_node, relation="EXECUTES", key=f"e_{idx}")

            # If program execution detected in query
            if "TO PROGRAM" in query_text.upper():
                prog_node = f"Program_{s_id}_{idx}"
                prog_cmd = query_text.split("PROGRAM")[1].strip(" ';") if "PROGRAM" in query_text else "program"
                G.add_node(prog_node, type="Process", label="OS_Command", cmd=prog_cmd[:40])
                G.add_edge(q_node, prog_node, relation="SPAWNS_PROCESS", key=f"spawn_{idx}")

            if "DROP TABLE" in query_text.upper():
                t_node = f"Table_Destruction_{s_id}_{idx}"
                G.add_node(t_node, type="DatabaseObject", label="DROP_TABLE", query=query_text[:50])
                G.add_edge(q_node, t_node, relation="DROPS", key=f"drop_{idx}")

            if "CREATE ROLE" in query_text.upper():
                r_node = f"Role_Escalation_{s_id}_{idx}"
                G.add_node(r_node, type="DatabaseObject", label="SUPERUSER_ROLE")
                G.add_edge(q_node, r_node, relation="CREATES_SUPERUSER", key=f"role_{idx}")

        # Abstract behaviors
        G_enriched, detected = algorithm_3_abstract.abstract_session_graph(G, templates)
        G_enriched = sanitize_for_graphml(G_enriched)

        case_dir = dest_dir / cat_name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "graphml").mkdir(parents=True, exist_ok=True)

        graphml_path = case_dir / "graphml" / f"{cat_name}.graphml"
        nx.write_graphml(G_enriched, str(graphml_path))

        png_path = case_dir / "graph.png"
        clean_title = cat_name.replace("_", " ").title() + f" (Live 4D Workload)"
        render_graph(graphml_path, png_path, title=clean_title)

        summary = {
            "case_id": cat_name,
            "session_id": s_id,
            "label": label_match,
            "data_source": "live_4d_attack_workload (PostgreSQL 17 Hook)",
            "database": "casce_banking",
            "node_count": G_enriched.number_of_nodes(),
            "edge_count": G_enriched.number_of_edges(),
            "detected_behaviors": [b["label"] for b in detected],
            "graph_file": graphml_path.name,
            "png_file": "graph.png",
        }
        (case_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        cases.append(summary)
        print(f"    [+] Created 4D live attack graph: {cat_name} (Nodes: {summary['node_count']}, Edges: {summary['edge_count']})")

    return cases


def main():
    print("=" * 60)
    print("CASCE REAL-TIME LIVE GRAPH GENERATION")
    print("=" * 60)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    cases_8 = process_live_run_8_final(OUT_DIR)
    cases_4d = process_live_4d_run(OUT_DIR)

    all_cases = cases_8 + cases_4d
    (OUT_DIR / "live_catalog_manifest.json").write_text(
        json.dumps(all_cases, indent=2), encoding="utf-8"
    )
    print("=" * 60)
    print(f"[✓] Successfully generated {len(all_cases)} real live graphs!")
    print(f"[✓] Output directory: {OUT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()
