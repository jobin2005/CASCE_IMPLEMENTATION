#!/usr/bin/env python3
"""
run_track2_diverse.py
=====================
Track 2: Empirical Live Evaluation with Realistic Diverse Benign Workloads
Evaluates CASCE on active PostgreSQL 17 traffic with native eBPF tracepoints and executor hooks.
Instead of trivial SELECT-only traffic, this testbed injects 8 diverse, realistic enterprise workloads:
  1. Teller standard query (SELECT)
  2. Teller transaction update + insert (UPDATE, INSERT)
  3. Compliance officer multi-table customer join (JOIN, SELECT)
  4. DBA table maintenance (VACUUM ANALYZE)
  5. DBA role provisioning and grant (CREATE ROLE, GRANT, DROP ROLE)
  6. Administrative backup with local compression (COPY ... TO PROGRAM 'gzip')
  7. Automated health/metric telemetry sync (COPY ... TO PROGRAM 'curl')
  8. Branch manager temporary reporting aggregation (CREATE TEMP TABLE)

Evaluated across all 4 Threat Classes:
  - Class 1: Privilege Abuse & Escalation
  - Class 2: Data Exfiltration
  - Class 3: SQL Injection & Sabotage (Negative Control)
  - Class 4: Multi-Stage APT Scenarios
"""

import csv
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Setup paths
REPO_ROOT = Path("/home/adithyan/Desktop/backup/CASCE_IMPLEMENTATION")
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "individual_simulation"))

import algorithm_1
import algorithm2
import algorithm_3_abstract
import algorithm_4_hybrid
from main import sanitize_for_graphml
from sklearn.metrics import roc_auc_score, average_precision_score

WORKSPACE_HOST = Path("/home/adithyan/Desktop/Projects/CASCE_DATASET")
CONTAINER = "casce_environment"
OUT_DIR = REPO_ROOT / "individual_simulation" / "track2_diverse_experiments"

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
        "name": "Class 3: Multi-Stage APT Scenarios",
        "folder": "class_3_multistage_apt",
        "scripts": [
            "attack_multi_session_apt.sh",
            "attack_reverse_shell.sh",
            "attack_priv_var_remote_bash.sh",
            "attack_priv_var_find_keys.sh",
            "attack_priv_var_enum_system.sh",
        ],
    },
]

BENIGN_WORKLOADS = [
    {
        "name": "teller_select",
        "role": "teller",
        "sql": "SELECT account_id, balance FROM accounts WHERE account_id = 101;",
    },
    {
        "name": "teller_tx",
        "role": "teller",
        "sql": "BEGIN; UPDATE accounts SET balance = balance - 50.00 WHERE account_id = 101; INSERT INTO transactions (account_id, amount, counterparty, transaction_time) VALUES (101, -50.00, 'ATM_WITHDRAWAL', NOW()); COMMIT;",
    },
    {
        "name": "compliance_kyc",
        "role": "compliance_officer",
        "sql": "SELECT c.customer_id, c.first_name, a.balance FROM customers c JOIN accounts a ON c.customer_id = a.customer_id WHERE a.balance > 25000 LIMIT 10;",
    },
    {
        "name": "dba_vacuum",
        "role": "postgres",
        "sql": "VACUUM (ANALYZE) accounts;",
    },
    {
        "name": "user_provision",
        "role": "postgres",
        "sql": "DROP ROLE IF EXISTS app_rep_temp; CREATE ROLE app_rep_temp LOGIN PASSWORD 'secret123'; GRANT SELECT ON accounts TO app_rep_temp; DROP ROLE app_rep_temp;",
    },
    {
        "name": "backup_gzip",
        "role": "postgres",
        "sql": "COPY (SELECT account_id, balance FROM accounts WHERE account_id < 100) TO PROGRAM 'gzip > /tmp/routine_backup_accounts.csv.gz';",
    },
    {
        "name": "metric_curl",
        "role": "postgres",
        "sql": "COPY (SELECT count(*) FROM transactions) TO PROGRAM 'curl -s -o /dev/null http://127.0.0.1:8080/health || true';",
    },
    {
        "name": "branch_analytics",
        "role": "branch_manager",
        "sql": "CREATE TEMP TABLE temp_branch AS SELECT branch_id, count(*), sum(balance) FROM accounts GROUP BY branch_id; SELECT * FROM temp_branch; DROP TABLE temp_branch;",
    },
]

def run_benign(role: str, sql: str, label: str):
    cmd = [
        "docker", "exec", "-e", f"PGAPPNAME=casce_label={label}", CONTAINER,
        "psql", "-X", "-q", "-h", "127.0.0.1", "-U", role, "-d", "casce_banking", "-c", sql
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def run_attack(script_path: str, label: str):
    cmd = [
        "docker", "exec", "-e", f"PGAPPNAME=casce_label={label}", "-e", "REPEAT=1", CONTAINER,
        "bash", script_path
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def logger_archive_and_start():
    print("  [logger] Resetting capture and starting eBPF + postgres logger...")
    subprocess.run(["docker", "exec", "-u", "root", CONTAINER, "bash", "/dataset_workspace/logger.sh", "archive"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["docker", "exec", "-u", "root", CONTAINER, "bash", "/dataset_workspace/logger.sh", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)

def logger_stop():
    print("  [logger] Stopping dual-plane logger...")
    subprocess.run(["docker", "exec", "-u", "root", CONTAINER, "bash", "/dataset_workspace/logger.sh", "stop"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)

def reset_database_state():
    sql = """
    DROP ROLE IF EXISTS hacker;
    DROP ROLE IF EXISTS stealth_hacker;
    DROP ROLE IF EXISTS sqli_admin;
    DROP ROLE IF EXISTS app_rep_temp;
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id BIGSERIAL PRIMARY KEY,
        account_id INT NOT NULL,
        amount NUMERIC(14, 2) NOT NULL,
        counterparty TEXT NOT NULL,
        transaction_time TIMESTAMP NOT NULL
    );
    """
    cmd = [
        "docker", "exec", CONTAINER,
        "psql", "-U", "postgres", "-d", "casce_banking", "-c", sql
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def wilson_interval(successes, total, confidence=0.95):
    if total == 0:
        return 0.0, 0.0, 0.0
    p_hat = successes / total
    z = 1.96
    denominator = 1 + (z**2) / total
    center = (p_hat + (z**2) / (2 * total)) / denominator
    spread = (z * math.sqrt((p_hat * (1 - p_hat) / total) + (z**2) / (4 * total**2))) / denominator
    return p_hat, max(0.0, center - spread), min(1.0, center + spread)

def analyze_thresholds(sessions, thresholds=[0.45, 0.50, 0.55, 0.60]):
    results = {}
    for th in thresholds:
        tp, fp, fn, tn = 0, 0, 0, 0
        for s in sessions:
            flagged = (s["risk_score"] >= th)
            if s["is_attack"]:
                if flagged:
                    tp += 1
                else:
                    fn += 1
            else:
                if flagged:
                    fp += 1
                else:
                    tn += 1
        pos = tp + fn
        neg = fp + tn
        rec = tp / pos if pos > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else None
        fpr = fp / neg if neg > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec is not None and (prec + rec) > 0) else 0.0
        results[str(th)] = {
            "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "Recall": round(rec, 4),
            "Precision": round(prec, 4) if prec is not None else None,
            "FPR": round(fpr, 4),
            "F1": round(f1, 4),
        }
    return results

def compute_auc(sessions):
    y_true = [1 if s["is_attack"] else 0 for s in sessions]
    y_scores = [s["risk_score"] for s in sessions]
    if len(set(y_true)) > 1:
        return round(roc_auc_score(y_true, y_scores), 4), round(average_precision_score(y_true, y_scores), 4)
    return 0.0, 0.0

def main():
    print("=" * 80)
    print("TRACK 2: EMPIRICAL LIVE RUN WITH DIVERSE BENIGN WORKLOADS")
    print("=" * 80)
    
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("[*] Loading production model: casce_gat_v3p_ens2.json...")
    model = algorithm_4_hybrid.load_model(str(REPO_ROOT / "casce_gat_v3p_ens2.json"))
    templates = algorithm_3_abstract.initialize_templates()
    
    all_experiments_summary = []
    all_sessions_global = []

    for idx, cat in enumerate(CATEGORIES, start=1):
        cat_name = cat["name"]
        cat_folder = cat["folder"]
        cat_dir = OUT_DIR / cat_folder
        cat_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[{idx}/4] Starting Live Evaluation for: {cat_name}")
        reset_database_state()
        logger_archive_and_start()

        # 1. Inject Diverse Benign Workloads
        print(f"  [+] Injecting {len(BENIGN_WORKLOADS)} diverse benign workloads (SELECT, UPDATE, VACUUM, ROLES, GZIP, CURL)...")
        for bw in BENIGN_WORKLOADS:
            label = f"Benign:{bw['name']}"
            run_benign(bw["role"], bw["sql"], label)
            time.sleep(0.5)

        # 2. Inject Category Attacks
        print(f"  [+] Injecting {len(cat['scripts'])} live attack scripts for {cat_name}...")
        for script in cat["scripts"]:
            albl = f"Malicious:{script.replace('.sh', '')}"
            script_path = f"/tmp/attack_workload_banking/{script}"
            run_attack(script_path, albl)
            time.sleep(1.0)

        time.sleep(3)
        logger_stop()

        # Copy captured telemetry
        shutil.copy2(WORKSPACE_HOST / "postgres_events.json", cat_dir / "postgres_events.json")
        shutil.copy2(WORKSPACE_HOST / "kernel_events.json", cat_dir / "kernel_events.json")
        shutil.copy2(WORKSPACE_HOST / "session_labels.jsonl", cat_dir / "session_labels.jsonl")

        # Load session labels
        session_labels = {}
        with open(cat_dir / "session_labels.jsonl") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    session_labels[item["session_id"]] = item["label"]

        # Run Correlation & Graph Construction
        master_log, correlated = algorithm_1.run_one(cat_dir)
        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_root = Path(tmpdirname)
            algorithm_1.save_run_output(cat_folder, master_log, correlated, tmp_root)
            event_table_path = tmp_root / f"{cat_folder}_event_table.json"
            correlation_path = tmp_root / f"{cat_folder}_session_correlation.csv"
            alg2_out = tmp_root / "alg2"

            lbl_csv = tmp_root / "labels.csv"
            with open(lbl_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["session_id", "label"])
                for sid, lbl in session_labels.items():
                    writer.writerow([sid, lbl])

            active_graphs, _, _, _ = algorithm2.run(
                event_table_path, correlation_path, alg2_out, cat_folder, lbl_csv
            )

            # Evaluate each session
            cat_sessions = []
            latencies = []

            for sid, G_raw in active_graphs.items():
                lbl = session_labels.get(sid, "unknown")
                is_attack = ("Malicious" in lbl)
                G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_raw, templates)
                G_enriched = sanitize_for_graphml(G_enriched)

                t0 = time.perf_counter()
                det = algorithm_4_hybrid.detect(G_enriched, model, session_id=sid, theta_a=0.55, theta_r=0.55)
                lat = (time.perf_counter() - t0)
                latencies.append(lat)

                s_dict = {
                    "session_id": sid,
                    "label": lbl,
                    "category": cat_name,
                    "is_attack": is_attack,
                    "risk_score": det["risk"],
                    "rule_score": det["rule_score"],
                    "gat_score": det["gat_score"],
                    "status": det["status"],
                    "node_count": G_enriched.number_of_nodes(),
                    "edge_count": G_enriched.number_of_edges(),
                    "behaviors": [b["label"] for b in behaviors],
                    "latency_s": round(lat, 4)
                }
                cat_sessions.append(s_dict)
                all_sessions_global.append(s_dict)

            # Performance Metrics at default theta = 0.55
            sweep = analyze_thresholds(cat_sessions, thresholds=[0.45, 0.50, 0.55, 0.60])
            m55 = sweep["0.55"]
            roc_auc, pr_auc = compute_auc(cat_sessions)

            sorted_lat = sorted(latencies)
            p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0
            p90 = sorted_lat[int(len(sorted_lat) * 0.9)] if sorted_lat else 0.0

            r_hat, r_low, r_high = wilson_interval(m55["TP"], m55["TP"] + m55["FN"])
            f_hat, f_low, f_high = wilson_interval(m55["FP"], m55["FP"] + m55["TN"])

            report = {
                "category": cat_name,
                "folder": cat_folder,
                "total_sessions": len(cat_sessions),
                "attacks_total": m55["TP"] + m55["FN"],
                "benign_total": m55["FP"] + m55["TN"],
                "TP": m55["TP"], "FN": m55["FN"], "FP": m55["FP"], "TN": m55["TN"],
                "Recall_TPR": m55["Recall"],
                "Recall_CI95": [round(r_low, 4), round(r_high, 4)],
                "Precision": m55["Precision"],
                "FPR": m55["FPR"],
                "FPR_CI95": [round(f_low, 4), round(f_high, 4)],
                "F1_Score": m55["F1"],
                "ROC_AUC": roc_auc,
                "PR_AUC": pr_auc,
                "Latency_p50_s": round(p50, 4),
                "Latency_p90_s": round(p90, 4),
                "threshold_sweep": sweep,
                "sessions": cat_sessions
            }
            all_experiments_summary.append(report)

            with open(cat_dir / "report.json", "w") as f:
                json.dump(report, f, indent=2)

            prec_str = f"{m55['Precision']*100:.1f}%" if m55['Precision'] is not None else "N/A"
            print(f"  [>] Results for {cat_name}:")
            print(f"      Sessions: {report['total_sessions']} ({report['attacks_total']} Attacks, {report['benign_total']} Benign)")
            print(f"      TP: {m55['TP']}, FN: {m55['FN']}, FP: {m55['FP']}, TN: {m55['TN']}")
            print(f"      Recall: {m55['Recall']*100:.1f}% [95% CI: {r_low*100:.1f}% - {r_high*100:.1f}%]")
            print(f"      Precision: {prec_str}, F1: {m55['F1']:.4f}, FPR: {m55['FPR']*100:.1f}% [95% CI: {f_low*100:.1f}% - {f_high*100:.1f}%]")
            print(f"      ROC-AUC: {roc_auc:.4f}, PR-AUC: {pr_auc:.4f}, Latency p50: {p50*1000:.1f} ms")

    # Global Total Analysis
    global_sweep = analyze_thresholds(all_sessions_global, thresholds=[0.45, 0.50, 0.55, 0.60])
    gm55 = global_sweep["0.55"]
    g_roc, g_pr = compute_auc(all_sessions_global)
    gr_hat, gr_low, gr_high = wilson_interval(gm55["TP"], gm55["TP"] + gm55["FN"])
    gf_hat, gf_low, gf_high = wilson_interval(gm55["FP"], gm55["FP"] + gm55["TN"])

    master_summary = {
        "title": "Track 2: Diverse Benign Workload Master Results",
        "total_sessions": len(all_sessions_global),
        "total_attacks": gm55["TP"] + gm55["FN"],
        "total_benign": gm55["FP"] + gm55["TN"],
        "TP": gm55["TP"], "FN": gm55["FN"], "FP": gm55["FP"], "TN": gm55["TN"],
        "Recall": gm55["Recall"],
        "Recall_CI95": [round(gr_low, 4), round(gr_high, 4)],
        "Precision": gm55["Precision"],
        "FPR": gm55["FPR"],
        "FPR_CI95": [round(gf_low, 4), round(gf_high, 4)],
        "F1": gm55["F1"],
        "ROC_AUC": g_roc,
        "PR_AUC": g_pr,
        "global_sweep": global_sweep,
        "category_reports": all_experiments_summary
    }

    with open(OUT_DIR / "track2_master_summary.json", "w") as f:
        json.dump(master_summary, f, indent=2)

    print("\n" + "=" * 80)
    print("TRACK 2 COMPLETED! MASTER SUMMARY:")
    print("=" * 80)
    print(f"Total Live Sessions Evaluated: {master_summary['total_sessions']}")
    print(f"Attacks: {master_summary['total_attacks']}, Benign: {master_summary['total_benign']}")
    print(f"TP: {gm55['TP']}, FN: {gm55['FN']}, FP: {gm55['FP']}, TN: {gm55['TN']}")
    print(f"Recall:    {gm55['Recall']*100:.1f}% [95% CI: {gr_low*100:.1f}% - {gr_high*100:.1f}%]")
    prec_total = f"{gm55['Precision']*100:.1f}%" if gm55['Precision'] is not None else "N/A"
    print(f"Precision: {prec_total}")
    print(f"FPR:       {gm55['FPR']*100:.1f}% [95% CI: {gf_low*100:.1f}% - {gf_high*100:.1f}%]")
    print(f"F1-Score:  {gm55['F1']:.4f}")
    print(f"ROC-AUC:   {g_roc:.4f}, PR-AUC: {g_pr:.4f}")
    print(f"\nArtifact saved: {OUT_DIR / 'track2_master_summary.json'}")

if __name__ == "__main__":
    main()
