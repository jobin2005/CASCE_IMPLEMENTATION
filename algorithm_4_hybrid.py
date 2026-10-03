#!/usr/bin/env python3
"""
CASCE — Algorithm 4: Hybrid Cross-Layer Threat Detection (merged/fixed)
=========================================================================

This merges two prior drafts and fixes two real bugs found by actually
running the second draft's GAT model, not just reading it:

  BUG 1 (crash): the training loop created `torch.optim.Adam(model.parameters())`
  *before* ever calling `model(data)`. GATv2Conv layers built with lazy
  in_channels=(-1,-1) have zero real parameters until their first forward
  pass, so `model.parameters()` raises `ValueError: uninitialized parameter`
  immediately -- confirmed by reproducing it, see chat. Fixed here by using
  EXPLICIT integer in_channels for every layer (no lazy shapes at all), so
  parameters exist the moment the model is constructed.

  BUG 2 (silent data loss): in a HeteroConv over directed edges, any node
  type that never appears as a DESTINATION in the edge-type list (e.g.
  "Query" -- nothing points *at* a Query node in the schema) is dropped
  entirely from x_dict after the first layer and never recovers. Confirmed
  by running HeteroConv directly and printing its output keys: 'Query' and
  'Process' vanished after one layer. That means Query nodes -- exactly
  where sensitive-table access, DROP/DELETE, and role escalation live --
  contributed nothing to the final risk score. Fixed here by auto-adding a
  reverse edge for every relation (dst, "rev_<rel>", src), so every node
  type is a destination of at least one relation and keeps updating.

Everything else keeps the better of the two drafts:
  - Rule path: the chain-DAG / all_simple_paths matcher (more correct than
    a single greedy DFS), extended chain-rule table, proper evidence
    tracing and alert-text rendering.
  - GAT path: real heterogeneous GATv2 model (node type structurally
    encoded via HeteroData, not one-hot -- better than a homogeneous
    single-type graph) with an actual, now-working training loop.
  - Robustness: if torch / torch_geometric aren't installed, the GAT path
    falls back to a documented heuristic instead of crashing the whole
    file on import (neither prior draft did this).

    risk <- FUSESCORES( RULES(G'_s, R), GAT(G'_s) )
    if risk >= theta_A: EMITALERT ; if risk >= theta_R: RESPOND
    else: LOGBENIGN

Usage
-----
Detect (batch over Algorithm 3's enriched .graphml output):
    python3 algo4_final.py --mode detect \
        --input-dir ./algo3_output --outdir ./algo4_out \
        --model-path ./casce_gat.pt

Train the GAT on labeled enriched graphs (labels.json: filename -> 0/1):
    python3 algo4_final.py --mode train \
        --input-dir ./algo3_output --labels ./labels.json \
        --model-path ./casce_gat.pt --epochs 30
"""

import os
import re
import json
import math
import hashlib
import argparse
import warnings

import networkx as nx
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import HeteroData
    from torch_geometric.nn import GATv2Conv, HeteroConv
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# ============================================================================
# 1. SCHEMA
#    Base types from the paper's Table I, + Configuration (needed by your
#    friend's DEFENSE_IMPAIRMENT template), + Behavior (added by Algorithm 3).
#    Verify this against Algorithm 2's real output before trusting results.
# ============================================================================

BASE_NODE_TYPES = ["Session", "Role", "Query", "Table", "Process", "File",
                    "Endpoint", "Configuration"]
ALL_NODE_TYPES = BASE_NODE_TYPES + ["Behavior"]

FORWARD_EDGE_TYPES = [
    # Edges from the jobs branch schema (schema.py: executes, accesses,
    # backed_by, spawns, opens, connects_to)
    ("Session", "executes",    "Query"),       # Session executes Query
    ("Query",   "accesses",    "Table"),        # Query accesses Table
    ("Query",   "reads_from",  "Table"),
    ("Query",   "modifies",    "Table"),
    ("Query",   "modifies",    "Role"),
    ("Query",   "accesses",    "Role"),        # what Algorithm 2 emits for CREATE/ALTER ROLE
    ("Query",   "modifies",    "Configuration"),
    ("Process", "executes",    "File"),
    ("Process", "reads_from",  "File"),
    ("Process", "writes_to",   "File"),
    ("Process", "modifies",    "File"),
    ("Process", "unlinks",     "File"),
    ("Process", "opens",       "File"),
    ("Process", "connects_to", "Endpoint"),
    ("Process", "spawns",      "Process"),
    ("Session", "spawns",      "Process"),
    ("Table",   "backed_by",   "File"),
    ("Behavior", "precedes",   "Behavior"),
]
for _nt in BASE_NODE_TYPES:
    FORWARD_EDGE_TYPES.append((_nt, "evidence_for", "Behavior"))
FORWARD_EDGE_TYPES = list(dict.fromkeys(FORWARD_EDGE_TYPES))

# --- BUG 2 FIX: add a reverse relation for every forward relation, so every
# node type is a destination of at least one edge type and keeps updating
# across HeteroConv layers instead of silently vanishing from x_dict.
EDGE_TYPES = list(FORWARD_EDGE_TYPES)
for (s, rel, d) in FORWARD_EDGE_TYPES:
    EDGE_TYPES.append((d, f"rev_{rel}", s))
EDGE_TYPES = list(dict.fromkeys(EDGE_TYPES))


# Chain rules (Table III extended to the 11 templates your friend implemented).
# match_type:
#   "ordered_subsequence" - labels must appear, in order, along a single
#       chronological precedes-chain (gaps/other behaviors in between OK).
#   "co_occurrence" - all labels must appear somewhere in the session,
#       ANY chains, order irrelevant (paper's "+" notation, e.g. "Object
#       destruction + service stop"). Deliberately NOT restricted to a
#       single precedes-chain, because two co-occurring but chronologically
#       distant behaviors (further apart than Algorithm 3's chain_gap) would
#       otherwise never share a chain and the rule could never fire -- that
#       would silently under-detect sabotage-style co-occurrence patterns.
CHAIN_RULES = [
    {"name": "Data exfiltration",
     "sequence": ["DATA_ACCESS", "DATA_PACKAGING", "EXTERNAL_TRANSFER"],
     "match_type": "ordered_subsequence", "severity": 0.95},
    {"name": "Direct data exfiltration",
     "sequence": ["DATA_ACCESS", "EXTERNAL_TRANSFER"],
     "match_type": "ordered_subsequence", "severity": 0.95},
    {"name": "Privilege abuse",
     "sequence": ["ACCOUNT_MANIPULATION", "UNIX_SHELL_EXECUTION", "DATA_ACCESS"],
     "match_type": "ordered_subsequence", "severity": 0.90},
    {"name": "Credential theft via OS",
     "sequence": ["UNIX_SHELL_EXECUTION", "OS_CREDENTIAL_DUMPING"],
     "match_type": "ordered_subsequence", "severity": 0.85},
    {"name": "Credential-based privilege escalation",
     "sequence": ["OS_CREDENTIAL_DUMPING", "ACCOUNT_MANIPULATION"],
     "match_type": "ordered_subsequence", "severity": 0.85},
    # NOTE: paper's "Object destruction + service stop". No service-stop
    # template exists yet in Algorithm 3's template set -- INDICATOR_REMOVAL_FILE
    # is used as an approximation (file/log cleanup after destructive action).
    # Flag to your friend: swap in a real service-stop template when one exists.
    {"name": "Sabotage",
     "sequence": ["DESTRUCTIVE_DB_OPERATION", "INDICATOR_REMOVAL_FILE"],
     "match_type": "co_occurrence", "severity": 0.90},
    {"name": "Anti-forensics / cover-up",
     "sequence": ["INDICATOR_REMOVAL_HISTORY", "INDICATOR_REMOVAL_FILE"],
     "match_type": "co_occurrence", "severity": 0.75},
    {"name": "Ingress tool transfer",
     "sequence": ["POTENTIAL_INGRESS_TOOL_TRANSFER", "UNIX_SHELL_EXECUTION"],
     "match_type": "co_occurrence", "severity": 0.65},
    {"name": "Defense evasion after privilege change",
     "sequence": ["ACCOUNT_MANIPULATION", "DEFENSE_IMPAIRMENT"],
     "match_type": "ordered_subsequence", "severity": 0.80},
    # single-behavior "soft" rules: one alarming behavior alone, lower severity
    {"name": "Credential access",
     "sequence": ["OS_CREDENTIAL_DUMPING"], "match_type": "co_occurrence", "severity": 0.55},
    {"name": "Destructive operation",
     "sequence": ["DESTRUCTIVE_DB_OPERATION"], "match_type": "co_occurrence", "severity": 0.50},
    {"name": "Unclassified external transfer",
     "sequence": ["EXTERNAL_TRANSFER"], "match_type": "co_occurrence", "severity": 0.45},
]

THETA_A = 0.5   # alert threshold (re-tune on VALIDATION data only, see --mode tune)
THETA_R = 0.8   # response threshold
# Fusion weights. With W_GAT = 0.75 the fused score was capped at 0.75 whenever
# no rule fired (rule = 0), which is below THETA_R, so the response tier was
# unreachable for any GAT-only detection. Weights of 1.0 make the noisy-OR a
# plain probabilistic OR: neither path is discounted, and a confident GAT alone
# can reach the response tier.
W_RULE = 1.0
W_GAT = 1.0

FEATURE_HASH_DIM = 16
NUM_NODE_FEATS = FEATURE_HASH_DIM + 8
# Model / training defaults. Size was cut from hidden 32 x 4 heads (~1.4M weights
# for ~7k tiny graphs, enough to memorise the corpus) to 16 x 2; run_experiments.py
# sweeps size explicitly. AdamW weight decay, dropout 0.3, batching and a fixed
# seed replace plain Adam / dropout 0.2 / batch 1 / unseeded.
HIDDEN_DIM = 16
HEADS = 2
NUM_LAYERS = 2
DROPOUT = 0.3
LEARNING_RATE = 1e-3
WEIGHT_DECAY = 1e-3
BATCH_SIZE = 64
EPOCHS = 60
PATIENCE = 8
SEED = 0


# ============================================================================
# 2. RULE-BASED PATH  — RULES(G'_s, R)
# ============================================================================

BEHAVIOR_LABEL_RE = re.compile(r"^\[(?P<mitre>.*?)\]\s*(?P<label>.+)$")


def _safe_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _parse_behavior_label(raw_label):
    m = BEHAVIOR_LABEL_RE.match(raw_label or "")
    return (m.group("label") if m else (raw_label or "").strip())


def _behavior_nodes(G):
    out = []
    for n, data in G.nodes(data=True):
        if data.get("type") != "Behavior":
            continue
        out.append({
            "node": n,
            "label": _parse_behavior_label(data.get("label", "")),
            "confidence": _safe_float(data.get("confidence")),
            "timestamp": _safe_float(data.get("timestamp")),
        })
    return out


def _behavior_chains(G, behaviors):
    """Sub-DAG of Behavior nodes linked by 'precedes'; every root->leaf path
    is one chronological chain. A behavior with no precedes edges at all
    becomes its own length-1 chain (so single-label rules still work)."""
    beh_ids = {b["node"] for b in behaviors}
    by_id = {b["node"]: b for b in behaviors}
    # Handle both DiGraph and MultiDiGraph; accept "relation" or "rel" attribute
    sub_edges = []
    if isinstance(G, nx.MultiDiGraph):
        for u, v, _k, d in G.edges(data=True, keys=True):
            rel = d.get("relation", d.get("rel"))
            if rel == "precedes" and u in beh_ids and v in beh_ids:
                sub_edges.append((u, v))
    else:
        for u, v, d in G.edges(data=True):
            rel = d.get("relation", d.get("rel"))
            if rel == "precedes" and u in beh_ids and v in beh_ids:
                sub_edges.append((u, v))
    H = nx.DiGraph()
    H.add_nodes_from(beh_ids)
    H.add_edges_from(sub_edges)

    chains = []
    roots = [n for n in H.nodes if H.in_degree(n) == 0]
    for r in roots:
        leaves = [n for n in H.nodes if H.out_degree(n) == 0 and nx.has_path(H, r, n)]
        if not leaves:
            chains.append([by_id[r]])
            continue
        for leaf in leaves:
            for path in nx.all_simple_paths(H, r, leaf):
                chains.append([by_id[n] for n in path])
    return chains


def _ordered_subsequence_match(chain_labels, rule_sequence):
    idx = 0
    for label in chain_labels:
        if idx < len(rule_sequence) and label == rule_sequence[idx]:
            idx += 1
    return idx == len(rule_sequence)


def evaluate_rules(G, chain_rules=CHAIN_RULES):
    """
    RULES(G'_s, R). Returns (rule_score, scenario, matched_node_ids, all_matches).
    (0.0, None, [], []) is the expected outcome for a benign session (no
    Behavior nodes, or none of the rules fire) -- not an error.
    """
    behaviors = _behavior_nodes(G)
    if not behaviors:
        return 0.0, None, [], []

    chains = _behavior_chains(G, behaviors)
    all_labels_in_session = {b["label"] for b in behaviors}
    conf_by_label = {}
    for b in behaviors:
        conf_by_label.setdefault(b["label"], []).append(b)

    all_matches = []
    for rule in chain_rules:
        best_for_rule = None

        if rule["match_type"] == "ordered_subsequence":
            for chain in chains:
                labels = [b["label"] for b in chain]
                if not _ordered_subsequence_match(labels, rule["sequence"]):
                    continue
                involved = [b for b in chain if b["label"] in rule["sequence"]]
                if not involved:
                    continue
                mean_conf = sum(b["confidence"] for b in involved) / len(involved)
                score = rule["severity"] * mean_conf
                if best_for_rule is None or score > best_for_rule["score"]:
                    best_for_rule = {"rule": rule["name"], "score": score,
                                      "nodes": [b["node"] for b in involved]}
        else:  # co_occurrence -- checked session-wide, not chain-restricted (see note above)
            if all(lbl in all_labels_in_session for lbl in rule["sequence"]):
                involved = []
                for lbl in rule["sequence"]:
                    best_instance = max(conf_by_label[lbl], key=lambda b: b["confidence"])
                    involved.append(best_instance)
                mean_conf = sum(b["confidence"] for b in involved) / len(involved)
                score = rule["severity"] * mean_conf
                best_for_rule = {"rule": rule["name"], "score": score,
                                  "nodes": [b["node"] for b in involved]}

        if best_for_rule:
            all_matches.append(best_for_rule)

    if not all_matches:
        return 0.0, None, [], []

    best = max(all_matches, key=lambda m: m["score"])
    return best["score"], best["rule"], best["nodes"], all_matches


def trace_evidence(G, behavior_node_ids):
    """TRACEEVIDENCE: walk evidence_for edges backward to raw facts."""
    facts, seen = [], set()
    for beh_node in behavior_node_ids:
        for pred in G.predecessors(beh_node):
            # Handle both DiGraph and MultiDiGraph edge data access
            edge_data_raw = G.get_edge_data(pred, beh_node)
            if edge_data_raw is None:
                continue
            # For MultiDiGraph, edge_data_raw is a dict of {key: data_dict}
            if isinstance(G, nx.MultiDiGraph):
                edge_items = edge_data_raw.values()
            else:
                edge_items = [edge_data_raw]
            for edge in edge_items:
                rel = edge.get("relation", edge.get("rel"))
                if rel == "evidence_for" and pred not in seen:
                    seen.add(pred)
                    data = G.nodes.get(pred, {})
                    facts.append({"node": pred, "type": data.get("type", "Unknown"),
                                   "label": data.get("label", pred),
                                   "timestamp": data.get("timestamp", data.get("timestamp_unix"))})
    facts.sort(key=lambda f: _safe_float(f.get("timestamp")))
    return facts


def render_alert_text(session_id, risk, scenario, facts):
    fact_strs = [f"{f['type'].lower()} '{f['label']}'" for f in facts]
    trail = ", then ".join(fact_strs) if fact_strs else "no evidence chain available"
    scenario_text = scenario.lower() if scenario else "unclassified anomaly"
    return (f"session {session_id}, risk {risk:.2f}, threat scenario: "
            f"possible {scenario_text} — {trail}")


# ============================================================================
# 3. GAT PATH  — GAT(G'_s)
# ============================================================================

_LITERAL_RE = re.compile(r"'(?:[^']|'')*'|\b0x[0-9a-f]+\b|\b\d+(?:\.\d+)?\b")
_ID_RE = re.compile(r"[0-9a-f]{6,}|\d+")
_TOKEN_RE = re.compile(r"[a-z0-9_#?]+")
_PRIVATE_IP_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)")


def normalize_sql(query):
    """Replace string/numeric literals with '?' so the hashed feature keys on
    the statement's shape, not on a specific account number, host or value
    (an exact-text hash is a direct memorisation channel)."""
    return " ".join(_LITERAL_RE.sub("?", str(query).lower()).split())


def node_semantic_text(data):
    """Text hashed into a node's feature vector. Deliberately excludes
    anything that is an identifier of a *run* rather than of behaviour: pids
    (the old fallback hashed str(node_id), i.e. "('Process', 20001)"), raw IPs
    and hostnames, and literal SQL values."""
    t = data.get("type")
    if t == "Query":
        return normalize_sql(data.get("query", ""))
    if t == "Table":
        return str(data.get("table_name", ""))
    if t == "Role":
        return str(data.get("role_name", ""))
    if t == "Process":
        return str(data.get("comm", ""))
    if t == "File":
        return _ID_RE.sub("#", str(data.get("filepath", data.get("arg", ""))).lower())
    if t == "Endpoint":
        ip = str(data.get("dest_ip", ""))
        scope = "internal" if _PRIVATE_IP_RE.match(ip) else "external"
        return f"port_{data.get('dest_port', '')} {scope}"
    if t == "Behavior":
        return str(data.get("behavior_label", data.get("label", "")))
    if t == "Configuration":
        return str(data.get("setting_name", ""))
    return str(t or "")


def _stable_hash_bucket(text, dim=FEATURE_HASH_DIM):
    """Deterministic feature hashing (md5, not hash()) so train-time and
    inference-time features never silently disagree across processes."""
    vec = np.zeros(dim, dtype=np.float32)
    if not text:
        return vec
    for tok in _TOKEN_RE.findall(str(text).lower()):
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def _node_ts(data):
    ts = data.get("timestamp_unix", data.get("timestamp"))
    return None if ts in (None, "") else _safe_float(ts, None)


def featurize_node(G, n, t_min, t_span):
    data = G.nodes[n]
    hash_feat = _stable_hash_bucket(node_semantic_text(data))
    ts = _node_ts(data)
    # Position inside the session (0..1), not ts/max_ts: unix timestamps are
    # ~1.79e9 everywhere so the old "recency" was a constant.
    rel_time = ((ts - t_min) / t_span) if (ts is not None and t_span > 0) else 0.0
    in_deg = G.in_degree(n) if G.is_directed() else G.degree(n)
    out_deg = G.out_degree(n) if G.is_directed() else 0
    numeric_feat = np.array([
        _safe_float(data.get("confidence")), _safe_float(data.get("s_struct")),
        _safe_float(data.get("s_sem")), _safe_float(data.get("s_temp")),
        1.0 if ts is not None else 0.0, rel_time,
        math.tanh(in_deg / 5.0), math.tanh(out_deg / 5.0)], dtype=np.float32)
    return np.concatenate([hash_feat, numeric_feat])


if TORCH_AVAILABLE:
    from torch_geometric.data import Batch
    from torch_geometric.loader import DataLoader
    from torch_geometric.nn import global_mean_pool

    def build_hetero_data(G, label=None):
        data = HeteroData()
        node_index = {nt: {} for nt in ALL_NODE_TYPES}
        node_feats = {nt: [] for nt in ALL_NODE_TYPES}

        stamps = [t for t in (_node_ts(d) for _, d in G.nodes(data=True)) if t is not None]
        t_min = min(stamps) if stamps else 0.0
        t_span = (max(stamps) - t_min) if stamps else 0.0

        for n, d in G.nodes(data=True):
            ntype = d.get("type")
            if ntype not in node_index:
                continue  # unknown node types are skipped
            node_index[ntype][n] = len(node_index[ntype])
            node_feats[ntype].append(featurize_node(G, n, t_min, t_span))

        for nt in ALL_NODE_TYPES:
            if node_feats[nt]:
                data[nt].x = torch.tensor(np.stack(node_feats[nt]), dtype=torch.float32)
            else:
                data[nt].x = torch.zeros((0, NUM_NODE_FEATS), dtype=torch.float32)

        edge_buckets = {et: ([], []) for et in EDGE_TYPES}
        if isinstance(G, nx.MultiDiGraph):
            edge_iter = ((u, v, ed) for u, v, _k, ed in G.edges(data=True, keys=True))
        else:
            edge_iter = G.edges(data=True)
        for u, v, ed in edge_iter:
            rel = ed.get("relation", ed.get("rel"))
            if rel is None:
                continue
            ut, vt = G.nodes[u].get("type"), G.nodes[v].get("type")
            key = (ut, rel, vt)
            if key not in edge_buckets:
                continue
            if u not in node_index.get(ut, {}) or v not in node_index.get(vt, {}):
                continue
            src, dst = edge_buckets[key]
            src.append(node_index[ut][u]); dst.append(node_index[vt][v])
            rev_key = (vt, f"rev_{rel}", ut)
            if rev_key in edge_buckets:
                rsrc, rdst = edge_buckets[rev_key]
                rsrc.append(node_index[vt][v]); rdst.append(node_index[ut][u])

        for et, (src, dst) in edge_buckets.items():
            data[et].edge_index = (torch.tensor([src, dst], dtype=torch.long) if src
                                    else torch.empty((2, 0), dtype=torch.long))
        if label is not None:
            data.y = torch.tensor([float(label)])
        return data

    class CasceHeteroGAT(nn.Module):
        """
        Heterogeneous GATv2 over CASCE's node/edge schema. Node type is
        encoded structurally (separate weights per HeteroConv relation).

        Capacity: the original (hidden 32 x 4 heads, 68 relation convs) had
        ~1.4M weights for ~7k graphs of 5-15 nodes, which is enough to store
        the corpus. Defaults are now hidden 16 x 2 heads; `hidden_dim`, `heads`,
        `num_layers` stay configurable so the size sweep in run_experiments.py
        can show the effect rather than assume it.

        Forward accepts a batched HeteroData (torch_geometric Batch); graph
        readout is a per-node-type mean pool, concatenated, then an MLP.
        Explicit in_channels everywhere (no lazy shapes) and an auto-added
        reverse relation per edge type keep every node type updating -- the
        two earlier bug fixes are unchanged.
        """
        def __init__(self, node_types=ALL_NODE_TYPES, edge_types=EDGE_TYPES,
                     in_dim=NUM_NODE_FEATS, hidden_dim=HIDDEN_DIM, heads=HEADS,
                     num_layers=NUM_LAYERS, dropout=DROPOUT):
            super().__init__()
            self.node_types = node_types
            self.hidden_dim = hidden_dim
            self.heads = heads
            self.config = dict(hidden_dim=hidden_dim, heads=heads,
                               num_layers=num_layers, dropout=dropout)

            self.convs = nn.ModuleList()
            layer_in_dim = in_dim
            for _ in range(num_layers):
                conv_dict = {
                    et: GATv2Conv(layer_in_dim, hidden_dim, heads=heads,
                                  dropout=dropout, add_self_loops=False)
                    for et in edge_types
                }
                self.convs.append(HeteroConv(conv_dict, aggr="sum"))
                layer_in_dim = hidden_dim * heads

            pooled_dim = hidden_dim * heads * len(node_types)
            self.classifier = nn.Sequential(
                nn.Linear(pooled_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout),
                nn.Linear(hidden_dim, 1),
            )

        def forward(self, data):
            x_dict = data.x_dict
            edge_index_dict = data.edge_index_dict
            out_dim = self.hidden_dim * self.heads
            num_graphs = int(data.num_graphs) if hasattr(data, "num_graphs") else 1
            device = next(self.parameters()).device

            for conv in self.convs:
                x_dict = conv(x_dict, edge_index_dict)
                x_dict = {k: F.elu(v) for k, v in x_dict.items()}
                for nt in self.node_types:
                    if nt not in x_dict:
                        x_dict[nt] = torch.zeros((0, out_dim), device=device)

            pooled = []
            for nt in self.node_types:
                x = x_dict[nt]
                if x.size(0) > 0:
                    batch = data[nt].batch if hasattr(data[nt], "batch") and data[nt].batch is not None \
                        else torch.zeros(x.size(0), dtype=torch.long, device=device)
                    pooled.append(global_mean_pool(x, batch, size=num_graphs))
                else:
                    pooled.append(torch.zeros((num_graphs, out_dim), device=device))
            return self.classifier(torch.cat(pooled, dim=1)).squeeze(-1)

    def count_parameters(model):
        return sum(p.numel() for p in model.parameters())

    def predict_probs(model, data_list, batch_size=256):
        """P(malicious) for a list of HeteroData, in order."""
        model.eval()
        out = []
        with torch.no_grad():
            for batch in DataLoader(data_list, batch_size=batch_size, shuffle=False):
                out.extend(torch.sigmoid(model(batch)).tolist())
        return out

    def gat_score(G, model):
        return predict_probs(model, [build_hetero_data(G)])[0]

else:

    def gat_score(G, model=None):
        """Fallback if torch/torch_geometric aren't installed: a simple,
        clearly-labelled heuristic so the pipeline still runs end-to-end.
        Real GATv2 path activates automatically once those are installed."""
        behaviors = _behavior_nodes(G)
        if not behaviors:
            return 0.0
        avg_conf = float(np.mean([b["confidence"] for b in behaviors]))
        precedes_edges = 0
        if isinstance(G, nx.MultiDiGraph):
            for _, _, _k, d in G.edges(data=True, keys=True):
                if d.get("relation", d.get("rel")) == "precedes":
                    precedes_edges += 1
        else:
            for _, _, d in G.edges(data=True):
                if d.get("relation", d.get("rel")) == "precedes":
                    precedes_edges += 1
        chain_density = min(1.0, precedes_edges / max(1, len(behaviors)))
        return float(0.7 * avg_conf + 0.3 * chain_density)


# ============================================================================
# 4. FUSION + DETECT
# ============================================================================

def fuse_scores(rule_score, gat_score_val, w_rule=W_RULE, w_gat=W_GAT):
    """Weighted noisy-OR: a strongly-confident rule match shouldn't get
    diluted just because the GAT is unsure, and vice versa -- matches the
    paper's framing of GAT catching what rules miss, not gating them."""
    r = max(0.0, min(1.0, rule_score))
    g = max(0.0, min(1.0, gat_score_val))
    return 1.0 - (1.0 - w_rule * r) * (1.0 - w_gat * g)


def detect(G, model, session_id="unknown", theta_a=THETA_A, theta_r=THETA_R, w_rule=W_RULE, w_gat=W_GAT):
    rule_score, scenario, matched_nodes, _all = evaluate_rules(G)
    gat_prob = gat_score(G, model)
    risk = fuse_scores(rule_score, gat_prob, w_rule=w_rule, w_gat=w_gat)

    assessment = {
        "session_id": session_id, "risk": round(risk, 4),
        "rule_score": round(rule_score, 4), "gat_score": round(gat_prob, 4),
        "scenario": scenario, "status": "benign",
    }

    if risk >= theta_a:
        facts = trace_evidence(G, matched_nodes) if matched_nodes else []
        assessment["status"] = "alert"
        assessment["evidence"] = facts
        assessment["message"] = render_alert_text(session_id, risk, scenario, facts) if matched_nodes else \
            f"session {session_id}, risk {risk:.2f} — flagged by GAT structural signal alone, no rule chain matched."
        if risk >= theta_r:
            assessment["status"] = "response"
            assessment["response_action"] = "FREEZE_SESSION_DESIGNATION"  # action recommendation only, not a live pg_terminate_backend call
    else:
        assessment["message"] = f"session {session_id}: normal behavior (risk {risk:.2f})"

    return assessment


# ============================================================================
# 5. CLI — detect / train / evaluate / tune
#
# DESIGN NOTES (addressing review items):
#
# Fusion equation justification (Issue #2):
#   fuse_scores uses weighted noisy-OR: 1 - (1 - w_r·r)(1 - w_g·g)
#   This is a monotone combination from Dempster-Shafer theory where each
#   detector provides independent "belief mass" that the session is malicious.
#   Key property: if EITHER detector is highly confident (score→1), the fused
#   score approaches 1 regardless of the other — neither detector can suppress
#   a strong signal from the other. This matches the paper's framing of Rules
#   as "fast-path known-pattern detection" and GAT as "semantic anomaly catch".
#
# Severity values justification (Issue #7):
#   Multi-step ordered chains receive higher severity because they represent
#   more complete attack progressions with higher confidence:
#     0.95  Data exfiltration (3-step chain: access→package→transfer)
#     0.90  Privilege abuse (3-step: account manip→shell→data access)
#     0.90  Sabotage (2-behavior co-occurrence with high impact)
#     0.85  Credential theft / escalation (2-step chains)
#     0.80  Defense evasion after privilege change (2-step)
#     0.75  Anti-forensics (2-behavior co-occurrence, lower impact)
#     0.65  Ingress tool transfer (2-behavior, preparatory)
#     0.55  Credential access (single behavior, concerning)
#     0.50  Destructive operation (single behavior, needs context)
#     0.45  Unclassified external transfer (single behavior, common)
#
# Algorithm 3 → GAT feature dependency (Issue #8):
#   The GAT's node features (confidence, s_struct, s_sem, s_temp) originate
#   from Algorithm 3's behavior abstraction stage. This means the Rule and
#   GAT detection paths share the same upstream signal source, violating
#   strict statistical independence. The noisy-OR fusion is still valid
#   because the two paths extract DIFFERENT aspects of the same signal:
#   Rules match specific known sequences, while the GAT learns structural
#   patterns across the heterogeneous graph topology. However, this shared
#   provenance should be acknowledged in research write-ups.
#
# FREEZE_SESSION (Issue #5):
#   The response action is an ACTION DESIGNATION only — it does NOT invoke
#   pg_terminate_backend() or any live PostgreSQL API. It logs the recommendation
#   for a human operator or future automation layer to act upon.
# ============================================================================

def _load_dataset_from_dirs(dir_str, label_str):
    """Load graphs and labels from comma-separated directory/label paths.

    Returns a list of HeteroData, each carrying its label in `.y`.
    """
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for this mode.")

    dirs = [d.strip() for d in dir_str.split(',') if d.strip()]
    label_files = [f.strip() for f in label_str.split(',') if f.strip()]

    dataset = []
    for d, lf in zip(dirs, label_files):
        with open(lf) as f:
            labels = json.load(f)
        for filename, label in labels.items():
            path = os.path.join(d, filename)
            if not os.path.exists(path):
                print(f"[data] WARNING: {filename} not found in {d} — skipping.")
                continue
            dataset.append(build_hetero_data(nx.read_graphml(path), label=label))
    return dataset


def set_seed(seed):
    import random
    random.seed(seed)
    np.random.seed(seed)
    if TORCH_AVAILABLE:
        torch.manual_seed(seed)


DEFAULT_TRAIN_CFG = dict(hidden_dim=HIDDEN_DIM, heads=HEADS, num_layers=NUM_LAYERS,
                         dropout=DROPOUT, lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY,
                         batch_size=BATCH_SIZE, epochs=EPOCHS, patience=PATIENCE, seed=SEED)


def load_model(model_path):
    if not TORCH_AVAILABLE:
        return None
    if model_path and os.path.exists(model_path):
        ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
        if isinstance(ckpt, dict) and "state_dict" in ckpt:
            model = CasceHeteroGAT(**ckpt["config"])
            model.load_state_dict(ckpt["state_dict"])
        else:  # legacy bare state_dict: default architecture
            model = CasceHeteroGAT()
            try:
                model.load_state_dict(ckpt)
            except Exception as e:
                print(f"[algo4] WARNING: could not load legacy weights ({e}); using untrained model.")
                return model
        print(f"[algo4] Loaded trained GAT weights from {model_path}")
        return model
    warnings.warn("No trained GAT checkpoint found — gat_score will be near-random "
                  "until train mode is run. The rule path is unaffected.", RuntimeWarning)
    return CasceHeteroGAT()


def save_model(model, path):
    torch.save({"config": model.config, "state_dict": model.state_dict()}, path)


def run_detection(input_dirs, outdir, model_path, theta_a, theta_r):
    os.makedirs(outdir, exist_ok=True)
    model = load_model(model_path)
    if not TORCH_AVAILABLE:
        print("[algo4] torch/torch_geometric not installed — GAT path running in heuristic fallback mode.")

    dirs = [d.strip() for d in input_dirs.split(',') if d.strip()]
    results = []
    for input_dir in dirs:
        for filename in sorted(os.listdir(input_dir)):
            if not filename.endswith(".graphml"):
                continue
            G = nx.read_graphml(os.path.join(input_dir, filename))
            session_id = os.path.splitext(filename)[0]
            assessment = detect(G, model, session_id=session_id, theta_a=theta_a, theta_r=theta_r)
            results.append(assessment)
            with open(os.path.join(outdir, f"{session_id}_assessment.json"), "w") as f:
                json.dump(assessment, f, indent=2)
            print(f"[{assessment['status'].upper()}] {assessment['message']}")

    with open(os.path.join(outdir, "_summary.json"), "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nProcessed {len(results)} session graphs. Summary: {os.path.join(outdir, '_summary.json')}")


def train_model(train_data, val_data=None, cfg=None, log=print):
    """Train a CasceHeteroGAT on a list of labelled HeteroData.

    AdamW (decoupled weight decay), mini-batches, fixed seed, early stopping on
    validation loss. Returns (model, history); the model is restored to its
    best-validation weights. `val_data` only steers early stopping -- it is
    never trained on, and thresholds must not be tuned on the test split.
    """
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for training.")
    c = {**DEFAULT_TRAIN_CFG, **(cfg or {})}
    set_seed(c["seed"])

    model = CasceHeteroGAT(hidden_dim=c["hidden_dim"], heads=c["heads"],
                           num_layers=c["num_layers"], dropout=c["dropout"])
    opt = torch.optim.AdamW(model.parameters(), lr=c["lr"], weight_decay=c["weight_decay"])

    n_pos = int(sum(float(d.y.item()) == 1.0 for d in train_data))
    n_neg = len(train_data) - n_pos
    pos_weight = torch.tensor([n_neg / max(1, n_pos)]) if n_pos else torch.tensor([1.0])
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    log(f"[train] {len(train_data)} graphs ({n_neg} benign, {n_pos} malicious), "
        f"{count_parameters(model):,} params, cfg={ {k: c[k] for k in ('hidden_dim','heads','dropout','weight_decay','batch_size')} }")

    gen = torch.Generator().manual_seed(c["seed"])
    train_loader = DataLoader(train_data, batch_size=c["batch_size"], shuffle=True, generator=gen)
    val_loader = DataLoader(val_data, batch_size=256) if val_data else None

    best_val, best_state, bad = float("inf"), None, 0
    history = []
    for epoch in range(1, c["epochs"] + 1):
        model.train()
        tot, cnt = 0.0, 0
        for batch in train_loader:
            opt.zero_grad()
            loss = loss_fn(model(batch), batch.y)
            loss.backward()
            opt.step()
            tot += loss.item() * batch.num_graphs
            cnt += batch.num_graphs
        rec = {"epoch": epoch, "train_loss": tot / cnt}
        if val_loader is not None:
            model.eval()
            vt, vc = 0.0, 0
            with torch.no_grad():
                for batch in val_loader:
                    vt += loss_fn(model(batch), batch.y).item() * batch.num_graphs
                    vc += batch.num_graphs
            rec["val_loss"] = vt / vc
            if rec["val_loss"] < best_val - 1e-4:
                best_val, bad = rec["val_loss"], 0
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
            else:
                bad += 1
        history.append(rec)
        log(f"[train] epoch {epoch}/{c['epochs']}  " +
            "  ".join(f"{k}={v:.4f}" for k, v in rec.items() if k != "epoch"))
        if val_loader is not None and bad >= c["patience"]:
            log(f"[train] early stop at epoch {epoch} (best val_loss={best_val:.4f})")
            break
    if best_state is not None:
        model.load_state_dict(best_state)
    return model, history


def train_gat(args):
    train_data = _load_dataset_from_dirs(args.train_dir, args.train_labels)
    if not train_data:
        raise RuntimeError("No training graphs found — check --train-dir and --train-labels.")
    val_data = []
    if args.val_dir and args.val_labels:
        val_data = _load_dataset_from_dirs(args.val_dir, args.val_labels)
    cfg = dict(epochs=args.epochs, lr=args.lr, weight_decay=args.weight_decay,
               dropout=args.dropout, hidden_dim=args.hidden_dim, heads=args.heads,
               batch_size=args.batch_size, seed=args.seed)
    model, _ = train_model(train_data, val_data, cfg)
    save_model(model, args.model_path)
    print(f"[train] Saved trained GAT weights to {args.model_path}")


def _score_dirs(model, dir_str, label_str):
    """Run detect() over labelled graphs; returns y, fused, rule, gat arrays."""
    dirs = [d.strip() for d in dir_str.split(',') if d.strip()]
    label_files = [f.strip() for f in label_str.split(',') if f.strip()]
    y, fused, rule, gat = [], [], [], []
    for d, lf in zip(dirs, label_files):
        with open(lf) as f:
            labels = json.load(f)
        for filename, label in labels.items():
            path = os.path.join(d, filename)
            if not os.path.exists(path):
                continue
            a = detect(nx.read_graphml(path), model, session_id=filename)
            y.append(int(label)); fused.append(a["risk"])
            rule.append(a["rule_score"]); gat.append(a["gat_score"])
    if not y:
        raise RuntimeError("No evaluation data found.")
    return y, fused, rule, gat


def evaluate_model(args):
    """Report rule-only, GAT-only and fused metrics on a labelled set.

    Thresholds: --theta-a for fused/GAT-only/rule-only unless overridden. Pick
    them with --mode tune on VALIDATION labels, then evaluate once on test.
    """
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode evaluate.")
    from casce_metrics import binary_report

    model = load_model(args.model_path)
    y, fused, rule, gat = _score_dirs(model, args.input_dir, args.labels)
    n_mal = sum(y)
    if n_mal in (0, len(y)):
        print(f"\n  ⚠ WARNING: evaluation set is 100% {'malicious' if n_mal else 'benign'} — "
              f"FPR/AUC unmeasurable; this evaluation cannot fail.\n")

    reports = {"fused": binary_report(y, fused, args.theta_a),
               "rule_only": binary_report(y, rule, 0.5),
               "gat_only": binary_report(y, gat, 0.5)}
    print(f"\n{'='*72}\n  EVALUATION  n={len(y)} ({n_mal} malicious, {len(y)-n_mal} benign)\n{'='*72}")
    print(f"  {'Scorer':<10}{'thr':>5}{'Acc':>7}{'Prec':>7}{'Rec':>7}{'F1':>7}{'FPR':>7}{'ROC':>7}{'PR':>7}{'Brier':>7}{'ECE':>7}")
    f = lambda v: "  n/a" if v is None else f"{v:7.3f}"
    for name, r in reports.items():
        print(f"  {name:<10}{r['threshold']:5.2f}{r['accuracy']:7.3f}{r['precision']:7.3f}{r['recall']:7.3f}"
              f"{r['f1']:7.3f}{r['fpr']:7.3f}{f(r['roc_auc'])}{f(r['pr_auc'])}{r['brier']:7.3f}{r['ece']:7.3f}")
    os.makedirs(args.outdir, exist_ok=True)
    out = os.path.join(args.outdir, "evaluation_results.json")
    with open(out, "w") as fh:
        json.dump(reports, fh, indent=2)
    print(f"\n  Results saved to {out}")
    return reports


def tune_thresholds(args):
    """Sweep theta on VALIDATION data to maximise F1. Refuses test label files."""
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode tune.")
    from casce_metrics import best_f1_threshold, binary_report

    if any("test" in os.path.basename(p).lower() for p in args.labels.split(",")):
        raise SystemExit("Refusing to tune thresholds on a label file named *test*: "
                         "tuning on the evaluation split leaks it. Pass validation labels.")
    model = load_model(args.model_path)
    y, fused, _rule, _gat = _score_dirs(model, args.input_dir, args.labels)
    best = best_f1_threshold(y, fused)
    rep = binary_report(y, fused, best)
    print(f"\n  Best fused F1 on validation = {rep['f1']:.4f} at theta_A = {best:.2f} "
          f"(ROC-AUC {rep['roc_auc']}, PR-AUC {rep['pr_auc']})")
    os.makedirs(args.outdir, exist_ok=True)
    with open(os.path.join(args.outdir, "threshold_sweep.json"), "w") as fh:
        json.dump({"best_theta": best, "validation_report": rep}, fh, indent=2)


def parse_args():
    p = argparse.ArgumentParser(description="CASCE Algorithm 4 — Hybrid Cross-Layer Threat Detection")
    p.add_argument("--mode", choices=["detect", "train", "evaluate", "tune"], default="detect")
    p.add_argument("--input-dir", default=None, help="Comma-separated enriched graph dirs (detect/evaluate/tune)")
    p.add_argument("--outdir", default="./alg4_out")
    p.add_argument("--model-path", default="./casce_gat.pt")
    p.add_argument("--labels", default=None, help="Comma-separated label JSON files (evaluate/tune)")
    p.add_argument("--theta-a", type=float, default=THETA_A)
    p.add_argument("--theta-r", type=float, default=THETA_R)
    p.add_argument("--train-dir", default=None)
    p.add_argument("--val-dir", default=None)
    p.add_argument("--train-labels", default=None)
    p.add_argument("--val-labels", default=None)
    p.add_argument("--epochs", type=int, default=EPOCHS)
    p.add_argument("--lr", type=float, default=LEARNING_RATE)
    p.add_argument("--weight-decay", type=float, default=WEIGHT_DECAY)
    p.add_argument("--dropout", type=float, default=DROPOUT)
    p.add_argument("--hidden-dim", type=int, default=HIDDEN_DIM)
    p.add_argument("--heads", type=int, default=HEADS)
    p.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    p.add_argument("--seed", type=int, default=SEED)
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "detect":
        if not args.input_dir:
            raise SystemExit("--input-dir is required for --mode detect")
        run_detection(args.input_dir, args.outdir, args.model_path, args.theta_a, args.theta_r)
    elif args.mode == "train":
        if not args.train_dir or not args.train_labels:
            raise SystemExit("--train-dir and --train-labels are required for --mode train")
        train_gat(args)
    elif args.mode == "evaluate":
        if not args.input_dir or not args.labels:
            raise SystemExit("--input-dir and --labels are required for --mode evaluate")
        evaluate_model(args)
    elif args.mode == "tune":
        if not args.input_dir or not args.labels:
            raise SystemExit("--input-dir and --labels are required for --mode tune")
        tune_thresholds(args)


if __name__ == "__main__":
    main()
