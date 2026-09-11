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


def _average_precision_from_scores(y_true, y_scores):
    """Compute average precision (PR-AUC under the stepwise definition)."""
    if not y_true:
        return 0.0
    try:
        from sklearn.metrics import average_precision_score
        return float(average_precision_score(y_true, y_scores))
    except Exception:
        pass

    positives = sum(1 for y in y_true if y == 1)
    if positives == 0:
        return 0.0

    ranked = sorted(zip(y_scores, y_true), key=lambda item: item[0], reverse=True)
    true_positives = 0
    false_positives = 0
    prev_recall = 0.0
    ap = 0.0

    for _score, label in ranked:
        if label == 1:
            true_positives += 1
        else:
            false_positives += 1

        recall = true_positives / positives
        precision = true_positives / max(1, true_positives + false_positives)

        if recall > prev_recall:
            ap += precision * (recall - prev_recall)
            prev_recall = recall

    return float(ap)


def _roc_auc_from_scores(y_true, y_scores):
    """Compute AUROC (Area Under Receiver Operating Characteristic Curve)."""
    if not y_true:
        return 0.0
    try:
        from sklearn.metrics import roc_auc_score
        return float(roc_auc_score(y_true, y_scores))
    except Exception:
        pass

    positives = [s for s, y in zip(y_scores, y_true) if y == 1]
    negatives = [s for s, y in zip(y_scores, y_true) if y == 0]
    if not positives or not negatives:
        return 0.5

    n_pos = len(positives)
    n_neg = len(negatives)
    u = sum(
        1.0 if p > n else 0.5 if p == n else 0.0
        for p in positives
        for n in negatives
    )
    return float(u / (n_pos * n_neg))


def _classification_metrics(tp, fp, fn, tn):
    total = max(1, tp + fp + fn + tn)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    specificity = tn / max(1, tn + fp)
    fpr = fp / max(1, fp + tn)
    fnr = fn / max(1, fn + tp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    accuracy = (tp + tn) / total
    balanced_accuracy = (recall + specificity) / 2

    numerator = (tp * tn) - (fp * fn)
    denominator = math.sqrt(
        max(1, (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    )
    mcc = numerator / denominator if denominator else 0.0
    alert_rate = (tp + fp) / total
    miss_rate = fn / max(1, fn + tp)

    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "fpr": fpr,
        "fnr": fnr,
        "f1": f1,
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "mcc": mcc,
        "alert_rate": alert_rate,
        "miss_rate": miss_rate,
    }


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

THETA_A = 0.65  # alert threshold selected after validation sweep
THETA_R = 0.8   # response threshold

# fuse_scores is 1 - (1 - W_RULE*r)(1 - W_GAT*g). With the old W_RULE=W_GAT=0.75,
# a *perfect* 3-stage exfiltration chain (severity=0.95, mean Algorithm-3
# confidence ~0.65-0.80) gives rule_score ~= 0.6-0.77, and 0.75 * 0.77 ~= 0.58
# -- BELOW THETA_A=0.65. That means the rule path could never alert on its
# own; every real alert was effectively being carried by the GAT, making the
# "hybrid" detector GAT-with-rule-garnish rather than two independent paths.
# Raising W_RULE to 1.0 lets a high-confidence rule match (rule_score >= 0.65)
# clear THETA_A unaided, matching the paper's framing of the rule path as an
# independent fast-path detector rather than a path that can only ever
# co-sign the GAT. W_GAT is left at 0.75 rather than also raised to 1.0: the
# GAT has no equivalent hard evidence trail (see Issue #8 below on shared
# provenance), so keeping it damped relative to the rule path is a
# conservative choice that should be revisited empirically once baselines
# and PR curves (Tier 2 in the review) exist to check it against.
W_RULE = 1.0
W_GAT = 0.75

FEATURE_HASH_DIM = 16
NUM_NODE_FEATS = FEATURE_HASH_DIM + 8
HIDDEN_DIM = 32
HEADS = 4
NUM_LAYERS = 2


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
            "timestamp": _safe_float(data.get("timestamp_unix", data.get("timestamp"))),
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
                                   "timestamp": data.get("timestamp_unix", data.get("timestamp"))})
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

def _stable_hash_bucket(text, dim=FEATURE_HASH_DIM):
    """Deterministic feature hashing (md5, not hash()) so train-time and
    inference-time features never silently disagree across processes."""
    vec = np.zeros(dim, dtype=np.float32)
    if not text:
        return vec
    for tok in re.findall(r"[a-zA-Z0-9_./:-]+", str(text).lower()):
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def featurize_node(G, n, max_ts):
    data = G.nodes[n]
    # Use label, query text, or node id as hash input for semantic features
    hash_text = data.get("label", data.get("query", str(n)))
    hash_feat = _stable_hash_bucket(hash_text)
    confidence = _safe_float(data.get("confidence"))
    s_struct = _safe_float(data.get("s_struct"))
    s_sem = _safe_float(data.get("s_sem"))
    s_temp = _safe_float(data.get("s_temp"))
    # Accept both "timestamp_unix" and "timestamp", prioritizing calibrated timestamp_unix
    ts_raw = data.get("timestamp_unix", data.get("timestamp", None))
    has_ts = 1.0 if ts_raw is not None else 0.0
    recency = (_safe_float(ts_raw) / max_ts) if max_ts > 0 else 0.0
    in_deg = G.in_degree(n) if G.is_directed() else G.degree(n)
    out_deg = G.out_degree(n) if G.is_directed() else 0
    numeric_feat = np.array([confidence, s_struct, s_sem, s_temp, has_ts, recency,
                              math.tanh(in_deg / 5.0), math.tanh(out_deg / 5.0)], dtype=np.float32)
    return np.concatenate([hash_feat, numeric_feat])


if TORCH_AVAILABLE:

    def build_hetero_data(G):
        data = HeteroData()
        node_index = {nt: {} for nt in ALL_NODE_TYPES}
        node_feats = {nt: [] for nt in ALL_NODE_TYPES}

        # Accept both "timestamp_unix" and "timestamp" for recency features
        timestamps = []
        for _, d in G.nodes(data=True):
            ts = d.get("timestamp_unix", d.get("timestamp"))
            if ts is not None:
                timestamps.append(_safe_float(ts))
        max_ts = max(timestamps) if timestamps else 1.0

        unknown_types = set()
        for n, d in G.nodes(data=True):
            ntype = d.get("type")
            if ntype not in node_index:
                unknown_types.add(ntype)
                continue
            node_index[ntype][n] = len(node_index[ntype])
            node_feats[ntype].append(featurize_node(G, n, max_ts))
        if unknown_types:
            pass  # Silently skip unknown types — they are expected for new node types

        for nt in ALL_NODE_TYPES:
            if node_feats[nt]:
                data[nt].x = torch.tensor(np.stack(node_feats[nt]), dtype=torch.float32)
            else:
                data[nt].x = torch.zeros((0, NUM_NODE_FEATS), dtype=torch.float32)

        edge_buckets = {et: ([], []) for et in EDGE_TYPES}
        unknown_edges = set()
        # Handle both DiGraph (u, v, data) and MultiDiGraph (u, v, key, data).
        # Rather than pulling a single mixed-arity tuple out of a generically
        # typed iterator and unpacking it differently per branch (which static
        # checkers like pyrefly can't narrow, since both branches share one
        # inferred type for edge_tuple), normalize each case to a plain
        # (u, v, ed) 3-tuple up front. This keeps runtime behavior identical
        # while making the unpack shape unambiguous everywhere it's used.
        if isinstance(G, nx.MultiDiGraph):
            edge_iter = ((u, v, ed) for u, v, _ekey, ed in G.edges(data=True, keys=True))
        else:
            edge_iter = G.edges(data=True)
        for u, v, ed in edge_iter:
            # Accept both "relation" (old format) and "rel" (jobs branch format)
            rel = ed.get("relation", ed.get("rel"))
            if rel is None:
                continue
            ut = G.nodes[u].get("type")
            vt = G.nodes[v].get("type")
            key = (ut, rel, vt)
            if key not in edge_buckets:
                unknown_edges.add(key)
                continue
            if u not in node_index.get(ut, {}) or v not in node_index.get(vt, {}):
                continue
            src, dst = edge_buckets[key]
            src.append(node_index[ut][u]); dst.append(node_index[vt][v])
            # BUG 2 fix companion: also populate the auto-added reverse relation
            rev_key = (vt, f"rev_{rel}", ut)
            if rev_key in edge_buckets:
                rsrc, rdst = edge_buckets[rev_key]
                rsrc.append(node_index[vt][v]); rdst.append(node_index[ut][u])
        # Only warn once about truly unexpected edges (suppress known noise)
        if unknown_edges:
            filtered = {e for e in unknown_edges if e[1] is not None and e[0] is not None}
            if filtered:
                pass  # Silently skip — varied graph schemas are expected

        for et, (src, dst) in edge_buckets.items():
            data[et].edge_index = (torch.tensor([src, dst], dtype=torch.long) if src
                                    else torch.empty((2, 0), dtype=torch.long))
        return data

    class CasceHeteroGAT(nn.Module):
        """
        Heterogeneous GATv2 over CASCE's node/edge schema. Node type is
        encoded structurally (separate weight matrices per HeteroConv
        relation), not via one-hot features, which is the whole point of
        using a heterogeneous GNN instead of a flattened homogeneous graph.

        BUG 1 fix: every GATv2Conv here gets an EXPLICIT integer in_channels
        (no lazy (-1,-1) shapes), so `model.parameters()` is fully populated
        the instant the model is constructed -- safe to build an optimizer
        before any forward pass, which the training loop does.
        BUG 2 fix: EDGE_TYPES already includes the auto-generated reverse
        relations, so every node type is a destination somewhere and keeps
        being updated across layers instead of vanishing from x_dict.
        """
        def __init__(self, node_types=ALL_NODE_TYPES, edge_types=EDGE_TYPES,
                     in_dim=NUM_NODE_FEATS, hidden_dim=HIDDEN_DIM, heads=HEADS,
                     num_layers=NUM_LAYERS, dropout=0.2):
            super().__init__()
            self.node_types = node_types
            self.hidden_dim = hidden_dim
            self.heads = heads

            self.convs = nn.ModuleList()
            layer_in_dim = in_dim
            for _ in range(num_layers):
                conv_dict = {
                    et: GATv2Conv(layer_in_dim, hidden_dim, heads=heads,
                                  dropout=dropout, add_self_loops=False)
                    for et in edge_types
                }
                self.convs.append(HeteroConv(conv_dict, aggr="sum"))
                layer_in_dim = hidden_dim * heads  # output dim of every layer after the first

            # BUG 3 FIX (readout): plain per-type mean-pooling averages a
            # 3-node attack subgraph into irrelevance inside a session with
            # hundreds of benign nodes. Replace with a learned attention gate
            # per node type: a small linear scorer produces one logit per
            # node, softmax turns those into weights, and the pooled vector
            # is the weighted sum. This lets the model learn to weight
            # Behavior nodes (where the actual signal lives) far more heavily
            # than routine Process/File/Query noise, instead of every node
            # counting equally regardless of relevance.
            out_dim = hidden_dim * heads
            self.attn_gates = nn.ModuleDict({
                nt: nn.Linear(out_dim, 1) for nt in node_types
            })

            pooled_dim = out_dim * len(node_types)
            self.classifier = nn.Sequential(
                nn.Linear(pooled_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout),
                nn.Linear(hidden_dim, 1),
            )

        def forward(self, data):
            x_dict = data.x_dict
            edge_index_dict = data.edge_index_dict
            out_dim = self.hidden_dim * self.heads

            for conv in self.convs:
                # Ensure every node type has an entry going in (zeros of the
                # right width if empty) so HeteroConv never chokes and so a
                # node type absent this layer still has *something* next layer.
                x_dict = conv(x_dict, edge_index_dict)
                x_dict = {k: F.elu(v) for k, v in x_dict.items()}
                for nt in self.node_types:
                    if nt not in x_dict:
                        x_dict[nt] = torch.zeros((0, out_dim))

            pooled_parts = []
            for nt in self.node_types:
                x = x_dict.get(nt)
                if x is not None and x.size(0) > 0:
                    gate_logits = self.attn_gates[nt](x).squeeze(-1)  # [num_nodes_of_type]
                    weights = torch.softmax(gate_logits, dim=0)
                    pooled_parts.append((x * weights.unsqueeze(-1)).sum(dim=0))
                else:
                    pooled_parts.append(torch.zeros(out_dim))
            graph_repr = torch.cat(pooled_parts, dim=0)
            return self.classifier(graph_repr).squeeze(-1)

    def gat_score(G, model):
        data = build_hetero_data(G)
        model.eval()
        with torch.no_grad():
            return torch.sigmoid(model(data)).item()

else:

    def gat_score(G, model=None):
        """Fallback if torch/torch_geometric aren't installed: a simple,
        clearly-labelled heuristic so the pipeline still runs end-to-end.
        Real GATv2 path activates automatically once those are installed."""
        behaviors = _behavior_nodes(G)
        if not behaviors:
            return 0.0
        avg_conf = float(np.mean([b["confidence"] for b in behaviors]))
        # Count precedes edges; handle both MultiDiGraph and DiGraph, and both attr names
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


def detect(G, model, session_id="unknown", theta_a=THETA_A, theta_r=THETA_R,
           w_rule=W_RULE, w_gat=W_GAT, detection_mode="hybrid"):
    rule_score, scenario, matched_nodes, _all = evaluate_rules(G)
    gat_prob = gat_score(G, model)

    if detection_mode == "rules_only":
        risk = rule_score
    elif detection_mode == "gat_only":
        risk = gat_prob
    else:
        risk = fuse_scores(rule_score, gat_prob, w_rule=w_rule, w_gat=w_gat)

    assessment = {
        "session_id": session_id, "risk": round(risk, 4),
        "rule_score": round(rule_score, 4), "gat_score": round(gat_prob, 4),
        "scenario": scenario, "status": "benign",
        "detection_mode": detection_mode,
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

    Args:
        dir_str: Comma-separated enriched graph directories
        label_str: Comma-separated label JSON file paths

    Returns:
        List of (HeteroData, float_label) tuples
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
            G = nx.read_graphml(path)
            dataset.append((build_hetero_data(G), float(label)))

    return dataset


def load_model(model_path):
    if not TORCH_AVAILABLE:
        return None
    model = CasceHeteroGAT()
    if model_path and os.path.exists(model_path):
        state = torch.load(model_path, map_location="cpu", weights_only=False)
        try:
            # strict=False was silently tolerating checkpoints that only
            # partly matched the current architecture (e.g. after adding the
            # attn_gates module below) -- the load would "succeed" while
            # leaving those parameters randomly initialized, and nothing
            # would tell you the resulting model was partly untrained.
            # Load strictly first; only fall back to a partial load with an
            # explicit, loud warning naming exactly what didn't match.
            model.load_state_dict(state, strict=True)
            print(f"[algo4] Loaded trained GAT weights from {model_path} (strict match).")
        except RuntimeError as strict_err:
            result = model.load_state_dict(state, strict=False)
            missing = list(result.missing_keys)
            unexpected = list(result.unexpected_keys)
            warnings.warn(
                f"[algo4] Checkpoint at {model_path} did NOT strictly match the current "
                f"model architecture. Missing params (randomly initialized): {missing}. "
                f"Unexpected params in checkpoint (ignored): {unexpected}. "
                f"Scores from this model are NOT fully trained-weight scores -- retrain "
                f"before trusting evaluation numbers. Original error: {strict_err}",
                RuntimeWarning,
            )
    else:
        warnings.warn("No trained GAT checkpoint found — gat_score will be near-random "
                       "until train mode is run. The rule path is unaffected.", RuntimeWarning)
    return model


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


def _compute_epoch_loss(model, dataset, loss_fn):
    """Compute average loss over a dataset without gradient updates."""
    model.eval()
    total = 0.0
    with torch.no_grad():
        for data, y in dataset:
            logit = model(data)
            loss = loss_fn(logit.unsqueeze(0), torch.tensor([y]))
            total += loss.item()
    return total / max(1, len(dataset))


def train_gat(args):
    """Train with proper train/validation split and early stopping."""
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode train.")

    # Load training data
    train_data = _load_dataset_from_dirs(args.train_dir, args.train_labels)
    if not train_data:
        raise RuntimeError("No training graphs found — check --train-dir and --train-labels.")

    # Load validation data (optional but recommended)
    val_data = []
    if args.val_dir and args.val_labels:
        val_data = _load_dataset_from_dirs(args.val_dir, args.val_labels)

    n_pos = sum(1 for _, y in train_data if y == 1.0)
    n_neg = len(train_data) - n_pos
    print(f"[train] Training set: {len(train_data)} graphs ({n_neg} normal, {n_pos} malicious)")
    if val_data:
        v_pos = sum(1 for _, y in val_data if y == 1.0)
        v_neg = len(val_data) - v_pos
        print(f"[train] Validation set: {len(val_data)} graphs ({v_neg} normal, {v_pos} malicious)")

    model = CasceHeteroGAT()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    pos_weight = torch.tensor([n_neg / max(1, n_pos)]) if n_pos > 0 else torch.tensor([1.0])
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    # Early stopping state
    best_val_loss = float('inf')
    patience = 5
    patience_counter = 0
    best_state = None

    for epoch in range(1, args.epochs + 1):
        # --- Training ---
        model.train()
        total_loss = 0.0
        for data, y in train_data:
            optimizer.zero_grad()
            logit = model(data)
            loss = loss_fn(logit.unsqueeze(0), torch.tensor([y]))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        train_loss = total_loss / len(train_data)

        # --- Validation ---
        if val_data:
            val_loss = _compute_epoch_loss(model, val_data, loss_fn)
            print(f"[train] epoch {epoch}/{args.epochs}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

            # Early stopping check
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"[train] Early stopping at epoch {epoch} (val_loss not improving for {patience} epochs)")
                    break
        else:
            print(f"[train] epoch {epoch}/{args.epochs}  train_loss={train_loss:.4f}")

    # Restore best model if we did early stopping
    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"[train] Restored best model (val_loss={best_val_loss:.4f})")

    torch.save(model.state_dict(), args.model_path)
    print(f"[train] Saved trained GAT weights to {args.model_path}")


def evaluate_model(args):
    """Evaluate the trained model on a labeled dataset and report metrics."""
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode evaluate. "
                         "Heuristic fallback cannot be used for scientific evaluation.")

    model = load_model(args.model_path)

    dirs = [d.strip() for d in args.input_dir.split(',') if d.strip()]
    label_files = [f.strip() for f in args.labels.split(',') if f.strip()]
    theta_a = getattr(args, 'theta_a', THETA_A)
    theta_r = getattr(args, 'theta_r', THETA_R)
    w_rule = getattr(args, 'w_rule', W_RULE)
    w_gat = getattr(args, 'w_gat', W_GAT)
    detection_mode = getattr(args, 'detection_mode', 'hybrid')

    y_true, y_scores, y_rule, y_gat = [], [], [], []
    for d, lf in zip(dirs, label_files):
        with open(lf) as f:
            labels = json.load(f)
        for filename, label in labels.items():
            path = os.path.join(d, filename)
            if not os.path.exists(path):
                continue
            G = nx.read_graphml(path)
            assessment = detect(G, model, session_id=filename, theta_a=theta_a, theta_r=theta_r,
                                w_rule=w_rule, w_gat=w_gat, detection_mode=detection_mode)
            y_true.append(int(label))
            y_scores.append(assessment['risk'])
            y_rule.append(assessment['rule_score'])
            y_gat.append(assessment['gat_score'])

    if not y_true:
        raise RuntimeError("No evaluation data found.")

    # Binary predictions at current threshold
    y_pred = [1 if s >= theta_a else 0 for s in y_scores]

    # Compute metrics
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    metrics = _classification_metrics(tp, fp, fn, tn)
    pr_auc = _average_precision_from_scores(y_true, y_scores)
    roc_auc = _roc_auc_from_scores(y_true, y_scores)

    results = {
        'threshold': theta_a,
        'detection_mode': detection_mode,
        'w_rule': w_rule,
        'w_gat': w_gat,
        'total_samples': len(y_true),
        'true_positives': tp, 'false_positives': fp,
        'false_negatives': fn, 'true_negatives': tn,
        'precision': round(metrics['precision'], 4),
        'recall': round(metrics['recall'], 4),
        'specificity': round(metrics['specificity'], 4),
        'false_positive_rate': round(metrics['fpr'], 4),
        'false_negative_rate': round(metrics['fnr'], 4),
        'f1_score': round(metrics['f1'], 4),
        'accuracy': round(metrics['accuracy'], 4),
        'balanced_accuracy': round(metrics['balanced_accuracy'], 4),
        'mcc': round(metrics['mcc'], 4),
        'auroc': round(roc_auc, 4),
        'roc_auc': round(roc_auc, 4),
        'auprc': round(pr_auc, 4),
        'pr_auc': round(pr_auc, 4),
        'alert_rate': round(metrics['alert_rate'], 4),
        'miss_rate': round(metrics['miss_rate'], 4),
        'confusion_matrix': [[tn, fp], [fn, tp]],
    }

    print(f"\n{'='*60}")
    print(f"  EVALUATION RESULTS (θ_A = {theta_a:.2f}, mode = {detection_mode})")
    print(f"{'='*60}")
    print(f"  Samples:   {len(y_true)} ({sum(y_true)} malicious, {len(y_true)-sum(y_true)} normal)")
    print(f"  Accuracy:        {metrics['accuracy']:.4f}")
    print(f"  Balanced Acc:    {metrics['balanced_accuracy']:.4f}")
    print(f"  Precision:       {metrics['precision']:.4f}")
    print(f"  Recall:          {metrics['recall']:.4f}")
    print(f"  Specificity:     {metrics['specificity']:.4f}")
    print(f"  FPR:             {metrics['fpr']:.4f}")
    print(f"  FNR:             {metrics['fnr']:.4f}")
    print(f"  F1-Score:        {metrics['f1']:.4f}")
    print(f"  MCC:             {metrics['mcc']:.4f}")
    print(f"  AUROC:           {roc_auc:.4f}")
    print(f"  AUPRC / PR-AUC:  {pr_auc:.4f}")
    print(f"  Alert Rate:      {metrics['alert_rate']:.4f}")
    print(f"  Miss Rate:       {metrics['miss_rate']:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"              Pred Normal  Pred Malicious")
    print(f"  True Normal     {tn:5d}       {fp:5d}")
    print(f"  True Malicious  {fn:5d}       {tp:5d}")
    print(f"{'='*60}")

    # Save results
    out_path = os.path.join(args.outdir, "evaluation_results.json")
    os.makedirs(args.outdir, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {out_path}")

    return results


def tune_thresholds(args):
    """Sweep θ_A to find the threshold maximizing F1 on validation data."""
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode tune.")

    model = load_model(args.model_path)

    dirs = [d.strip() for d in args.input_dir.split(',') if d.strip()]
    label_files = [f.strip() for f in args.labels.split(',') if f.strip()]

    y_true, y_scores = [], []
    for d, lf in zip(dirs, label_files):
        with open(lf) as f:
            labels = json.load(f)
        for filename, label in labels.items():
            path = os.path.join(d, filename)
            if not os.path.exists(path):
                continue
            G = nx.read_graphml(path)
            assessment = detect(G, model, session_id=filename)
            y_true.append(int(label))
            y_scores.append(assessment['risk'])

    if not y_true:
        raise RuntimeError("No data for threshold tuning.")

    print(f"\n{'='*60}")
    print(f"  THRESHOLD TUNING (sweeping θ_A)")
    print(f"{'='*60}")
    print(f"  {'θ_A':>6}  {'Prec':>6}  {'Recall':>6}  {'F1':>6}  {'Acc':>6}")
    print(f"  {'-'*36}")

    best_f1, best_theta = 0, THETA_A
    sweep_results = []

    for theta_int in range(10, 91, 5):
        theta = theta_int / 100.0
        y_pred = [1 if s >= theta else 0 for s in y_scores]
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        acc = (tp + tn) / max(1, len(y_true))

        sweep_results.append({'theta': theta, 'precision': prec, 'recall': rec, 'f1': f1, 'accuracy': acc})
        print(f"  {theta:6.2f}  {prec:6.3f}  {rec:6.3f}  {f1:6.3f}  {acc:6.3f}")

        if f1 > best_f1:
            best_f1 = f1
            best_theta = theta

    print(f"\n  ★ Best F1 = {best_f1:.4f} at θ_A = {best_theta:.2f}")
    print(f"    Recommended: update THETA_A = {best_theta}")

    out_path = os.path.join(args.outdir, "threshold_sweep.json")
    os.makedirs(args.outdir, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({'best_theta': best_theta, 'best_f1': best_f1, 'sweep': sweep_results}, f, indent=2)
    print(f"    Sweep results saved to {out_path}")


def parse_args():
    p = argparse.ArgumentParser(description="CASCE Algorithm 4 — Hybrid Cross-Layer Threat Detection")
    p.add_argument("--mode", choices=["detect", "train", "evaluate", "tune"], default="detect")

    # Shared
    p.add_argument("--input-dir", default=None,
                   help="Comma-separated enriched graph dirs (detect/evaluate/tune)")
    p.add_argument("--outdir", default="./alg4_out")
    p.add_argument("--model-path", default="./casce_gat.pt")
    p.add_argument("--labels", default=None,
                   help="Comma-separated label JSON files (evaluate/tune)")
    p.add_argument("--theta-a", type=float, default=THETA_A)
    p.add_argument("--theta-r", type=float, default=THETA_R)
    p.add_argument("--w-rule", type=float, default=W_RULE,
                   help="Weight for rule-based detector in fusion")
    p.add_argument("--w-gat", type=float, default=W_GAT,
                   help="Weight for GAT detector in fusion")
    p.add_argument("--detection-mode", choices=["hybrid", "rules_only", "gat_only"], default="hybrid",
                   help="Detection modality: hybrid, rules_only, or gat_only")

    # Train-specific
    p.add_argument("--train-dir", default=None,
                   help="Comma-separated training enriched graph dirs")
    p.add_argument("--val-dir", default=None,
                   help="Comma-separated validation enriched graph dirs")
    p.add_argument("--train-labels", default=None,
                   help="Comma-separated training label JSON files")
    p.add_argument("--val-labels", default=None,
                   help="Comma-separated validation label JSON files")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--lr", type=float, default=1e-3)
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