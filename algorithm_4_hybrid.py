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
    ("Query",   "reads_from",  "Table"),
    ("Query",   "accesses",    "Table"),
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

THETA_A = 0.5   # alert threshold
THETA_R = 0.8   # response threshold
W_RULE = 0.55
W_GAT = 0.45

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
            "timestamp": _safe_float(data.get("timestamp")),
        })
    return out


def _behavior_chains(G, behaviors):
    """Sub-DAG of Behavior nodes linked by 'precedes'; every root->leaf path
    is one chronological chain. A behavior with no precedes edges at all
    becomes its own length-1 chain (so single-label rules still work)."""
    beh_ids = {b["node"] for b in behaviors}
    by_id = {b["node"]: b for b in behaviors}
    sub_edges = [(u, v) for u, v, d in G.edges(data=True)
                 if d.get("relation") == "precedes" and u in beh_ids and v in beh_ids]
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
            edge = G.get_edge_data(pred, beh_node)
            if edge and edge.get("relation") == "evidence_for" and pred not in seen:
                seen.add(pred)
                data = G.nodes[pred]
                facts.append({"node": pred, "type": data.get("type", "Unknown"),
                               "label": data.get("label", pred),
                               "timestamp": data.get("timestamp")})
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
    hash_feat = _stable_hash_bucket(data.get("label", ""))
    confidence = _safe_float(data.get("confidence"))
    s_struct = _safe_float(data.get("s_struct"))
    s_sem = _safe_float(data.get("s_sem"))
    s_temp = _safe_float(data.get("s_temp"))
    ts_raw = data.get("timestamp", None)
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

        timestamps = [_safe_float(d.get("timestamp")) for _, d in G.nodes(data=True)
                      if d.get("timestamp") is not None]
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
            print(f"[algo4] WARNING: node type(s) {unknown_types} not in schema — skipped.")

        for nt in ALL_NODE_TYPES:
            if node_feats[nt]:
                data[nt].x = torch.tensor(np.stack(node_feats[nt]), dtype=torch.float32)
            else:
                data[nt].x = torch.zeros((0, NUM_NODE_FEATS), dtype=torch.float32)

        edge_buckets = {et: ([], []) for et in EDGE_TYPES}
        unknown_edges = set()
        for u, v, ed in G.edges(data=True):
            rel = ed.get("relation")
            ut, vt = G.nodes[u].get("type"), G.nodes[v].get("type")
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
        if unknown_edges:
            print(f"[algo4] WARNING: edge type(s) {unknown_edges} not in schema — skipped.")

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

            pooled_dim = hidden_dim * heads * len(node_types)
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
                    pooled_parts.append(x.mean(dim=0))
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
        precedes_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("relation") == "precedes")
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


def detect(G, model, session_id="unknown", theta_a=THETA_A, theta_r=THETA_R):
    rule_score, scenario, matched_nodes, _all = evaluate_rules(G)
    gat_prob = gat_score(G, model)
    risk = fuse_scores(rule_score, gat_prob)

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
            assessment["response_action"] = "FREEZE_SESSION"
    else:
        assessment["message"] = f"session {session_id}: normal behavior (risk {risk:.2f})"

    return assessment


# ============================================================================
# 5. CLI — detect / train
# ============================================================================

def load_model(model_path):
    if not TORCH_AVAILABLE:
        return None
    model = CasceHeteroGAT()
    if model_path and os.path.exists(model_path):
        state = torch.load(model_path, map_location="cpu")
        try:
            model.load_state_dict(state, strict=False)
            print(f"[algo4] Loaded trained GAT weights from {model_path}")
        except Exception as e:
            print(f"[algo4] WARNING: could not load weights ({e}); using untrained model.")
    else:
        warnings.warn("No trained GAT checkpoint found — gat_score will be near-random "
                       "until train mode is run. The rule path is unaffected.", RuntimeWarning)
    return model


def run_detection(input_dir, outdir, model_path, theta_a, theta_r):
    os.makedirs(outdir, exist_ok=True)
    model = load_model(model_path)
    if not TORCH_AVAILABLE:
        print("[algo4] torch/torch_geometric not installed — GAT path running in heuristic fallback mode.")

    results = []
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


def train_gat(input_dir, labels_path, model_out, epochs=30, lr=1e-3):
    if not TORCH_AVAILABLE:
        raise SystemExit("torch + torch_geometric are required for --mode train.")

    with open(labels_path) as f:
        labels = json.load(f)

    model = CasceHeteroGAT()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)  # safe now: no lazy params

    dataset = []
    for filename, label in labels.items():
        path = os.path.join(input_dir, filename)
        if not os.path.exists(path):
            print(f"[train] WARNING: {filename} listed in labels but not found — skipping.")
            continue
        G = nx.read_graphml(path)
        dataset.append((build_hetero_data(G), float(label)))

    if not dataset:
        raise RuntimeError("No labeled graphs found — check --labels and --input-dir.")

    n_pos = sum(1 for _, y in dataset if y == 1.0)
    n_neg = len(dataset) - n_pos
    pos_weight = torch.tensor([n_neg / max(1, n_pos)]) if n_pos > 0 else torch.tensor([1.0])
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    model.train()
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for data, y in dataset:
            optimizer.zero_grad()
            logit = model(data)
            loss = loss_fn(logit.unsqueeze(0), torch.tensor([y]))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"[train] epoch {epoch}/{epochs}  loss={total_loss/len(dataset):.4f}")

    torch.save(model.state_dict(), model_out)
    print(f"[train] Saved trained GAT weights to {model_out}")


def parse_args():
    p = argparse.ArgumentParser(description="CASCE Algorithm 4 — Hybrid Cross-Layer Threat Detection")
    p.add_argument("--mode", choices=["detect", "train"], default="detect")
    p.add_argument("--input-dir", required=True)
    p.add_argument("--outdir", default="./alg4_out")
    p.add_argument("--model-path", default="./casce_gat.pt")
    p.add_argument("--labels", default=None)
    p.add_argument("--theta-a", type=float, default=THETA_A)
    p.add_argument("--theta-r", type=float, default=THETA_R)
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--lr", type=float, default=1e-3)
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "detect":
        run_detection(args.input_dir, args.outdir, args.model_path, args.theta_a, args.theta_r)
    else:
        if not args.labels:
            raise SystemExit("--labels is required for --mode train")
        train_gat(args.input_dir, args.labels, args.model_path, args.epochs, args.lr)


if __name__ == "__main__":
    main()