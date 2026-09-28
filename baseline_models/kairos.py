#!/usr/bin/env python3
"""Kairos (Cheng et al., IEEE S&P 2024) baseline -- a real Temporal Graph
Network (TGN) implementation, not a hand-wavy approximation, scaled to
CASCE's data.

Kairos's real method: a TGN (Rossi et al. 2020) maintains a per-entity
memory vector that updates as timestamped events arrive; it is trained to
predict each event's edge type from the interacting entities' memories, and
the prediction error at each edge is the anomaly score. Reproduced here
using PyTorch Geometric's own `TGNMemory` (the exact class Kairos's own
code imports from `torch_geometric.nn`), with `IdentityMessage` and
`LastAggregator` -- the same PyG building blocks Kairos's real code uses.

Disclosed simplification: Kairos's own code additionally samples each
node's last-K temporal neighbors (`LastNeighborLoader`) and refines the
memory into an embedding via a graph-attention layer (`TransformerConv`)
before predicting edge type. On CASCE's graphs (mean 9.5 nodes, 11.6 edges
per session) that neighbor-sampling/attention refinement step is
unnecessary machinery for graphs this small -- this uses the raw memory
vector directly as the node embedding, which is exactly the "TGN-mem"
ablation variant described in the original TGN paper (Rossi et al. 2020,
Table 2), not an invented shortcut. The core mechanism being tested --
does memory-based temporal modeling predict "normal" edge types, and does
prediction error flag anomalies -- is unchanged.

Disclosed adaptation, required by the setting: TGN's memory is indexed by a
persistent global node id, meaningful in Kairos's native whole-host stream
setting. CASCE's corpus is many separate session graphs with session-local
node ids -- reused here exactly as in the ShadeWatcher baseline: nodes are
identified by SEMANTIC KEYS (table/role/file/config name, endpoint address,
process command, behavior label; Session/Query fall back to bare type, and
deliberately never use raw query text -- see shadewatcher.py's docstring for
why) so memory persists meaningfully for entities that recur across
sessions. All TRAIN-BENIGN graphs are concatenated into one chronological
event stream (synthetic strictly-increasing timestamps preserve each
session's internal order; sessions themselves are ordered by file name for
determinism) -- this is the same "one continuous provenance stream" setting
TGN memory is designed for, just built from many short sessions instead of
one long host trace.

The prediction TARGET is edge relation type (executes/accesses/connects_to/
...), matching Kairos's own "predict the event type" design. The raw
message fed into TGN's message module is derived from (src_type, dst_type)
one-hot features -- NOT the relation label itself, which would leak the
prediction target.

Usage:
    python baseline_models/kairos.py
"""
import json
import sys
from pathlib import Path

import networkx as nx
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import TGNMemory
from torch_geometric.nn.models.tgn import IdentityMessage, LastAggregator

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402
from baseline_models.shadewatcher import entity_key  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

MEMORY_DIM = 32
TIME_DIM = 16
BATCH_SIZE = 64
EPOCHS = 5
LR = 1e-3
SEED = 42

NODE_TYPES = ["Session", "Role", "Query", "Table", "Process", "File",
              "Endpoint", "Configuration", "Behavior"]
TYPE_IDX = {t: i for i, t in enumerate(NODE_TYPES)}


def node_type_of_key(key: str) -> str:
    return key.split(":", 1)[0] if ":" in key else key


def extract_events(G: nx.MultiDiGraph):
    """(src_key, dst_key, relation) triples, edge-insertion order (this
    project's graphs don't carry a reliable absolute wall-clock edge order
    beyond insertion, so insertion order is used as the within-graph
    chronology; see main() for the cross-graph synthetic clock)."""
    key_of = {n: entity_key(d.get("type", "?"), d) for n, d in G.nodes(data=True)}
    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    events = []
    for edge in edge_iter:
        u, v, d = edge[0], edge[1], edge[-1]
        rel = d.get("relation", d.get("rel", "?"))
        events.append((key_of[u], key_of[v], rel))
    return events


def build_type_feature(key: str) -> np.ndarray:
    vec = np.zeros(len(NODE_TYPES), dtype=np.float32)
    vec[TYPE_IDX.get(node_type_of_key(key), 0)] = 1.0
    return vec


class EdgeTypePredictor(nn.Module):
    def __init__(self, memory_dim, n_relations, hidden=32):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(memory_dim * 2, hidden), nn.ReLU(),
            nn.Linear(hidden, n_relations),
        )

    def forward(self, z_src, z_dst):
        return self.net(torch.cat([z_src, z_dst], dim=-1))


def load_all_events():
    graphs = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        entries = []
        for fname, label in sorted(labels.items()):
            path = GRAPHML_DIR / fname
            if not path.exists():
                continue
            G = nx.read_graphml(path)
            entries.append({"file": fname, "label": int(label), "events": extract_events(G)})
        graphs[part] = entries
    return graphs


def build_vocab(all_entries):
    entities, relations = {}, {}
    for entries in all_entries:
        for e in entries:
            for h, t, r in e["events"]:
                entities.setdefault(h, len(entities))
                entities.setdefault(t, len(entities))
                relations.setdefault(r, len(relations))
    return entities, relations


def main():
    torch.manual_seed(SEED)
    print("Loading graphs + extracting temporal events (semantic entity keys)...")
    graphs = load_all_events()
    for part in ("train", "val", "test"):
        n_mal = sum(e["label"] for e in graphs[part])
        print(f"  {part}: {len(graphs[part])} ({n_mal} malicious, {len(graphs[part]) - n_mal} benign)")

    entities, relations = build_vocab([graphs["train"], graphs["val"], graphs["test"]])
    n_entities, n_relations = len(entities), len(relations)
    print(f"\n{n_entities} entities, {n_relations} relation types")
    raw_msg_dim = len(NODE_TYPES) * 2

    memory = TGNMemory(n_entities, raw_msg_dim, MEMORY_DIM, TIME_DIM,
                        message_module=IdentityMessage(raw_msg_dim, MEMORY_DIM, TIME_DIM),
                        aggregator_module=LastAggregator())
    predictor = EdgeTypePredictor(MEMORY_DIM, n_relations)
    optimizer = torch.optim.Adam(set(memory.parameters()) | set(predictor.parameters()), lr=LR)
    loss_fn = nn.CrossEntropyLoss()

    def to_batch_tensors(entries):
        """Flatten a set of session graphs into one chronological event
        stream: sessions ordered deterministically (file name), a session's
        own edges keep their insertion order, and a strictly-increasing
        synthetic clock spans the whole stream (offset per session so no
        two sessions' events interleave -- each session is one atomic burst
        in time, consistent with it being one bounded session in reality)."""
        src, dst, t, raw_msg, rel, y_graph_start = [], [], [], [], [], []
        clock = 0
        for e in entries:
            y_graph_start.append((clock, len(src)))
            for h, d_, r in e["events"]:
                src.append(entities[h]); dst.append(entities[d_])
                t.append(clock)
                raw_msg.append(np.concatenate([build_type_feature(h), build_type_feature(d_)]))
                rel.append(relations[r])
                clock += 1
            clock += 1  # gap between sessions
        return (torch.tensor(src), torch.tensor(dst), torch.tensor(t, dtype=torch.long),
                torch.tensor(np.stack(raw_msg) if raw_msg else np.zeros((0, raw_msg_dim)), dtype=torch.float),
                torch.tensor(rel), y_graph_start)

    train_src, train_dst, train_t, train_msg, train_rel, _ = to_batch_tensors(
        [e for e in graphs["train"] if e["label"] == 0])
    print(f"\nTraining TGN memory + edge-type predictor on {len(train_src)} events from "
          f"TRAIN-BENIGN sessions only (Kairos is unsupervised/one-class)...")

    memory.train()
    predictor.train()
    for epoch in range(1, EPOCHS + 1):
        memory.reset_state()
        total_loss, n = 0.0, 0
        for i in range(0, len(train_src), BATCH_SIZE):
            sl = slice(i, i + BATCH_SIZE)
            src, dst, t, msg, rel = train_src[sl], train_dst[sl], train_t[sl], train_msg[sl], train_rel[sl]
            n_id = torch.cat([src, dst]).unique()
            z, _ = memory(n_id)
            assoc = torch.zeros(n_entities, dtype=torch.long)
            assoc[n_id] = torch.arange(n_id.size(0))

            pred = predictor(z[assoc[src]], z[assoc[dst]])
            loss = loss_fn(pred, rel)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            memory.detach()
            memory.update_state(src, dst, t, msg)

            total_loss += loss.item() * len(src)
            n += len(src)
        print(f"  epoch {epoch}/{EPOCHS}  edge_type_loss={total_loss / max(1, n):.4f}")

    @torch.no_grad()
    def score_split(entries):
        """Replay this split's events through the trained (frozen-parameter,
        memory-still-updating) model in chronological continuation of
        training -- a real deployment keeps advancing memory after training
        ends. Per-event cross-entropy is the anomaly signal; a session's
        score is its mean per-edge prediction loss (Kairos's own
        "prediction error at each edge" scoring, aggregated to the
        graph/session level for this project's classification protocol)."""
        memory.eval()
        predictor.eval()
        src, dst, t, msg, rel, starts = to_batch_tensors(entries)
        per_edge_loss = np.zeros(len(src))
        for i in range(0, len(src), BATCH_SIZE):
            sl = slice(i, i + BATCH_SIZE)
            s, d_, tt, m, r = src[sl], dst[sl], t[sl], msg[sl], rel[sl]
            if len(s) == 0:
                continue
            n_id = torch.cat([s, d_]).unique()
            z, _ = memory(n_id)
            assoc = torch.zeros(n_entities, dtype=torch.long)
            assoc[n_id] = torch.arange(n_id.size(0))
            pred = predictor(z[assoc[s]], z[assoc[d_]])
            per_edge_loss[sl] = F.cross_entropy(pred, r, reduction="none").numpy()
            memory.update_state(s, d_, tt, m)

        scores, labels = [], []
        for gi, e in enumerate(entries):
            start_idx = starts[gi][1]
            end_idx = starts[gi + 1][1] if gi + 1 < len(starts) else len(src)
            seg = per_edge_loss[start_idx:end_idx]
            scores.append(float(seg.mean()) if len(seg) else 0.0)
            labels.append(e["label"])
        return np.array(scores), np.array(labels)

    val_scores, val_y = score_split(graphs["val"])
    grid = np.linspace(val_scores.min(), val_scores.max(), 200)
    theta = cm.best_f1_threshold(val_y, val_scores, grid=grid)
    test_scores, test_y = score_split(graphs["test"])
    rep = cm.binary_report(test_y, test_scores, theta)

    print(f"\nKairos (TGN edge-type-prediction error, benign-only) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"memory_dim": MEMORY_DIM, "time_dim": TIME_DIM, "n_entities": n_entities,
           "n_relations": n_relations, "theta": theta, "test": rep}
    out_path = OUT_DIR / "kairos_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
