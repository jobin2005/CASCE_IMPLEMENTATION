#!/usr/bin/env python3
"""ShadeWatcher (Zeng et al., IEEE S&P/Oakland 2022) baseline -- a real
implementation of its dominant component (TransR knowledge-graph embedding),
not a hand-wavy approximation, scaled to CASCE's data.

ShadeWatcher recasts threat detection as a recommendation problem: it
builds a knowledge graph (KG) of system-entity interactions and learns
which interactions are "expected" via TransR embedding, then refines with a
downstream GNN. Per independent analysis of the system (cited in our
provenance_baseline_results/shadewatcher_citation.md), TransR is reported
to be the dominant contributor to ShadeWatcher's detection accuracy -- so
implementing TransR-based interaction-plausibility scoring faithfully is a
disclosed, reasonably-scoped adaptation of the real method, not a
different algorithm wearing ShadeWatcher's name. The downstream GNN
refinement step is NOT reproduced here (out of scope given TransR is
described as the accuracy-dominant piece); this is stated plainly, not
hidden.

TransR (Lin et al., AAAI 2015), reproduced faithfully: each entity has an
embedding in entity space; each relation has both an embedding and its OWN
projection matrix that maps entity vectors into that relation's space
(unlike TransE's single shared space). A triple (h, r, t)'s plausibility is
scored by ||h_r + r - t_r||, trained via margin-ranking loss against
corrupted (random-tail) negatives -- exactly TransR's original formulation.

Disclosed adaptation, required by our setting: ShadeWatcher's real KG spans
ONE whole-system audit log, where entities (specific files, specific
processes) persist and recur across the whole trace, which is what makes a
KG embedding meaningful. CASCE's corpus is thousands of SEPARATE small
session graphs with session-local node IDs that never recur across graphs
-- embedding raw IDs would learn nothing transferable. Instead, entities
here are SEMANTIC KEYS: Table/Role/File/Configuration/Endpoint use their
actual name/address (these genuinely recur across many sessions, e.g. the
same table or the same attacker IP appears in many different sessions);
Process uses its command name (`comm`) rather than its per-session pid;
Behavior uses its MITRE-mapped label. Session and Query nodes have no
stable cross-session identity and collapse to their bare type -- and
deliberately do NOT use raw query text as a key, to avoid the exact
literal-token memorization shortcut flagged earlier in this project's
audit (a table/IP that only appears in some train families would otherwise
give TransR a de facto ID-lookup shortcut instead of learned structure).

Usage:
    python baseline_models/shadewatcher.py
"""
import json
import sys
from pathlib import Path

import networkx as nx
import numpy as np
import torch
import torch.nn as nn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

ENTITY_DIM = 32
RELATION_DIM = 16
MARGIN = 1.0
EPOCHS = 15
BATCH_SIZE = 256
LR = 1e-2
SEED = 42


def entity_key(node_type: str, attrs: dict) -> str:
    """Semantic cross-graph entity identity -- see module docstring for why
    this is necessary and why Query never uses raw text."""
    if node_type == "Table":
        return f"Table:{attrs.get('table_name', '?')}"
    if node_type == "Role":
        return f"Role:{attrs.get('role_name', '?')}"
    if node_type == "File":
        return f"File:{attrs.get('filepath', '?')}"
    if node_type == "Configuration":
        return f"Configuration:{attrs.get('setting_name', '?')}"
    if node_type == "Endpoint":
        return f"Endpoint:{attrs.get('dest_ip', '?')}:{attrs.get('dest_port', '?')}"
    if node_type == "Process":
        return f"Process:{attrs.get('comm', '?')}"
    if node_type == "Behavior":
        return f"Behavior:{attrs.get('behavior_label', '?')}"
    return node_type  # Session, Query: type-level only (see docstring)


def extract_triples(G: nx.MultiDiGraph):
    key_of = {n: entity_key(d.get("type", "?"), d) for n, d in G.nodes(data=True)}
    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    triples = []
    for edge in edge_iter:
        u, v, d = edge[0], edge[1], edge[-1]
        rel = d.get("relation", d.get("rel", "?"))
        triples.append((key_of[u], rel, key_of[v]))
    return triples


class TransR(nn.Module):
    def __init__(self, n_entities, n_relations, e_dim=ENTITY_DIM, r_dim=RELATION_DIM):
        super().__init__()
        self.ent = nn.Embedding(n_entities, e_dim)
        self.rel = nn.Embedding(n_relations, r_dim)
        self.proj = nn.Embedding(n_relations, e_dim * r_dim)
        nn.init.xavier_uniform_(self.ent.weight)
        nn.init.xavier_uniform_(self.rel.weight)
        nn.init.xavier_uniform_(self.proj.weight)
        self.e_dim, self.r_dim = e_dim, r_dim

    def score(self, h, r, t):
        """Lower = more plausible (standard TransR energy)."""
        h_e = self.ent(h)
        t_e = self.ent(t)
        r_e = self.rel(r)
        M = self.proj(r).view(-1, self.e_dim, self.r_dim)
        h_r = torch.bmm(h_e.unsqueeze(1), M).squeeze(1)
        t_r = torch.bmm(t_e.unsqueeze(1), M).squeeze(1)
        return torch.norm(h_r + r_e - t_r, p=2, dim=1)


def build_vocab(triples_by_graph):
    entities, relations = {}, {}
    for triples in triples_by_graph:
        for h, r, t in triples:
            entities.setdefault(h, len(entities))
            entities.setdefault(t, len(entities))
            relations.setdefault(r, len(relations))
    return entities, relations


def load_all():
    graphs = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        entries = []
        for fname, label in labels.items():
            path = GRAPHML_DIR / fname
            if not path.exists():
                continue
            G = nx.read_graphml(path)
            entries.append({"file": fname, "label": int(label), "triples": extract_triples(G)})
        graphs[part] = entries
    return graphs


def train_transr(train_benign_triples, entities, relations):
    torch.manual_seed(SEED)
    model = TransR(len(entities), len(relations))
    opt = torch.optim.Adam(model.parameters(), lr=LR)

    flat = [(entities[h], relations[r], entities[t]) for triples in train_benign_triples for h, r, t in triples]
    flat = np.array(flat, dtype=np.int64)
    n_ent = len(entities)
    print(f"  {len(flat)} positive triples, {n_ent} entities, {len(relations)} relations")

    rng = np.random.RandomState(SEED)
    for epoch in range(1, EPOCHS + 1):
        perm = rng.permutation(len(flat))
        total_loss, n_batches = 0.0, 0
        for i in range(0, len(flat), BATCH_SIZE):
            batch = flat[perm[i:i + BATCH_SIZE]]
            h = torch.tensor(batch[:, 0])
            r = torch.tensor(batch[:, 1])
            t = torch.tensor(batch[:, 2])
            t_neg = torch.tensor(rng.randint(0, n_ent, size=len(batch)))

            opt.zero_grad()
            pos_score = model.score(h, r, t)
            neg_score = model.score(h, r, t_neg)
            loss = torch.clamp(MARGIN + pos_score - neg_score, min=0).mean()
            loss.backward()
            opt.step()
            total_loss += loss.item()
            n_batches += 1
        print(f"  epoch {epoch}/{EPOCHS}  margin_loss={total_loss / max(1, n_batches):.4f}")
    return model


@torch.no_grad()
def graph_anomaly_scores(model, entries, entities, relations, unk_score):
    scores, labels = [], []
    for e in entries:
        energies = []
        for h, r, t in e["triples"]:
            if h not in entities or r not in relations or t not in entities:
                energies.append(unk_score)  # unseen entity/relation: maximally implausible
                continue
            hh = torch.tensor([entities[h]])
            rr = torch.tensor([relations[r]])
            tt = torch.tensor([entities[t]])
            energies.append(model.score(hh, rr, tt).item())
        scores.append(float(np.mean(energies)) if energies else 0.0)
        labels.append(e["label"])
    return np.array(scores), np.array(labels)


def main():
    print("Loading graphs + extracting KG triples (semantic entity keys, see module docstring)...")
    graphs = load_all()
    for part in ("train", "val", "test"):
        n_mal = sum(e["label"] for e in graphs[part])
        print(f"  {part}: {len(graphs[part])} ({n_mal} malicious, {len(graphs[part]) - n_mal} benign)")

    train_benign = [e["triples"] for e in graphs["train"] if e["label"] == 0]
    entities, relations = build_vocab(train_benign)
    print(f"\nTraining TransR on {len(train_benign)} TRAIN-BENIGN graphs' triples only "
          f"(ShadeWatcher is unsupervised/one-class)...")
    model = train_transr(train_benign, entities, relations)

    # A triple involving an entity/relation never seen in benign training is treated as
    # maximally implausible (worst observed training energy), not silently ignored.
    train_flat = np.array([[entities[h], relations[r], entities[t]]
                            for triples in train_benign for h, r, t in triples], dtype=np.int64)
    with torch.no_grad():
        train_energies = model.score(torch.tensor(train_flat[:, 0]), torch.tensor(train_flat[:, 1]),
                                      torch.tensor(train_flat[:, 2])).numpy()
    unk_score = float(train_energies.max())

    val_scores, val_y = graph_anomaly_scores(model, graphs["val"], entities, relations, unk_score)
    grid = np.linspace(val_scores.min(), val_scores.max(), 200)
    theta = cm.best_f1_threshold(val_y, val_scores, grid=grid)
    test_scores, test_y = graph_anomaly_scores(model, graphs["test"], entities, relations, unk_score)
    rep = cm.binary_report(test_y, test_scores, theta)

    print(f"\nShadeWatcher (TransR interaction-plausibility, benign-only) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned energy)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"entity_dim": ENTITY_DIM, "relation_dim": RELATION_DIM, "n_entities": len(entities),
           "n_relations": len(relations), "theta": theta, "test": rep}
    out_path = OUT_DIR / "shadewatcher_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
