#!/usr/bin/env python3
"""FLASH-IDS (Rehman et al., IEEE S&P 2024) baseline -- adapted from their
actual published method (DART-Laboratory/Flash-IDS, streamspot.ipynb), not a
placeholder.

FLASH's real mechanism, reproduced here:
1. Word2Vec node "documents": each node's document is the sequence of edge-
   relation tokens ("action" in their code) on edges touching that node
   (their prepare_graph() appends the action to both the actor's and the
   object's document list -- reproduced identically here).
2. Node features: each token is embedded via Word2Vec, a sinusoidal
   positional encoding is added (their PositionalEncoder class, reproduced
   verbatim), then mean-pooled into one fixed-size vector per node
   (their infer() function, reproduced verbatim).
3. Self-supervised pretext task: a 2-layer SAGEConv GNN is trained to
   predict each node's TYPE from its neighborhood -- NOT the malicious/
   benign label. This is exactly their design (their dummy labels are
   entity-type codes 'a'-'h'), not a leak: node type is available for both
   classes and isn't the thing being evaluated.
4. Anomaly score: at inference, count how many nodes have their type
   MISPREDICTED by the trained GNN (their `cond = ~(pred == graph.y)`,
   reproduced verbatim). A graph with abnormal structure "confuses" the
   type-predictor more.

One disclosed adaptation: their code uses a hardcoded absolute count
threshold (thresh=200), which only makes sense because their benchmark's
graphs are all the same size. CASCE's session graphs vary in size (tens to
hundreds of nodes), so a raw count doesn't transfer -- this uses the
FRACTION of mispredicted nodes instead, with the threshold tuned on val via
the same best_f1_threshold protocol as every other baseline in this project
(arguably more principled than their fixed 200 anyway, not a weakening).

Usage:
    python baseline_models/flash.py
"""
import json
import math
import sys
from pathlib import Path

import networkx as nx
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from gensim.models import Word2Vec
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

W2V_DIM = 30       # matches FLASH's own streamspot config
HIDDEN_DIM = 32    # matches FLASH's own GCN class
BATCH_SIZE = 32
MAX_EPOCHS = 15
PATIENCE = 5
SEED = 42

NODE_TYPES = ["Session", "Role", "Query", "Table", "Process", "File",
              "Endpoint", "Configuration", "Behavior"]
TYPE_TO_IDX = {t: i for i, t in enumerate(NODE_TYPES)}


class PositionalEncoder:
    """Verbatim from FLASH's own code."""
    def __init__(self, d_model, max_len=100000):
        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        self.pe = torch.zeros(max_len, d_model)
        self.pe[:, 0::2] = torch.sin(position * div_term)
        self.pe[:, 1::2] = torch.cos(position * div_term)

    def embed(self, x):
        return x + self.pe[:x.size(0)]


class FlashGNN(nn.Module):
    """Verbatim architecture from FLASH's own streamspot.ipynb GCN class."""
    def __init__(self, in_channel, out_channel):
        super().__init__()
        self.conv1 = SAGEConv(in_channel, HIDDEN_DIM, normalize=True)
        self.conv2 = SAGEConv(HIDDEN_DIM, out_channel, normalize=True)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = x.relu()
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.conv2(x, edge_index)
        return x


def prepare_graph(G: nx.MultiDiGraph):
    """Same shape as FLASH's own prepare_graph(): per-node document (list of
    incident edge-relation tokens) + node type label + homogeneous edge_index."""
    node_ids = list(G.nodes())
    idx_of = {n: i for i, n in enumerate(node_ids)}
    docs = {n: [] for n in node_ids}
    type_label = np.zeros(len(node_ids), dtype=np.int64)
    for n, d in G.nodes(data=True):
        type_label[idx_of[n]] = TYPE_TO_IDX.get(d.get("type"), 0)

    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    src, dst = [], []
    for edge in edge_iter:
        u, v, d = edge[0], edge[1], edge[-1]
        rel = d.get("relation", d.get("rel", "?"))
        docs[u].append(rel)
        docs[v].append(rel)
        src.append(idx_of[u]); dst.append(idx_of[v])

    documents = [docs[n] for n in node_ids]
    edge_index = np.array([src, dst], dtype=np.int64) if src else np.zeros((2, 0), dtype=np.int64)
    return documents, type_label, edge_index


def infer(document, w2v, encoder, dim=W2V_DIM):
    """Verbatim logic from FLASH's own infer()."""
    word_embeddings = [w2v.wv[tok] for tok in document if tok in w2v.wv]
    if not word_embeddings:
        return np.zeros(dim, dtype=np.float32)
    out = torch.tensor(np.array(word_embeddings), dtype=torch.float)
    out = encoder.embed(out)
    return out.detach().cpu().numpy().mean(axis=0)


def load_all_graphs():
    graphs = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        for fname, label in labels.items():
            path = GRAPHML_DIR / fname
            if not path.exists():
                continue
            G = nx.read_graphml(path)
            documents, type_label, edge_index = prepare_graph(G)
            graphs.setdefault(part, []).append(
                {"file": fname, "label": int(label), "documents": documents,
                 "type_label": type_label, "edge_index": edge_index})
    return graphs


def build_pyg_dataset(entries, w2v, encoder):
    ds = []
    for e in entries:
        feats = np.stack([infer(doc, w2v, encoder) for doc in e["documents"]])
        data = Data(x=torch.tensor(feats, dtype=torch.float),
                    y=torch.tensor(e["type_label"], dtype=torch.long),
                    edge_index=torch.tensor(e["edge_index"], dtype=torch.long))
        data.graph_label = e["label"]
        ds.append(data)
    return ds


def run_epoch(model, loader, optimizer, loss_fn, train: bool):
    model.train() if train else model.eval()
    total_loss, n = 0.0, 0
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for batch in loader:
            if train:
                optimizer.zero_grad()
            out = model(batch.x, batch.edge_index)
            loss = loss_fn(out, batch.y)
            if train:
                loss.backward()
                optimizer.step()
            total_loss += loss.item() * batch.num_graphs
            n += batch.num_graphs
    return total_loss / max(1, n)


@torch.no_grad()
def mispredict_fraction(model, loader):
    model.eval()
    scores, labels = [], []
    for batch in loader:
        out = model(batch.x, batch.edge_index)
        pred = out.argmax(dim=1)
        wrong = (pred != batch.y).float()
        for g in range(batch.num_graphs):
            mask = batch.batch == g
            scores.append(wrong[mask].mean().item())
            labels.append(batch.graph_label[g].item() if torch.is_tensor(batch.graph_label)
                           else batch.graph_label[g])
    return np.array(scores), np.array(labels)


def main():
    torch.manual_seed(SEED)
    print("Loading graphs + building node documents...")
    graphs = load_all_graphs()
    for part in ("train", "val", "test"):
        n_mal = sum(e["label"] for e in graphs[part])
        print(f"  {part}: {len(graphs[part])} ({n_mal} malicious, {len(graphs[part]) - n_mal} benign)")

    print(f"\nTraining Word2Vec (dim={W2V_DIM}) on TRAIN split node documents...")
    train_docs = [doc for e in graphs["train"] for doc in e["documents"] if doc]
    w2v = Word2Vec(sentences=train_docs, vector_size=W2V_DIM, window=10, min_count=1,
                    workers=4, epochs=20, seed=SEED)
    encoder = PositionalEncoder(W2V_DIM)
    print(f"  vocab: {len(w2v.wv)} tokens (edge-relation types)")

    print("\nBuilding PyG datasets (Word2Vec + positional-encoding node features)...")
    train_ds = build_pyg_dataset(graphs["train"], w2v, encoder)
    val_ds = build_pyg_dataset(graphs["val"], w2v, encoder)
    test_ds = build_pyg_dataset(graphs["test"], w2v, encoder)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE)

    print(f"\nTraining node-type pretext GNN (self-supervised -- predicts node TYPE, "
          f"not attack/benign; trained on both classes, per FLASH's own design)...")
    model = FlashGNN(W2V_DIM, len(NODE_TYPES))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    loss_fn = nn.CrossEntropyLoss()

    best_val_loss, patience_ctr, best_state = float("inf"), 0, None
    for epoch in range(1, MAX_EPOCHS + 1):
        train_loss = run_epoch(model, train_loader, optimizer, loss_fn, train=True)
        val_loss = run_epoch(model, val_loader, optimizer, loss_fn, train=False)
        print(f"  epoch {epoch}/{MAX_EPOCHS}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")
        if val_loss < best_val_loss:
            best_val_loss, patience_ctr = val_loss, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f"  early stopping at epoch {epoch}")
                break
    if best_state is not None:
        model.load_state_dict(best_state)

    val_scores, val_y = mispredict_fraction(model, val_loader)
    theta = cm.best_f1_threshold(val_y, val_scores)
    test_scores, test_y = mispredict_fraction(model, test_loader)
    rep = cm.binary_report(test_y, test_scores, theta)

    print(f"\nFLASH (node-type-mispredict anomaly score) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned fraction)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"w2v_dim": W2V_DIM, "theta_fraction": theta, "test": rep}
    out_path = OUT_DIR / "flash_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
