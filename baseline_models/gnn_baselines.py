#!/usr/bin/env python3
"""GNN baselines (GCN, GraphSAGE, GAT, GATv2) against CASCE's own GAT.

Uses the EXACT SAME graph representation as CASCE's GAT (algorithm_4_hybrid.
build_hetero_data / ALL_NODE_TYPES / EDGE_TYPES / NUM_NODE_FEATS), and the
same family-disjoint split -- only the conv layer changes, so any accuracy
delta is attributable to architecture, not data or features.

GCNConv does not support heterogeneous/bipartite message passing (raises
ValueError). Per PyTorch Geometric's own guidance for this case, GraphConv is
used as GCN's drop-in substitute here -- a documented, disclosed
substitution, not a silent swap.

Unlike algorithm_4_hybrid.py's own (unbatched, one-graph-at-a-time) training
loop, this script batches graphs via torch_geometric's DataLoader for
tractable wall-clock time across 4 models x thousands of graphs. Batching is
a training-speed technique; it does not change what representation the model
sees per graph.

Usage:
    python baseline_models/gnn_baselines.py
"""
import json
import sys
import time
from pathlib import Path

import networkx as nx
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from torch_geometric.loader import DataLoader
from torch_geometric.nn import GCNConv, GraphConv, SAGEConv, GATConv, GATv2Conv, HeteroConv, global_mean_pool

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import algorithm_4_hybrid as a4  # noqa: E402
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_RESULTS = REPO / "gnn_results"
OUT_MODELS = REPO / "baseline_models" / "checkpoints"

HIDDEN_DIM = a4.HIDDEN_DIM   # 32, same as CASCE's own GAT
HEADS = a4.HEADS             # 4
NUM_LAYERS = a4.NUM_LAYERS   # 2
NODE_TYPES = a4.ALL_NODE_TYPES
EDGE_TYPES = a4.EDGE_TYPES
IN_DIM = a4.NUM_NODE_FEATS
BATCH_SIZE = 32
MAX_EPOCHS = 15
PATIENCE = 5
SEED = 42

# GCNConv can't do heterogeneous/bipartite message passing -- GraphConv is
# PyG's own suggested substitute (see module docstring).
CONV_BUILDERS = {
    "gcn":   lambda in_d, out_d: GraphConv(in_d, out_d * HEADS, aggr="add"),
    "sage":  lambda in_d, out_d: SAGEConv(in_d, out_d * HEADS),
    "gat":   lambda in_d, out_d: GATConv((in_d, in_d), out_d, heads=HEADS, add_self_loops=False),
    "gatv2": lambda in_d, out_d: GATv2Conv((in_d, in_d), out_d, heads=HEADS, add_self_loops=False),
}


class HeteroGNNBaseline(nn.Module):
    def __init__(self, conv_type, in_dim=IN_DIM, hidden_dim=HIDDEN_DIM,
                 num_layers=NUM_LAYERS, node_types=NODE_TYPES, edge_types=EDGE_TYPES, dropout=0.2):
        super().__init__()
        self.node_types = node_types
        self.conv_type = conv_type
        self.dropout = dropout
        builder = CONV_BUILDERS[conv_type]

        self.convs = nn.ModuleList()
        layer_in = in_dim
        for _ in range(num_layers):
            conv_dict = {et: builder(layer_in, hidden_dim) for et in edge_types}
            self.convs.append(HeteroConv(conv_dict, aggr="sum"))
            layer_in = hidden_dim * HEADS

        pooled_dim = hidden_dim * HEADS * len(node_types)
        self.classifier = nn.Sequential(
            nn.Linear(pooled_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, data):
        x_dict = data.x_dict
        edge_index_dict = data.edge_index_dict
        out_dim = HIDDEN_DIM * HEADS

        for conv in self.convs:
            x_dict = conv(x_dict, edge_index_dict)
            x_dict = {k: F.elu(v) for k, v in x_dict.items()}
            for nt in self.node_types:
                if nt not in x_dict:
                    x_dict[nt] = torch.zeros((0, out_dim))

        num_graphs = data.num_graphs
        pooled_parts = []
        for nt in self.node_types:
            x = x_dict.get(nt)
            batch = data[nt].batch if nt in data.node_types else None
            if x is not None and x.size(0) > 0 and batch is not None:
                pooled_parts.append(global_mean_pool(x, batch, size=num_graphs))
            else:
                pooled_parts.append(torch.zeros(num_graphs, out_dim))
        graph_repr = torch.cat(pooled_parts, dim=1)
        return self.classifier(graph_repr).squeeze(-1)


def load_dataset(name):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    dataset = []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        data = a4.build_hetero_data(G)
        data.y = torch.tensor([float(label)])
        dataset.append(data)
    return dataset


def run_epoch(model, loader, optimizer, loss_fn, train: bool):
    model.train() if train else model.eval()
    total_loss, n = 0.0, 0
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for batch in loader:
            if train:
                optimizer.zero_grad()
            logits = model(batch)
            loss = loss_fn(logits, batch.y)
            if train:
                loss.backward()
                optimizer.step()
            total_loss += loss.item() * batch.num_graphs
            n += batch.num_graphs
    return total_loss / max(1, n)


@torch.no_grad()
def predict_probs(model, loader):
    model.eval()
    probs, ys = [], []
    for batch in loader:
        logits = model(batch)
        probs.append(torch.sigmoid(logits))
        ys.append(batch.y)
    return torch.cat(probs).numpy(), torch.cat(ys).numpy().astype(int)


def count_parameters(model):
    return sum(p.numel() for p in model.parameters())


def main():
    torch.manual_seed(SEED)
    OUT_RESULTS.mkdir(exist_ok=True)
    OUT_MODELS.mkdir(parents=True, exist_ok=True)

    print("Loading + building HeteroData for all splits (same representation as CASCE's own GAT)...")
    t0 = time.time()
    train_ds = load_dataset("train")
    val_ds = load_dataset("val")
    test_ds = load_dataset("test")
    print(f"train={len(train_ds)} val={len(val_ds)} test={len(test_ds)}  ({time.time()-t0:.0f}s)")

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE)

    n_pos = sum(int(d.y.item()) for d in train_ds)
    pos_weight = torch.tensor([(len(train_ds) - n_pos) / max(1, n_pos)])

    summary = {}
    for conv_type in ("gcn", "sage", "gat", "gatv2"):
        print(f"\n{'='*60}\n{conv_type.upper()}\n{'='*60}")
        torch.manual_seed(SEED)
        model = HeteroGNNBaseline(conv_type)
        n_params = count_parameters(model)
        print(f"parameters: {n_params:,}")
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

        best_val_loss, patience_ctr, best_state, epochs_run = float("inf"), 0, None, 0
        t0 = time.time()
        for epoch in range(1, MAX_EPOCHS + 1):
            train_loss = run_epoch(model, train_loader, optimizer, loss_fn, train=True)
            val_loss = run_epoch(model, val_loader, optimizer, loss_fn, train=False)
            epochs_run = epoch
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
        train_time = time.time() - t0
        torch.save(model.state_dict(), OUT_MODELS / f"gnn_{conv_type}.pt")

        val_probs, val_y = predict_probs(model, val_loader)
        theta = cm.best_f1_threshold(val_y, val_probs)
        test_probs, test_y = predict_probs(model, test_loader)
        report = cm.binary_report(test_y, test_probs, theta)

        print(f"  theta(val-tuned)={theta:.3f}  epochs={epochs_run}  train_time={train_time:.0f}s")
        print(f"  test: acc={report['accuracy']:.4f} prec={report['precision']:.4f} "
              f"rec={report['recall']:.4f} f1={report['f1']:.4f} fpr={report['fpr']:.4f} "
              f"roc_auc={report['roc_auc']} brier={report['brier']:.4f}")
        print(f"  confusion: tp={report['tp']} fp={report['fp']} fn={report['fn']} tn={report['tn']}")

        out = {"conv_type": conv_type, "n_parameters": n_params, "epochs_run": epochs_run,
               "train_time_sec": round(train_time, 1), "theta": theta, "test": report}
        (OUT_RESULTS / f"{conv_type}.json").write_text(json.dumps(out, indent=2, default=float))
        summary[conv_type] = {"n_parameters": n_params, "epochs_run": epochs_run, **report}

    (OUT_RESULTS / "summary.json").write_text(json.dumps(summary, indent=2, default=float))
    print(f"\nSaved per-model results + summary.json -> {OUT_RESULTS}")


if __name__ == "__main__":
    main()
