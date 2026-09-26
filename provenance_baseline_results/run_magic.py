#!/usr/bin/env python3
"""Train + evaluate MAGIC (unmodified model/training code) on the CASCE
multi-domain corpus.

MAGIC's batch-level mode is self-supervised: a masked-graph autoencoder
trained on BENIGN graphs only (this is MAGIC's own design, not a constraint
imposed here -- it gets strictly less supervision than every other baseline
in this comparison, which trains on both classes).

Evaluation deliberately does NOT reuse MAGIC's own evaluate_batch_level_using_knn
(model/eval.py), because that function re-shuffles and re-samples its own
train/test split internally (ignoring any external split), which would make
its numbers incomparable to the rest of this project's family-disjoint
protocol. Instead: fit the k-NN reference on OUR train-split benign
embeddings only, tune the threshold on OUR val split, report on OUR test
split -- the same protocol as every other baseline script in this repo.
"""
import json
import sys
from pathlib import Path

import _dgl_compat  # noqa: E402,F401  -- must run before `import dgl`, see that file
import dgl
import networkx as nx
import numpy as np
import torch
from sklearn.neighbors import NearestNeighbors

MAGIC_DIR = Path(__file__).resolve().parent / "magic"
sys.path.insert(0, str(MAGIC_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model.autoencoder import build_model  # noqa: E402
from model.train import batch_level_train  # noqa: E402
from utils.loaddata import transform_graph  # noqa: E402
from utils.utils import set_random_seed, create_optimizer  # noqa: E402
from casce_metrics import best_f1_threshold, binary_report  # noqa: E402

DATA_DIR = MAGIC_DIR / "data" / "casce"
SEED = 0
MAX_EPOCH = 5      # matches MAGIC's own streamspot config (num_hidden=256, max_epoch=5, num_layers=4)
BATCH_SIZE = 12


class Args:
    lr = 0.001
    weight_decay = 5e-4
    negative_slope = 0.2
    mask_rate = 0.5
    alpha_l = 3
    optimizer = "adam"
    num_hidden = 256
    num_layers = 4


def load_split():
    manifest = json.loads((DATA_DIR / "manifest.json").read_text())
    graphs = {}
    node_dim = 0
    edge_dim = 0
    for part, entries in manifest["splits"].items():
        for e in entries:
            data = json.loads((DATA_DIR / e["file"]).read_text())
            g = dgl.from_networkx(nx.node_link_graph(data), node_attrs=["type"], edge_attrs=["type"])
            graphs[e["idx"]] = (g, e["label"])
            node_dim = max(node_dim, int(g.ndata["type"].max().item()))
            edge_dim = max(edge_dim, int(g.edata["type"].max().item()) if g.num_edges() else 0)
    return manifest, graphs, node_dim + 1, edge_dim + 1


def pooled_embed(model, g, n_dim, e_dim):
    g = transform_graph(g, n_dim, e_dim)
    with torch.no_grad():
        rep = model.embed(g)
    return rep.mean(0).numpy()  # graph-level mean pool, same as MAGIC's own Pooling(mean)


def main():
    set_random_seed(SEED)
    manifest, graphs, n_dim, e_dim = load_split()
    print(f"loaded {len(graphs)} graphs, n_dim={n_dim} e_dim={e_dim}")

    train_entries = manifest["splits"]["train"]
    train_benign_idx = [e["idx"] for e in train_entries if e["label"] == 0]
    print(f"MAGIC trains on {len(train_benign_idx)} BENIGN-only train graphs "
          f"(of {len(train_entries)} total train graphs -- self-supervised, no malicious exposure)")

    args = Args()
    args.n_dim, args.e_dim = n_dim, e_dim
    model = build_model(args)
    optimizer = create_optimizer(args.optimizer, model, args.lr, args.weight_decay)

    class Loader:
        def __iter__(self):
            import random
            idxs = list(train_benign_idx)
            random.shuffle(idxs)
            for i in range(0, len(idxs), BATCH_SIZE):
                yield idxs[i:i + BATCH_SIZE]

    graphs_list_by_idx = {k: v for k, v in graphs.items()}
    model = batch_level_train(model, graphs_list_by_idx, Loader(), optimizer, MAX_EPOCH, "cpu", n_dim, e_dim)
    (MAGIC_DIR / "checkpoints").mkdir(exist_ok=True)
    torch.save(model.state_dict(), MAGIC_DIR / "checkpoints" / "checkpoint-casce.pt")

    model.eval()
    embeds, labels_by_part = {}, {}
    for part in ("train", "val", "test"):
        idxs = [e["idx"] for e in manifest["splits"][part]]
        labels_by_part[part] = np.array([graphs[i][1] for i in idxs])
        embeds[part] = np.stack([pooled_embed(model, graphs[i][0], n_dim, e_dim) for i in idxs])
        print(f"embedded {part}: {embeds[part].shape}")

    train_labels = labels_by_part["train"]
    x_ref = embeds["train"][train_labels == 0]  # k-NN reference: train-benign only
    mu, sigma = x_ref.mean(0), x_ref.std(0) + 1e-6
    x_ref_n = (x_ref - mu) / sigma

    n_neighbors = min(max(int(len(x_ref) * 0.02), 2), 10)
    nbrs = NearestNeighbors(n_neighbors=n_neighbors).fit(x_ref_n)
    d_ref, _ = nbrs.kneighbors(x_ref_n, n_neighbors=n_neighbors)
    mean_ref_dist = d_ref.mean() * n_neighbors / (n_neighbors - 1)

    def score(part):
        x = (embeds[part] - mu) / sigma
        d, _ = nbrs.kneighbors(x, n_neighbors=n_neighbors)
        return d.mean(axis=1) / mean_ref_dist

    val_scores, test_scores = score("val"), score("test")
    theta = best_f1_threshold(labels_by_part["val"], val_scores)
    rep = binary_report(labels_by_part["test"], test_scores, theta)
    print(f"\nMAGIC (self-supervised, benign-only training) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta_A(tuned on val)={theta:.3f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"theta_A": theta, "n_train_benign": len(train_benign_idx),
           "n_train_total": len(train_entries), "test": rep}
    out_path = Path(__file__).resolve().parent / "magic_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
