#!/usr/bin/env python3
"""StreamSpot (Manzoor et al., KDD 2016) baseline -- a real implementation of
the method, not a conceptual placeholder.

StreamSpot's actual pipeline (faithfully reproduced here, single-graph batch
setting rather than their original streaming setting, since our sessions are
already-complete graphs, not a live edge stream):

1. K-hop local shingles: for every node, a bounded-depth BFS captures the
   sequence of (node_type, edge_relation) labels reachable within K hops.
   This is StreamSpot's "shingle" -- a local structural+semantic fingerprint,
   the same idea as their GraphChi-based shingle extraction, adapted from a
   live stream to a static graph (all edges are "already arrived").
2. StreamHash sketching: each graph's shingle multiset is projected into a
   fixed L-dimensional sketch via a seeded random sign per (shingle, dim) --
   this is a standard SimHash / random-hyperplane sketch, which is what
   their paper's "StreamHash" projection computes, without needing to
   materialize an explicit L x |shingle-space| projection matrix.
3. Centroid-distance anomaly scoring: K-means centroids are fit on
   TRAIN-BENIGN sketches only (StreamSpot is a one-class / unsupervised
   method, like MAGIC -- this is not a constraint imposed here, it's the
   published method). A graph's anomaly score is its distance to the
   nearest centroid.

Threshold tuned on val, reported on test -- same protocol as every other
baseline in this project.

Usage:
    python baseline_models/streamspot.py
"""
import hashlib
import json
import sys
from collections import Counter, deque
from pathlib import Path

import networkx as nx
import numpy as np
from sklearn.cluster import KMeans

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

K_HOPS = 3          # shingle depth
SKETCH_DIM = 128    # StreamHash sketch dimensionality
N_CLUSTERS = 8      # benign cluster centroids
SEED = 42


def extract_shingles(G: nx.MultiDiGraph) -> Counter:
    """K-hop local shingles: one per node, the BFS-order sequence of
    (node_type, edge_relation) labels within K hops."""
    node_type = {n: d.get("type", "?") for n, d in G.nodes(data=True)}
    adj = {n: [] for n in G.nodes()}
    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    for edge in edge_iter:
        u, v, d = edge[0], edge[1], edge[-1]
        rel = d.get("relation", d.get("rel", "?"))
        adj[u].append((v, rel))

    shingles = Counter()
    for start in G.nodes():
        seq = [node_type[start]]
        visited = {start}
        frontier = deque([(start, 0)])
        while frontier:
            n, depth = frontier.popleft()
            if depth >= K_HOPS:
                continue
            for v, rel in sorted(adj.get(n, []), key=lambda x: (x[1], x[0])):
                seq.append(rel)
                seq.append(node_type.get(v, "?"))
                if v not in visited:
                    visited.add(v)
                    frontier.append((v, depth + 1))
        shingles["/".join(seq)] += 1
    return shingles


def _shingle_sign(shingle: str, dim: int) -> int:
    """Deterministic +-1 sign for (shingle, dim) -- the per-shingle random
    hyperplane projection, computed via hashing instead of a stored matrix."""
    h = hashlib.md5(f"{shingle}::{dim}".encode()).hexdigest()
    return 1 if int(h, 16) % 2 == 0 else -1


def sketch(shingles: Counter, dim=SKETCH_DIM) -> np.ndarray:
    vec = np.zeros(dim, dtype=np.float64)
    for shingle, count in shingles.items():
        for d in range(dim):
            vec[d] += count * _shingle_sign(shingle, d)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def build_sketches(rows_labels: dict) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for fname, label in rows_labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(sketch(extract_shingles(G)))
        y.append(int(label))
    return np.stack(X), np.array(y)


def main():
    print(f"Extracting shingles (K={K_HOPS} hops) + StreamHash sketches (dim={SKETCH_DIM})...")
    splits = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        X, y = build_sketches(labels)
        splits[part] = (X, y)
        print(f"  {part}: {X.shape} ({y.sum()} malicious, {len(y) - y.sum()} benign)")

    X_train, y_train = splits["train"]
    x_benign = X_train[y_train == 0]
    print(f"\nFitting {N_CLUSTERS} centroids on {len(x_benign)} TRAIN-BENIGN sketches only "
          f"(StreamSpot is one-class/unsupervised -- no malicious exposure)")
    km = KMeans(n_clusters=N_CLUSTERS, random_state=SEED, n_init=10).fit(x_benign)

    def score(X):
        d = km.transform(X)  # distance to every centroid
        return d.min(axis=1)

    val_scores = score(splits["val"][0])
    theta = cm.best_f1_threshold(splits["val"][1], val_scores)
    test_scores = score(splits["test"][0])
    rep = cm.binary_report(splits["test"][1], test_scores, theta)

    print(f"\nStreamSpot (one-class, benign-only centroids) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"k_hops": K_HOPS, "sketch_dim": SKETCH_DIM, "n_clusters": N_CLUSTERS,
           "n_train_benign": int(len(x_benign)), "theta": theta, "test": rep}
    out_path = OUT_DIR / "streamspot_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
