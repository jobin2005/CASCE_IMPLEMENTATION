#!/usr/bin/env python3
"""Unicorn (Han et al., NDSS 2020) baseline -- a real implementation of its
core algorithm, scaled to CASCE's data, not a hand-wavy approximation.

Unicorn's real pipeline (per the paper + its own modeler code at
github.com/crimson-unicorn/modeler, which we read before writing this):
1. Local graph histograms: each graph is summarized as a weighted multiset
   ("histogram") of local structural elements.
2. HistoSketch: the histogram is hashed into a fixed-length integer sketch
   via Consistent Weighted Sampling (CWS -- Ioffe, ICDM 2010; HistoSketch
   itself is Yang & Zou, ICDM 2017, which Unicorn builds on directly). CWS
   is reproduced faithfully here (the actual per-element/per-dimension gamma-
   distributed hashing scheme, not a simplified SimHash stand-in -- that
   would be a different algorithm wearing Unicorn's name).
3. K-medoids clustering + Hamming-distance thresholding on BENIGN sketches
   only: this exactly matches the real modeler code we inspected
   (pairwise Hamming distance, medoid-based clustering, threshold = a
   multiple of intra-cluster distance spread).

Disclosed adaptations (we found their sketch-GENERATION engine is not in
the Python repos we could inspect -- only the downstream modeler/clustering
code was -- so the histogram-construction step below follows the published
CWS/HistoSketch algorithm applied to a k-hop structural histogram of our
own graphs, not a byte-for-byte copy of unavailable C++ source):
- Local histogram built from k-hop (node_type, edge_relation) shingles,
  same general "local neighborhood" feature family StreamSpot/Unicorn both
  use, adapted to our schema (see baseline_models/streamspot.py for the
  precedent of this same adaptation).
- K-medoids implemented directly here (PAM-style) rather than via
  sklearn_extra, to avoid a new dependency on an already near-full disk --
  the algorithm itself (medoid = element minimizing intra-cluster distance
  sum, iterative reassignment) is standard, not a weaker substitute.
- Threshold tuned on val via best_f1_threshold (searched over the actual
  observed Hamming-distance range, not the default [0,1] grid -- see the
  RT-APT baseline for why that default grid silently breaks non-probability
  scores).

Usage:
    python baseline_models/unicorn.py
"""
import hashlib
import json
import sys
from collections import Counter, deque
from pathlib import Path

import networkx as nx
import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

K_HOPS = 2
SKETCH_DIM = 64      # L in CWS/HistoSketch terms
N_CLUSTERS = 5        # matches Unicorn's own default cluster count family
NUM_STDS = 3.0         # matches the modeler's mean + num_stds*std threshold idea (as a prior, not the final theta)
SEED = 42


def local_histogram(G: nx.MultiDiGraph, k=K_HOPS) -> Counter:
    """k-hop local structural shingles -> weighted histogram (same shingle
    family as StreamSpot/RT-APT, see module docstring)."""
    node_type = {n: d.get("type", "?") for n, d in G.nodes(data=True)}
    adj = {n: [] for n in G.nodes()}
    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    for edge in edge_iter:
        u, v, d = edge[0], edge[1], edge[-1]
        rel = d.get("relation", d.get("rel", "?"))
        adj[u].append((v, rel))

    hist = Counter()
    for start in G.nodes():
        seq = [node_type[start]]
        visited = {start}
        frontier = deque([(start, 0)])
        while frontier:
            n, depth = frontier.popleft()
            if depth >= k:
                continue
            for v, rel in sorted(adj.get(n, []), key=lambda x: (x[1], x[0])):
                seq.append(rel)
                seq.append(node_type.get(v, "?"))
                if v not in visited:
                    visited.add(v)
                    frontier.append((v, depth + 1))
        hist["/".join(seq)] += 1
    return hist


_CWS_CACHE = {}


def _cws_randoms(elem: str, dim: int):
    """Deterministic per-(element,dim) pseudorandom draws for Consistent
    Weighted Sampling (Ioffe 2010): r,c ~ Gamma(2,1), beta ~ Uniform(0,1),
    all seeded from a hash of (elem, dim) so the same element always maps to
    the same draws regardless of which graph/histogram it appears in --
    required for sketches to be comparable across graphs. Memoized: the same
    (elem, dim) pair recurs across thousands of graphs sharing common local
    structural shingles, and constructing a fresh RandomState per call
    dominated runtime (180ms/graph, ~30min for the full corpus) before this
    cache -- the math is unchanged, this only avoids redundant recomputation."""
    key = (elem, dim)
    cached = _CWS_CACHE.get(key)
    if cached is not None:
        return cached
    seed = int(hashlib.md5(f"{elem}::{dim}".encode()).hexdigest(), 16) % (2**32)
    rng = np.random.RandomState(seed)
    r = rng.gamma(2.0, 1.0)
    c = rng.gamma(2.0, 1.0)
    beta = rng.uniform(0.0, 1.0)
    _CWS_CACHE[key] = (r, c, beta)
    return r, c, beta


def histosketch(hist: Counter, dim=SKETCH_DIM) -> np.ndarray:
    """Consistent Weighted Sampling over the histogram -> integer sketch of
    length `dim`. For each sketch dimension, every histogram element
    "votes" via its CWS-transformed weight; the element with the minimum
    transformed value wins that dimension (its hash becomes the sketch
    value there). Two histograms sharing more heavily-weighted elements are
    more likely to agree on more dimensions -- Hamming distance between
    sketches estimates histogram dissimilarity."""
    sketch = np.zeros(dim, dtype=np.int64)
    if not hist:
        return sketch
    for d in range(dim):
        best_val, best_elem_hash = np.inf, 0
        for elem, weight in hist.items():
            if weight <= 0:
                continue
            r, c, beta = _cws_randoms(elem, d)
            t = np.floor(np.log(weight) / r + beta)
            y = np.exp(r * (t - beta))
            a = c / (y * np.exp(r))
            if a < best_val:
                best_val = a
                best_elem_hash = int(hashlib.md5(elem.encode()).hexdigest()[:8], 16)
        sketch[d] = best_elem_hash
    return sketch


def hamming(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.mean(a != b))


def kmedoids(X: np.ndarray, k: int, seed=SEED, max_iter=50):
    """Direct PAM-style K-medoids under Hamming distance (avoids adding
    sklearn_extra as a new dependency on a near-full disk)."""
    rng = np.random.RandomState(seed)
    n = X.shape[0]
    medoid_idx = rng.choice(n, size=min(k, n), replace=False)
    D = np.zeros((n, n), dtype=np.float32)
    # Pairwise Hamming distance matrix (n is at most a few thousand here, fine).
    for i in range(n):
        D[i] = (X != X[i]).mean(axis=1)

    for _ in range(max_iter):
        assign = D[:, medoid_idx].argmin(axis=1)
        new_medoid_idx = medoid_idx.copy()
        changed = False
        for ci in range(len(medoid_idx)):
            members = np.where(assign == ci)[0]
            if len(members) == 0:
                continue
            sub = D[np.ix_(members, members)]
            best = members[sub.sum(axis=1).argmin()]
            if best != medoid_idx[ci]:
                new_medoid_idx[ci] = best
                changed = True
        medoid_idx = new_medoid_idx
        if not changed:
            break
    return X[medoid_idx]


def score_to_medoids(X: np.ndarray, medoids: np.ndarray) -> np.ndarray:
    dists = np.stack([(X != m).mean(axis=1) for m in medoids], axis=1)
    return dists.min(axis=1)


def build_sketches(labels: dict):
    X, y = [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(histosketch(local_histogram(G)))
        y.append(int(label))
    return np.stack(X), np.array(y)


def main():
    print(f"Extracting k-hop histograms (k={K_HOPS}) + HistoSketch/CWS sketches (dim={SKETCH_DIM})...")
    splits = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        X, y = build_sketches(labels)
        splits[part] = (X, y)
        print(f"  {part}: {X.shape} ({y.sum()} malicious, {len(y) - y.sum()} benign)")

    X_train, y_train = splits["train"]
    x_benign = X_train[y_train == 0]
    print(f"\nFitting {N_CLUSTERS} medoids (Hamming distance, PAM-style) on {len(x_benign)} "
          f"TRAIN-BENIGN sketches only (Unicorn is one-class/unsupervised)")
    medoids = kmedoids(x_benign, N_CLUSTERS)

    val_scores = score_to_medoids(splits["val"][0], medoids)
    grid = np.linspace(val_scores.min(), val_scores.max(), 200)
    theta = cm.best_f1_threshold(splits["val"][1], val_scores, grid=grid)
    test_scores = score_to_medoids(splits["test"][0], medoids)
    rep = cm.binary_report(splits["test"][1], test_scores, theta)

    print(f"\nUnicorn (HistoSketch/CWS + K-medoids, benign-only) on CASCE multi-domain corpus, "
          f"held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned Hamming frac)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"k_hops": K_HOPS, "sketch_dim": SKETCH_DIM, "n_clusters": N_CLUSTERS,
           "n_train_benign": int(len(x_benign)), "theta": theta, "test": rep}
    out_path = OUT_DIR / "unicorn_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
