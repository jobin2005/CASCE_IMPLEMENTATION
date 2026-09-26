#!/usr/bin/env python3
"""RT-APT (Weng et al., J. Network and Computer Applications 2024) baseline,
adapted from the actual published implementation (github.com/luannd4869/RT-APT,
src/streamspot/streamspot.ipynb), not a placeholder.

RT-APT's real streamspot-track pipeline, reproduced here:
1. Weisfeiler-Lehman subtree relabeling: each node starts labeled with its
   type; K=3 rounds of relabeling combine a node's current label with the
   SORTED labels of its predecessors+successors and MD5-hash the result into
   a new label (their wl_subtree_features(), reproduced verbatim). This
   captures increasingly larger local-structure equivalence classes.
2. FlexSketch: every node's full label history (initial + all K iterations)
   is pooled into one multiset per graph; the graph's sketch is the raw
   frequency COUNT of its top-100 most common labels, i.e. a rank-frequency
   profile, not a fixed per-label feature axis (their FlexSketch class,
   reproduced verbatim -- unusual but that is genuinely their published
   design, streaming-histogram machinery included even though a single
   static-graph update collapses it to one histogram).
3. K-means anomaly scoring: 5 centroids fit on standardized TRAIN-BENIGN
   sketches only (their own one-class design, no malicious exposure).
   Anomaly score = distance to the nearest centroid.

One disclosed adaptation: their own threshold rule is a fixed 98.5th
percentile of BENIGN training distances (unsupervised, no held-out labels
used at all). For consistency with every other baseline in this project
(MAGIC/StreamSpot/FLASH/CASCE all tune theta on val via best-F1), this uses
that same val-tuned protocol instead -- arguably fairer, not weaker, since
it is compared against ground truth rather than an arbitrary percentile.

Usage:
    python baseline_models/rtapt.py
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import networkx as nx
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "provenance_baseline_results"

WL_ITERS = 3        # matches RT-APT's own k=3
MAX_BINS = 100       # matches RT-APT's own FlexSketch(max_bins=100)
N_CLUSTERS = 5       # matches RT-APT's own KMeans(n_clusters=5)
SEED = 42


def wl_subtree_features(G: nx.MultiDiGraph, k=WL_ITERS) -> dict:
    """Verbatim logic from RT-APT's own wl_subtree_features()."""
    node_label = {n: d.get("type", "?") for n, d in G.nodes(data=True)}
    preds = {n: set() for n in G.nodes()}
    succs = {n: set() for n in G.nodes()}
    edge_iter = G.edges(keys=True) if G.is_multigraph() else G.edges()
    for edge in edge_iter:
        u, v = edge[0], edge[1]
        succs[u].add(v)
        preds[v].add(u)

    features = {n: [node_label[n]] for n in G.nodes()}
    current = dict(node_label)
    for _ in range(k):
        new_labels = {}
        for n in G.nodes():
            neighbors = sorted(
                [str(current.get(p, "")) for p in preds[n]] +
                [str(current.get(s, "")) for s in succs[n]]
            )
            combined = str(current.get(n, "")) + "|" + "|".join(neighbors)
            h = hashlib.md5(combined.encode()).hexdigest()
            new_labels[n] = h
            features[n].append(h)
        current = new_labels
    return features


def flexsketch(features: dict, max_bins=MAX_BINS) -> np.ndarray:
    """Verbatim logic from RT-APT's own FlexSketch (single-update case)."""
    all_labels = [lbl for lbls in features.values() for lbl in lbls]
    counter = Counter(all_labels)
    vector = np.zeros(max_bins)
    for i, (_, count) in enumerate(counter.most_common(max_bins)):
        vector[i] = count
    return vector


def build_sketches(labels: dict):
    X, y = [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(flexsketch(wl_subtree_features(G)))
        y.append(int(label))
    return np.stack(X), np.array(y)


def main():
    print(f"Extracting WL-subtree features (k={WL_ITERS}) + FlexSketch (bins={MAX_BINS})...")
    splits = {}
    for part in ("train", "val", "test"):
        labels = json.loads((SPLITS_DIR / f"{part}_labels.json").read_text())
        X, y = build_sketches(labels)
        splits[part] = (X, y)
        print(f"  {part}: {X.shape} ({y.sum()} malicious, {len(y) - y.sum()} benign)")

    X_train, y_train = splits["train"]
    x_benign = X_train[y_train == 0]
    scaler = StandardScaler().fit(x_benign)
    x_benign_s = scaler.transform(x_benign)

    print(f"\nFitting {N_CLUSTERS} centroids on {len(x_benign)} TRAIN-BENIGN sketches only "
          f"(RT-APT is one-class/unsupervised -- no malicious exposure)")
    km = KMeans(n_clusters=N_CLUSTERS, random_state=SEED, n_init=10).fit(x_benign_s)

    def score(X):
        Xs = scaler.transform(X)
        d = km.transform(Xs)
        return d.min(axis=1)

    val_scores = score(splits["val"][0])
    # cm.best_f1_threshold's default grid (0.05-0.95) assumes probability-like
    # scores in [0,1]. RT-APT's score is a raw K-means centroid distance in
    # standardized 100-dim space (observed range ~1-11, not a probability) --
    # using the default grid would silently clip theta to 0.05, below every
    # real score, and "detect" everything as positive. Search the actual
    # observed score range instead.
    grid = np.linspace(val_scores.min(), val_scores.max(), 200)
    theta = cm.best_f1_threshold(splits["val"][1], val_scores, grid=grid)
    test_scores = score(splits["test"][0])
    rep = cm.binary_report(splits["test"][1], test_scores, theta)

    print(f"\nRT-APT (WL-subtree + FlexSketch + K-means, benign-only centroids) on CASCE "
          f"multi-domain corpus, held-out test (n={rep['n']}, {rep['n_pos']} malicious):")
    print(f"  theta(val-tuned)={theta:.4f}")
    print(f"  confusion: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} tn={rep['tn']}")
    print(f"  acc={rep['accuracy']:.4f} prec={rep['precision']:.4f} rec={rep['recall']:.4f} "
          f"f1={rep['f1']:.4f} fpr={rep['fpr']:.4f} roc_auc={rep['roc_auc']} brier={rep['brier']:.4f}")

    out = {"wl_iters": WL_ITERS, "max_bins": MAX_BINS, "n_clusters": N_CLUSTERS,
           "n_train_benign": int(len(x_benign)), "theta": theta, "test": rep}
    out_path = OUT_DIR / "rtapt_results.json"
    out_path.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nsaved -> {out_path}")


if __name__ == "__main__":
    main()
