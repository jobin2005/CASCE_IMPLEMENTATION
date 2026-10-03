#!/usr/bin/env python3
"""Simulation of Paper P27: 'Multivariate Log-based Anomaly Detection for Distributed Database' (Zhang et al., ACM SIGKDD 2024).

Methodology:
1. Extract multivariate database log streams (query volume, table access matrix, execution errors, statement distributions, session duration).
2. Construct multivariate log feature vectors representing concurrent database log dimensions.
3. Train multivariate deep learning / ensemble anomaly detector.
4. Evaluate on the exact same family-disjoint test set (N=2,004).
"""

import json
import sys
from pathlib import Path
import networkx as nx
import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import casce_metrics as cm

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "baseline_models"

def extract_multivariate_db_log_features(G: nx.MultiDiGraph) -> np.ndarray:
    n_queries = 0
    n_tables = 0
    stmt_counts = {"SELECT": 0, "INSERT": 0, "UPDATE": 0, "DELETE": 0, "COPY": 0, "OTHER": 0}
    rel_counts = {"executes": 0, "accesses": 0, "reads_from": 0, "modifies": 0}
    
    for _, d in G.nodes(data=True):
        t = d.get("type")
        if t == "Query":
            n_queries += 1
            st = d.get("stmt_type", "OTHER").upper()
            if st in stmt_counts:
                stmt_counts[st] += 1
            else:
                stmt_counts["OTHER"] += 1
        elif t == "Table":
            n_tables += 1
            
    edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
    for edge in edge_iter:
        d = edge[-1]
        rel = d.get("relation", d.get("rel"))
        if rel in rel_counts:
            rel_counts[rel] += 1
            
    feats = (
        [n_queries, n_tables]
        + [stmt_counts[k] for k in ["SELECT", "INSERT", "UPDATE", "DELETE", "COPY", "OTHER"]]
        + [rel_counts[k] for k in ["executes", "accesses", "reads_from", "modifies"]]
    )
    return np.array(feats, dtype=np.float32)

def load_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    X, y = [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(extract_multivariate_db_log_features(G))
        y.append(int(label))
    return np.stack(X), np.array(y)

def main():
    print("[P27 Simulation - Zhang et al. KDD 2024] Extracting multivariate DB log features...")
    X_train, y_train = load_split("train")
    X_val, y_val = load_split("val")
    X_test, y_test = load_split("test")
    
    print(f"Multivariate log matrix: train={X_train.shape}, val={X_val.shape}, test={X_test.shape}")
    
    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)
    
    models = {
        "Multivariate_KDD_MLP": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=400, random_state=42),
        "Multivariate_KDD_RF": RandomForestClassifier(n_estimators=300, max_depth=10, random_state=42, n_jobs=-1),
    }
    
    results = {}
    for name, model in models.items():
        model.fit(X_train_s, y_train)
        val_probs = model.predict_proba(X_val_s)[:, 1]
        theta = cm.best_f1_threshold(y_val, val_probs)
        test_probs = model.predict_proba(X_test_s)[:, 1]
        report = cm.binary_report(y_test, test_probs, theta)
        
        print(f"  {name}: theta={theta:.3f} | acc={report['accuracy']:.4f} | prec={report['precision']:.4f} | rec={report['recall']:.4f} | f1={report['f1']:.4f} | fpr={report['fpr']:.4f}")
        results[name] = report
        
    out_file = OUT_DIR / "p27_multivariate_results.json"
    out_file.write_text(json.dumps(results, indent=2, default=float))
    print(f"Saved P27 results to {out_file}")

if __name__ == "__main__":
    main()
