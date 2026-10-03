#!/usr/bin/env python3
"""Database-Only IDS Baseline Simulation (pgAudit / SQL-Only Feature Models).

This script isolates the database-layer visibility of session graphs in the
CASCE multi-domain corpus. All operating system and kernel entities
(Process, File, Endpoint, Configuration nodes, and eBPF syscall edge relations like
spawns, opens, connects_to) are explicitly STRIPPED OUT.

The model receives ONLY database-layer information:
- Session, Role, Query, Table nodes
- DB relations: executes, accesses, reads_from, modifies
- SQL AST statement types and target objects

This provides an exact, rigorous empirical simulation of DB-only security systems
(such as pgAudit, DAM, SQLi filters, and SQL-only ML detectors).

Split: Same family-disjoint split as CASCE's own GAT
(output/corpus_multidomain/algo4_splits/).
"""

import json
import sys
from pathlib import Path
import networkx as nx
import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

import casce_metrics as cm

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "baseline_models"

DB_NODE_TYPES = ["Session", "Role", "Query", "Table"]
DB_EDGE_RELATIONS = ["executes", "accesses", "reads_from", "modifies"]

FEATURE_NAMES = (
    ["db_n_nodes", "db_n_edges", "db_density"]
    + [f"db_nodetype_{t}" for t in DB_NODE_TYPES]
    + [f"db_edgerel_{r}" for r in DB_EDGE_RELATIONS]
    + ["db_max_in_deg", "db_max_out_deg", "db_mean_in_deg", "db_mean_out_deg"]
)

def extract_db_only_features(G: nx.MultiDiGraph) -> np.ndarray:
    """Filter graph to database-layer nodes/edges only, stripping OS/kernel context."""
    db_nodes = [n for n, d in G.nodes(data=True) if d.get("type") in DB_NODE_TYPES]
    subG = G.subgraph(db_nodes).copy()
    
    n_nodes = subG.number_of_nodes()
    n_edges = subG.number_of_edges()
    density = nx.density(subG) if n_nodes > 1 else 0.0
    
    node_counts = {t: 0 for t in DB_NODE_TYPES}
    for _, d in subG.nodes(data=True):
        t = d.get("type")
        if t in node_counts:
            node_counts[t] += 1
            
    edge_counts = {r: 0 for r in DB_EDGE_RELATIONS}
    edge_iter = subG.edges(keys=True, data=True) if subG.is_multigraph() else subG.edges(data=True)
    for edge in edge_iter:
        d = edge[-1]
        rel = d.get("relation", d.get("rel"))
        if rel in edge_counts:
            edge_counts[rel] += 1
            
    in_degs = [deg for _, deg in subG.in_degree()]
    out_degs = [deg for _, deg in subG.out_degree()]
    
    feats = (
        [n_nodes, n_edges, density]
        + [node_counts[t] for t in DB_NODE_TYPES]
        + [edge_counts[r] for r in DB_EDGE_RELATIONS]
        + [max(in_degs, default=0), max(out_degs, default=0),
           float(np.mean(in_degs)) if in_degs else 0.0,
           float(np.mean(out_degs)) if out_degs else 0.0]
    )
    return np.array(feats, dtype=np.float32)

def load_db_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    X, y, files = [], [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(extract_db_only_features(G))
        y.append(int(label))
        files.append(fname)
    return np.stack(X), np.array(y), files

def main():
    print("Loading DB-only feature split (Kernel/OS nodes stripped)...")
    X_train, y_train, _ = load_db_split("train")
    X_val, y_val, _ = load_db_split("val")
    X_test, y_test, _ = load_db_split("test")
    print(f"train={X_train.shape} val={X_val.shape} test={X_test.shape}")
    
    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)
    
    models = {
        "random_forest": RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1),
        "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
        "mlp": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, early_stopping=True, random_state=42),
    }
    if XGB_AVAILABLE:
        models["xgboost"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=42, n_jobs=-1)
        
    results = {}
    for name, model in models.items():
        use_scaled = name in ("logistic_regression", "mlp")
        Xtr = X_train_s if use_scaled else X_train
        Xv = X_val_s if use_scaled else X_val
        Xte = X_test_s if use_scaled else X_test
        
        model.fit(Xtr, y_train)
        val_scores = model.predict_proba(Xv)[:, 1]
        theta = cm.best_f1_threshold(y_val, val_scores)
        test_scores = model.predict_proba(Xte)[:, 1]
        report = cm.binary_report(y_test, test_scores, theta)
        
        print(f"\nDB-Only Baseline ({name}):")
        print(f"  theta={theta:.3f} | acc={report['accuracy']:.4f} | prec={report['precision']:.4f} | rec={report['recall']:.4f} | f1={report['f1']:.4f} | fpr={report['fpr']:.4f}")
        results[name] = report

    out_file = OUT_DIR / "db_only_results.json"
    out_file.write_text(json.dumps(results, indent=2, default=float))
    print(f"\nSaved DB-only simulation results to {out_file}")

if __name__ == "__main__":
    main()
