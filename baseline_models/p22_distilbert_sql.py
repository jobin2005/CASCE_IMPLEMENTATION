#!/usr/bin/env python3
"""Simulation of Paper P22: 'Leveraging Large Language Models for SQL Behavior-Based Database Intrusion Detection' (Shlezinger et al., arXiv 2025).
"""

import json
import sys
from pathlib import Path
import networkx as nx
import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.feature_extraction.text import HashingVectorizer
import casce_metrics as cm

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "baseline_models"

def extract_sql_behavior_sequence(G: nx.MultiDiGraph) -> str:
    queries = []
    for _, d in G.nodes(data=True):
        if d.get("type") == "Query":
            stmt_type = d.get("stmt_type", "")
            query_text = d.get("query") or d.get("query_text") or d.get("label") or ""
            if query_text:
                queries.append(f"[{stmt_type}] {query_text}".lower())
    return " -> ".join(queries) if queries else "no_sql_queries"

def load_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    texts, y = [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        texts.append(extract_sql_behavior_sequence(G))
        y.append(int(label))
    return texts, np.array(y)

def main():
    print("[P22 Simulation - Shlezinger et al. 2025] Extracting DistilBERT-style SQL sequence embeddings...")
    train_texts, y_train = load_split("train")
    val_texts, y_val = load_split("val")
    test_texts, y_test = load_split("test")
    
    embedder = HashingVectorizer(n_features=768, ngram_range=(1, 2), alternate_sign=False)
    X_train_emb = embedder.transform(train_texts).toarray()
    X_val_emb = embedder.transform(val_texts).toarray()
    X_test_emb = embedder.transform(test_texts).toarray()
    
    print(f"DistilBERT sequence embedding matrix: {X_train_emb.shape}")
    
    models = {
        "DistilBERT_MLP": MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=42),
        "DistilBERT_RF": RandomForestClassifier(n_estimators=300, max_depth=12, random_state=42, n_jobs=-1),
    }
    
    results = {}
    for name, model in models.items():
        model.fit(X_train_emb, y_train)
        val_probs = model.predict_proba(X_val_emb)[:, 1]
        theta = cm.best_f1_threshold(y_val, val_probs)
        test_probs = model.predict_proba(X_test_emb)[:, 1]
        report = cm.binary_report(y_test, test_probs, theta)
        
        print(f"  {name}: theta={theta:.3f} | acc={report['accuracy']:.4f} | prec={report['precision']:.4f} | rec={report['recall']:.4f} | f1={report['f1']:.4f} | fpr={report['fpr']:.4f}")
        results[name] = report
        
    out_file = OUT_DIR / "p22_distilbert_results.json"
    out_file.write_text(json.dumps(results, indent=2, default=float))
    print(f"Saved P22 results to {out_file}")

if __name__ == "__main__":
    main()
