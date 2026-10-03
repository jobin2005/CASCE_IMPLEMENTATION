#!/usr/bin/env python3
"""Simulation of Paper P25: 'Enhanced SQL Injection Detection using Chi-Square
Feature Selection and Machine Learning Classifiers' (Casmiry et al., Frontiers in Big Data 2025).
"""

import json
import sys
from pathlib import Path
import networkx as nx
import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

import casce_metrics as cm

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "baseline_models"

def extract_session_sql_text(G: nx.MultiDiGraph) -> str:
    sql_texts = []
    for _, d in G.nodes(data=True):
        if d.get("type") == "Query":
            text = d.get("query") or d.get("query_text") or d.get("label") or ""
            if text:
                sql_texts.append(str(text).lower())
    return " ".join(sql_texts) if sql_texts else "empty_query"

def load_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    texts, y, files = [], [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        texts.append(extract_session_sql_text(G))
        y.append(int(label))
        files.append(fname)
    return texts, np.array(y), files

def main():
    print("[P25 Simulation - Casmiry et al. 2025] Loading SQL texts...")
    train_texts, y_train, _ = load_split("train")
    val_texts, y_val, _ = load_split("val")
    test_texts, y_test, _ = load_split("test")
    
    print(f"Loaded train={len(train_texts)}, val={len(val_texts)}, test={len(test_texts)}")
    
    vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000, token_pattern=r"(?u)\b\w+\b")
    X_train_vec = vectorizer.fit_transform(train_texts)
    X_val_vec = vectorizer.transform(val_texts)
    X_test_vec = vectorizer.transform(test_texts)
    
    print(f"Raw TF-IDF feature shape: {X_train_vec.shape}")
    
    k_features = min(300, X_train_vec.shape[1])
    selector = SelectKBest(chi2, k=k_features)
    X_train_chi = selector.fit_transform(X_train_vec, y_train)
    X_val_chi = selector.transform(X_val_vec)
    X_test_chi = selector.transform(X_test_vec)
    
    print(f"Chi-square selected feature shape: {X_train_chi.shape}")
    
    models = {
        "MultinomialNB": MultinomialNB(),
        "RandomForest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
        "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
    }
    
    results = {}
    for name, model in models.items():
        model.fit(X_train_chi, y_train)
        val_probs = model.predict_proba(X_val_chi)[:, 1]
        theta = cm.best_f1_threshold(y_val, val_probs)
        test_probs = model.predict_proba(X_test_chi)[:, 1]
        report = cm.binary_report(y_test, test_probs, theta)
        
        print(f"  {name}: theta={theta:.3f} | acc={report['accuracy']:.4f} | prec={report['precision']:.4f} | rec={report['recall']:.4f} | f1={report['f1']:.4f} | fpr={report['fpr']:.4f}")
        results[name] = report
        
    out_file = OUT_DIR / "p25_chisq_results.json"
    out_file.write_text(json.dumps(results, indent=2, default=float))
    print(f"Saved P25 results to {out_file}")

if __name__ == "__main__":
    main()
