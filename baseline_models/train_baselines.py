#!/usr/bin/env python3
import os
import json
import numpy as np
import networkx as nx
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, average_precision_score

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / 'output'
TRAIN_VAL_SPLIT = 42

def load_split(runs_dir, run_range=None):
    graphs = []
    labels = []
    
    if not runs_dir.exists():
        return graphs, np.array(labels)
        
    runs = sorted([d for d in os.listdir(runs_dir) if d.startswith('run_')], 
                  key=lambda x: int(x.split('_')[1]))
    
    if run_range is not None:
        runs = [r for r in runs if run_range[0] <= int(r.split('_')[1]) <= run_range[1]]
        
    for run in runs:
        run_path = runs_dir / run
        lbl_file = run_path / 'labels.json'
        if not lbl_file.exists(): 
            continue
            
        with open(lbl_file) as f:
            run_labels = json.load(f)
            
        for fname, y in run_labels.items():
            g_path = run_path / fname
            if g_path.exists():
                try:
                    G = nx.read_graphml(g_path)
                    graphs.append(G)
                    labels.append(y)
                except Exception as e:
                    print(f"Skipping corrupt graph {fname}: {e}")
                    
    return graphs, np.array(labels)

def extract_raw_features(graphs):
    """
    Since classical ML models cannot handle topological structures, we flatten
    the graph into tabular numeric properties and a TF-IDF behavior bag.
    """
    X_num = []
    corpus = []
    for G in graphs:
        n_nodes = G.number_of_nodes()
        n_edges = G.number_of_edges()
        density = nx.density(G)
        
        behaviors = []
        for n, data in G.nodes(data=True):
            if data.get('type') == 'Behavior':
                lbl = data.get('label', '')
                try:
                    import re
                    m = re.match(r"^\[.*?\]\s*(.+)$", lbl)
                    if m: lbl = m.group(1)
                except:
                    pass
                behaviors.append(lbl.replace(" ", "_"))
        
        behaviors.append("graph_topology_baseline")
        corpus.append(" ".join(behaviors))
        X_num.append([n_nodes, n_edges, density])
    return np.array(X_num), corpus

def evaluate_model(name, y_true, y_pred, y_prob):
    print(f"\n{'='*40}")
    print(f" {name.upper()} RESULTS")
    print(f"{'='*40}")
    
    if len(np.unique(y_true)) < 2:
        print("Warning: Test set has only one class. Metrics might be unreliable.")
        
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    try:
        auroc = roc_auc_score(y_true, y_prob)
        auprc = average_precision_score(y_true, y_prob)
    except ValueError:
        auroc, auprc = 0.0, 0.0
        
    fpr = fp / (fp + tn) if (fp+tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn+tp) > 0 else 0
    
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"FNR:       {fnr:.4f}")
    print(f"AUROC:     {auroc:.4f}")
    print(f"AUPRC:     {auprc:.4f}")

def main():
    print("Loading GraphML datasets via identical run constraints...")
    train_graphs, y_train = load_split(OUTPUT_DIR / 'dataset_dev', (1, TRAIN_VAL_SPLIT))
    val_graphs, y_val = load_split(OUTPUT_DIR / 'dataset_dev', (TRAIN_VAL_SPLIT + 1, 999))
    test_graphs, y_test = load_split(OUTPUT_DIR / 'dataset_test')
    
    if len(train_graphs) == 0:
        print("Error: No training graphs found. Ensure run_pipeline.py --stage labels was executed.")
        return
        
    if len(test_graphs) == 0:
        print("Error: No test graphs found. Ensure dataset_test is successfully parsed.")
        return

    # Merge train and val since classical ML usually doesn't early-stop like PyTorch GAT
    train_graphs = train_graphs + val_graphs
    y_train = np.concatenate([y_train, y_val])
    
    print(f"Loaded Train samples: {len(y_train)}, Test samples: {len(y_test)}")
    
    print("Extracting tabular numeric/TF-IDF features...")
    X_num_train, corp_train = extract_raw_features(train_graphs)
    X_num_test, corp_test = extract_raw_features(test_graphs)
    
    # Vocabulary constraint to simulate classical feature engineering limitations
    vectorizer = TfidfVectorizer(max_features=50)
    X_text_train = vectorizer.fit_transform(corp_train).toarray()
    X_text_test = vectorizer.transform(corp_test).toarray()
    
    X_train = np.hstack([X_num_train, X_text_train])
    X_test = np.hstack([X_num_test, X_text_test])
    
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "XGBoost": XGBClassifier(eval_metric='logloss', random_state=42),
        "MLP (Basic DNN)": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=42)
    }
    
    print("\nInitiating Training & Evaluation...")
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        else:
            y_prob = y_pred
        evaluate_model(name, y_test, y_pred, y_prob)

if __name__ == '__main__':
    main()
