#!/usr/bin/env python3
import json
import networkx as nx
from pathlib import Path
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import algorithm_4_hybrid

def evaluate_casce():
    OUTPUT_DIR = Path('output/dataset_test')
    y_true = []
    y_pred = []
    
    print("Loading dataset_test graphml files and executing CASCE Algorithm 4 Rules...")
    for run_dir in OUTPUT_DIR.glob('run_*'):
        for g_file in run_dir.glob('*.graphml'):
            G = nx.read_graphml(g_file)
            session_id = g_file.stem
            is_malicious = 0 if '_Normal' in g_file.name else 1
            
            # Run CASCE algorithm 4 rules + heuristic fallback
            assessment = algorithm_4_hybrid.detect(G, None, session_id)
            
            y_true.append(is_malicious)
            y_pred.append(1 if assessment['status'] in ['alert', 'response'] else 0)
            
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp+tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn+tp) > 0 else 0
    
    print("\n========================================")
    print(" CASCE ALGORITHM 4 (HEURISTIC) RESULTS")
    print("========================================")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"FNR:       {fnr:.4f}")

evaluate_casce()
