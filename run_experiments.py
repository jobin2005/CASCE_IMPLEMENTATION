import os
import json
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve, f1_score, accuracy_score
import torch

from algorithm_4_hybrid import evaluate_rules, gat_score, load_model, fuse_scores

import warnings
warnings.filterwarnings('ignore')

DEV_GRAPHML_DIR = "dataset_dev/enriched_graphs/graphml"
DEV_LABELS_FILE = "dataset_dev/algo4_splits/val_labels.json"
TEST_GRAPHML_DIR = "dataset_test/enriched_graphs/graphml"
TEST_LABELS_FILE = "dataset_test/algo4_splits/test_labels.json"

MODEL_PATH = "casce_gat.pt"
model = load_model(MODEL_PATH)

def extract_scores(graphml_dir, labels_file):
    with open(labels_file, "r") as f:
        labels = json.load(f)
        
    scores = []
    
    for filename, label in labels.items():
        filepath = os.path.join(graphml_dir, filename)
        if not os.path.exists(filepath):
            continue
            
        G = nx.read_graphml(filepath)
        rule_score, _, _, _ = evaluate_rules(G)
        g_score = gat_score(G, model)
        
        # Keep original graph for ablation
        scores.append({
            "session_id": filename,
            "label": float(label),
            "rule_score": rule_score,
            "gat_score": g_score,
            "G": G
        })
        
    return scores

print("Loading dev set...")
dev_scores = extract_scores(DEV_GRAPHML_DIR, DEV_LABELS_FILE)

print("Loading test set...")
test_scores = extract_scores(TEST_GRAPHML_DIR, TEST_LABELS_FILE)

print(f"Dev size: {len(dev_scores)}, Test size: {len(test_scores)}")

# 1. Optimize Thresholds and Weights on Dev Set
best_f1 = -1
best_params = {}

for w_r in np.arange(0.1, 1.1, 0.1):
    for w_g in np.arange(0.1, 1.1, 0.1):
        for theta_a in np.arange(0.1, 1.0, 0.1):
            if w_r < theta_a or w_g < theta_a:
                continue
                
            y_true = [s["label"] for s in dev_scores]
            y_pred = [1 if fuse_scores(s["rule_score"], s["gat_score"], w_r, w_g) >= theta_a else 0 for s in dev_scores]
            
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_params = {"W_RULE": w_r, "W_GAT": w_g, "THETA_A": theta_a}

W_RULE = best_params["W_RULE"]
W_GAT = best_params["W_GAT"]
THETA_A = best_params["THETA_A"]
THETA_R = THETA_A + 0.2 if THETA_A + 0.2 <= 1.0 else 0.95

print(f"Optimized Parameters: W_RULE={W_RULE:.2f}, W_GAT={W_GAT:.2f}, THETA_A={THETA_A:.2f}, THETA_R={THETA_R:.2f} (Dev F1: {best_f1:.4f})")

# Helper for metrics
def get_metrics(y_true, y_pred, y_prob):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0
    fpr = fp / (fp + tn) if fp + tn > 0 else 0
    fnr = fn / (fn + tp) if fn + tp > 0 else 0
    specificity = tn / (tn + fp) if tn + fp > 0 else 0
    
    fpr_curve, tpr_curve, _ = roc_curve(y_true, y_prob)
    auroc = auc(fpr_curve, tpr_curve)
    
    precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_prob)
    auprc = auc(recall_curve, precision_curve)
    
    return {
        "Precision": precision, "Recall": recall, "F1": f1,
        "FPR": fpr, "FNR": fnr, "Specificity": specificity,
        "AUROC": auroc, "AUPRC": auprc,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn
    }

# Ensure result dir
os.makedirs("casce_results", exist_ok=True)

report_content = "# CASCE Evaluation Report\n\n"
report_content += "## 4. Fusion evaluation & 5. Threshold sensitivity (Validation Results)\n"
report_content += "Optimized weights and thresholds on the validation set to ensure independent capabilities crossing the alert threshold:\n"
report_content += f"- **W_RULE**: {W_RULE:.2f}\n- **W_GAT**: {W_GAT:.2f}\n- **THETA_A**: {THETA_A:.2f}\n- **THETA_R**: {THETA_R:.2f}\n\n"

# Overall CASCE Evaluation
y_true_test = [s["label"] for s in test_scores]
y_prob_hybrid = [fuse_scores(s["rule_score"], s["gat_score"], W_RULE, W_GAT) for s in test_scores]
y_pred_hybrid = [1 if p >= THETA_A else 0 for p in y_prob_hybrid]

metrics_hybrid = get_metrics(y_true_test, y_pred_hybrid, y_prob_hybrid)

report_content += "## 1. Overall CASCE evaluation\n"
report_content += "| Metric | Value |\n|---|---|\n"
for k, v in metrics_hybrid.items():
    if isinstance(v, float):
        report_content += f"| {k} | {v:.4f} |\n"
    else:
        report_content += f"| {k} | {v} |\n"
report_content += "\n"

# Plot ROC for overall
fpr_h, tpr_h, _ = roc_curve(y_true_test, y_prob_hybrid)
plt.figure()
plt.plot(fpr_h, tpr_h, label=f"Hybrid (AUC = {metrics_hybrid['AUROC']:.3f})")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - Overall CASCE")
plt.legend()
plt.savefig("casce_results/roc_curve_overall.png")
plt.close()

# 2. Rules vs GAT vs Hybrid
y_prob_rules = [fuse_scores(s["rule_score"], s["gat_score"], 1.0, 0.0) for s in test_scores]
y_pred_rules = [1 if p >= THETA_A else 0 for p in y_prob_rules]
metrics_rules = get_metrics(y_true_test, y_pred_rules, y_prob_rules)

y_prob_gat = [fuse_scores(s["rule_score"], s["gat_score"], 0.0, 1.0) for s in test_scores]
y_pred_gat = [1 if p >= THETA_A else 0 for p in y_prob_gat]
metrics_gat = get_metrics(y_true_test, y_pred_gat, y_prob_gat)

report_content += "## 2. Rules vs GAT vs Hybrid\n"
report_content += "| Metric | Rules Only | GAT Only | Hybrid |\n|---|---|---|---|\n"
keys_to_report = ["Precision", "Recall", "F1", "FPR", "FNR", "AUROC"]
for k in keys_to_report:
    report_content += f"| {k} | {metrics_rules[k]:.4f} | {metrics_gat[k]:.4f} | {metrics_hybrid[k]:.4f} |\n"
report_content += "\n"

# 3. Algorithm 3 ablation
print("Running Algorithm 3 ablation...")
ablation_results = {}

for name, ablation_type in [("Raw/Factual graph", "raw"), ("Behavior abstraction", "no_chain"), ("Behavior abstraction + chaining", "full")]:
    y_prob_abl = []
    for s in test_scores:
        G_abl = s["G"].copy()
        
        if ablation_type == "raw":
            nodes_to_remove = [n for n, d in G_abl.nodes(data=True) if d.get("type") == "Behavior"]
            G_abl.remove_nodes_from(nodes_to_remove)
            
        elif ablation_type == "no_chain":
            edges_to_remove = [(u, v) for u, v, d in G_abl.edges(data=True) if d.get("rel") == "precedes" or d.get("relation") == "precedes"]
            G_abl.remove_edges_from(edges_to_remove)
            
        rule_score, _, _, _ = evaluate_rules(G_abl)
        g_score = gat_score(G_abl, model)
        
        y_prob_abl.append(fuse_scores(rule_score, g_score, W_RULE, W_GAT))
        
    y_pred_abl = [1 if p >= THETA_A else 0 for p in y_prob_abl]
    ablation_results[name] = get_metrics(y_true_test, y_pred_abl, y_prob_abl)

report_content += "## 3. Algorithm 3 ablation\n"
report_content += "| Metric | Raw/Factual graph | Behavior abstraction | Behavior abstraction + chaining |\n|---|---|---|---|\n"
for k in ["Precision", "Recall", "F1", "FPR"]:
    v_raw = ablation_results["Raw/Factual graph"][k]
    v_abs = ablation_results["Behavior abstraction"][k]
    v_full = ablation_results["Behavior abstraction + chaining"][k]
    report_content += f"| {k} | {v_raw:.4f} | {v_abs:.4f} | {v_full:.4f} |\n"
report_content += "\n"

with open("casce_results/all_experiments.md", "w") as f:
    f.write(report_content)

print("Evaluation complete. Results saved in casce_results/all_experiments.md")
