#!/usr/bin/env python3
"""Classical ML baselines (Logistic Regression, Random Forest, XGBoost, MLP)
against the CASCE multi-domain corpus.

Feature representation
-----------------------
Each session graph is flattened into a tabular feature vector: per-node-type
counts, per-edge-relation counts, degree statistics, and per-MITRE-behavior-
label counts/confidence stats (the same behavior signal CASCE's own GAT
reads off Behavior nodes). This is a fair "flatten the same graph" baseline.

What is deliberately EXCLUDED: CASCE's own rule-engine chain-match score
(evaluate_rules() / CHAIN_RULES in algorithm_4_hybrid.py). That score IS
CASCE's own verdict -- including it as a classical-ML feature would just be
reading off CASCE's own output, not a real independent baseline. Nothing
here calls evaluate_rules() or replicates CHAIN_RULES.

Split: same family-disjoint split as CASCE's own GAT
(output/corpus_multidomain/algo4_splits/), so the comparison is apples to
apples.

Usage:
    python baseline_models/classical_ml.py
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

sys.path.insert(0, str(REPO))
import casce_metrics as cm  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
SPLITS_DIR = CORPUS / "algo4_splits"
OUT_DIR = REPO / "classical_ml_results"

NODE_TYPES = ["Session", "Role", "Query", "Table", "Process", "File",
              "Endpoint", "Configuration", "Behavior"]
EDGE_RELATIONS = ["executes", "accesses", "reads_from", "modifies", "opens",
                   "connects_to", "spawns", "backed_by", "unlinks",
                   "writes_to", "precedes", "evidence_for"]
BEHAVIOR_LABELS = ["EXTERNAL_TRANSFER", "UNIX_SHELL_EXECUTION",
                    "POTENTIAL_INGRESS_TOOL_TRANSFER", "DATA_ACCESS",
                    "DEFENSE_IMPAIRMENT", "ACCOUNT_MANIPULATION",
                    "DATA_PACKAGING", "DESTRUCTIVE_DB_OPERATION"]

FEATURE_NAMES = (
    ["n_nodes", "n_edges", "density"]
    + [f"nodetype_{t}" for t in NODE_TYPES]
    + [f"edgerel_{r}" for r in EDGE_RELATIONS]
    + ["max_in_deg", "max_out_deg", "mean_in_deg", "mean_out_deg"]
    + [f"behavior_{b}" for b in BEHAVIOR_LABELS]
    + ["n_behaviors", "mean_behavior_conf", "max_behavior_conf"]
)


def extract_features(G: nx.MultiDiGraph) -> np.ndarray:
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    density = nx.density(G) if n_nodes > 1 else 0.0

    node_type_counts = {t: 0 for t in NODE_TYPES}
    behavior_confs = []
    behavior_label_counts = {b: 0 for b in BEHAVIOR_LABELS}
    for _, d in G.nodes(data=True):
        t = d.get("type")
        if t in node_type_counts:
            node_type_counts[t] += 1
        if t == "Behavior":
            label = d.get("label", "")
            lbl = label.split("]")[-1].strip() if "]" in label else label
            if lbl in behavior_label_counts:
                behavior_label_counts[lbl] += 1
            try:
                behavior_confs.append(float(d.get("confidence", 0.0)))
            except (TypeError, ValueError):
                pass

    edge_rel_counts = {r: 0 for r in EDGE_RELATIONS}
    for _, _, _k, d in G.edges(keys=True, data=True):
        rel = d.get("relation", d.get("rel"))
        if rel in edge_rel_counts:
            edge_rel_counts[rel] += 1

    in_degs = [deg for _, deg in G.in_degree()]
    out_degs = [deg for _, deg in G.out_degree()]

    feats = (
        [n_nodes, n_edges, density]
        + [node_type_counts[t] for t in NODE_TYPES]
        + [edge_rel_counts[r] for r in EDGE_RELATIONS]
        + [max(in_degs, default=0), max(out_degs, default=0),
           float(np.mean(in_degs)) if in_degs else 0.0,
           float(np.mean(out_degs)) if out_degs else 0.0]
        + [behavior_label_counts[b] for b in BEHAVIOR_LABELS]
        + [len(behavior_confs),
           float(np.mean(behavior_confs)) if behavior_confs else 0.0,
           float(np.max(behavior_confs)) if behavior_confs else 0.0]
    )
    return np.array(feats, dtype=np.float32)


def load_split(name: str):
    labels = json.loads((SPLITS_DIR / f"{name}_labels.json").read_text())
    X, y, files = [], [], []
    for fname, label in labels.items():
        path = GRAPHML_DIR / fname
        if not path.exists():
            continue
        G = nx.read_graphml(path)
        X.append(extract_features(G))
        y.append(int(label))
        files.append(fname)
    return np.stack(X), np.array(y), files


def main():
    OUT_DIR.mkdir(exist_ok=True)
    print("Loading + featurizing splits...")
    X_train, y_train, _ = load_split("train")
    X_val, y_val, _ = load_split("val")
    X_test, y_test, _ = load_split("test")
    print(f"train={X_train.shape} val={X_val.shape} test={X_test.shape}")
    print(f"feature dim: {X_train.shape[1]} ({len(FEATURE_NAMES)} named)")

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    models = {
        "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
        "random_forest": RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced",
                                                  random_state=42, n_jobs=-1),
        "mlp": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, early_stopping=True, random_state=42),
    }
    if XGB_AVAILABLE:
        models["xgboost"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                           eval_metric="logloss", random_state=42, n_jobs=-1)
    else:
        print("[!] xgboost not installed -- skipping (will be disclosed as such in the results, not faked)")

    all_results = {}
    for name, model in models.items():
        print(f"\n=== {name} ===")
        use_scaled = name in ("logistic_regression", "mlp")
        Xtr = X_train_s if use_scaled else X_train
        Xv = X_val_s if use_scaled else X_val
        Xte = X_test_s if use_scaled else X_test

        model.fit(Xtr, y_train)
        val_scores = model.predict_proba(Xv)[:, 1]
        theta = cm.best_f1_threshold(y_val, val_scores)
        test_scores = model.predict_proba(Xte)[:, 1]
        report = cm.binary_report(y_test, test_scores, theta)

        print(f"  theta(val-tuned)={theta:.3f}")
        print(f"  test: acc={report['accuracy']:.4f} prec={report['precision']:.4f} "
              f"rec={report['recall']:.4f} f1={report['f1']:.4f} fpr={report['fpr']:.4f} "
              f"roc_auc={report['roc_auc']} brier={report['brier']:.4f}")
        print(f"  confusion: tp={report['tp']} fp={report['fp']} fn={report['fn']} tn={report['tn']}")

        out = {"model": name, "theta": theta, "n_features": X_train.shape[1],
               "feature_names": FEATURE_NAMES, "test": report}
        (OUT_DIR / f"{name}.json").write_text(json.dumps(out, indent=2, default=float))
        all_results[name] = report

    summary_path = OUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(
        {k: {m: v[m] for m in ("accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "brier")}
         for k, v in all_results.items()}, indent=2, default=float))
    print(f"\nSaved per-model results + summary.json -> {OUT_DIR}")


if __name__ == "__main__":
    main()
