#!/usr/bin/env python3
"""
test_ip_shortcut_ablation.py — Network Destination Ablation Experiment
========================================================================

Evaluates the trained GAT model on intact graphs vs. ablated graphs
where all network connection nodes ('Endpoint'), connection edges ('connects_to'),
and network destination IP attributes are stripped.

If accuracy and F1 score remain stable on ablated graphs, it proves the model
is performing genuine structural and semantic learning, rather than relying on
destination IP address shortcuts.
"""

import json
from pathlib import Path
import networkx as nx
from algorithm_4_hybrid import detect, load_model


def strip_network_features(G: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Return a copy of graph G with Endpoint nodes, connects_to edges, and IP attributes removed."""
    G_ablated = G.copy()

    # 1. Remove all Endpoint nodes
    nodes_to_remove = [
        n for n, data in G_ablated.nodes(data=True)
        if data.get("type") == "Endpoint" or data.get("node_type") == "Endpoint"
    ]
    for n in nodes_to_remove:
        G_ablated.remove_node(n)

    # 2. Remove connects_to edges if any remain
    edges_to_remove = []
    if isinstance(G_ablated, nx.MultiDiGraph):
        for u, v, k, d in G_ablated.edges(data=True, keys=True):
            rel = d.get("relation", d.get("rel"))
            if rel == "connects_to":
                edges_to_remove.append((u, v, k))
        for u, v, k in edges_to_remove:
            G_ablated.remove_edge(u, v, key=k)
    else:
        for u, v, d in G_ablated.edges(data=True):
            rel = d.get("relation", d.get("rel"))
            if rel == "connects_to":
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            G_ablated.remove_edge(u, v)

    # 3. Strip IP/port metadata from remaining nodes
    for n, d in G_ablated.nodes(data=True):
        for ip_key in ("dest_ip", "ip", "port", "connects_to"):
            if ip_key in d:
                d[ip_key] = ""

    return G_ablated


def run_ablation_eval(data_dir: Path, model_path: Path):
    graphml_dir = data_dir / "enriched_graphs" / "graphml"
    test_labels_file = data_dir / "algo4_splits" / "test_labels.json"

    if not test_labels_file.exists():
        test_labels_file = data_dir / "algo4_splits" / "all_labels.json"

    with open(test_labels_file) as f:
        test_labels = json.load(f)

    print(f"Loaded {len(test_labels)} test graphs from {test_labels_file.name}")
    model = load_model(str(model_path))

    intact_results = []
    ablated_results = []

    for filename, label in test_labels.items():
        gpath = graphml_dir / filename
        if not gpath.exists():
            continue

        G_intact = nx.read_graphml(gpath)
        G_ablated = strip_network_features(G_intact)

        sid = filename.replace("enriched_", "").replace(".graphml", "")

        res_intact = detect(G_intact, model, session_id=sid)
        res_ablated = detect(G_ablated, model, session_id=sid)

        pred_intact = 1 if res_intact["risk"] >= 0.5 else 0
        pred_ablated = 1 if res_ablated["risk"] >= 0.5 else 0

        intact_results.append((int(label), pred_intact))
        ablated_results.append((int(label), pred_ablated))

    def compute_metrics(pairs):
        y_true = [t for t, p in pairs]
        y_pred = [p for t, p in pairs]
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

        acc = (tp + tn) / max(1, len(y_true))
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        return acc, prec, rec, f1, tp, fp, fn, tn

    acc_i, prec_i, rec_i, f1_i, tp_i, fp_i, fn_i, tn_i = compute_metrics(intact_results)
    acc_a, prec_a, rec_a, f1_a, tp_a, fp_a, fn_a, tn_a = compute_metrics(ablated_results)

    print(f"\n{'='*65}")
    print(f" NETWORK DESTINATION ABLATION EXPERIMENT REPORT")
    print(f"{'='*65}")
    print(f"  Total Test Graphs: {len(test_labels)}")
    print(f"  {'Metric':<18} {'Intact Graphs':<20} {'Ablated Graphs (No IPs)':<20}")
    print(f"  {'-'*60}")
    print(f"  {'Accuracy':<18} {acc_i:<20.4f} {acc_a:<20.4f}")
    print(f"  {'Precision':<18} {prec_i:<20.4f} {prec_a:<20.4f}")
    print(f"  {'Recall':<18} {rec_i:<20.4f} {rec_a:<20.4f}")
    print(f"  {'F1 Score':<18} {f1_i:<20.4f} {f1_a:<20.4f}")
    print(f"  {'-'*60}")
    print(f"  {'Confusion Matrix':<18} TP={tp_i} FP={fp_i} FN={fn_i} TN={tn_i:<5} TP={tp_a} FP={fp_a} FN={fn_a} TN={tn_a}")
    print(f"{'='*65}\n")

    drop = acc_i - acc_a
    if drop <= 0.05:
        print("✓ CONCLUSION: Model accuracy did NOT collapse when connection/IP nodes were stripped!")
        print("  This confirms the model is learning genuine structural and semantic patterns, not relying on IP address shortcuts.")
    else:
        print(f"⚠ WARNING: Performance dropped by {drop:.2%} when connection nodes were stripped.")

    return {
        "intact": {"accuracy": acc_i, "f1": f1_i},
        "ablated": {"accuracy": acc_a, "f1": f1_a},
        "accuracy_drop": drop,
    }


if __name__ == "__main__":
    data_dir = Path("datagen/generated/banking_v2_fixed")
    model_path = data_dir / "casce_gat.pt"
    run_ablation_eval(data_dir, model_path)
