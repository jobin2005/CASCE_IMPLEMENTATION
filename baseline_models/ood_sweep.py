#!/usr/bin/env python3
"""Leave-one-category-out OOD sweep: does architecture choice matter under
genuine distribution shift, not just on the easy family-disjoint split?

Holds out an ENTIRE attack/benign category (both classes' instances of that
technique, e.g. all reverse_shell sessions -- malicious AND benign variants)
from training entirely. Trains on the remaining categories (family-disjoint
train/val/test_iid, same protocol as everywhere else in this project), then
reports each model's performance on:
  - test_iid: held-out family-disjoint sessions from the SAME categories seen
    in training (the "easy" split -- same protocol as gnn_baselines.py)
  - test_ood: every session of the held-out category (a technique never seen
    in any form during training)

This is the test that actually isolates architecture generalization, which
the plain family-disjoint split (gnn_baselines.py) does not.

Usage:
    python baseline_models/ood_sweep.py --holdout reverse_shell
"""
import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import networkx as nx
import numpy as np
import torch
import torch.nn as nn
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from torch_geometric.loader import DataLoader

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import algorithm_4_hybrid as a4  # noqa: E402
import casce_metrics as cm  # noqa: E402
from baseline_models.classical_ml import extract_features  # noqa: E402
from baseline_models.gnn_baselines import HeteroGNNBaseline, run_epoch, predict_probs, count_parameters  # noqa: E402

CORPUS = REPO / "output" / "corpus_multidomain"
GRAPHML_DIR = CORPUS / "graphml"
OUT_DIR = REPO / "gnn_results" / "ood_sweep"
SEED = 42
BATCH_SIZE = 32
MAX_EPOCHS = 15
PATIENCE = 5


def build_split(holdout_category, seed=SEED):
    rows = [json.loads(l) for l in open(CORPUS / "sessions.jsonl")]
    ood_rows = [r for r in rows if r["category"] == holdout_category]
    remaining = [r for r in rows if r["category"] != holdout_category]
    print(f"holdout category '{holdout_category}': {len(ood_rows)} sessions "
          f"({sum(r['label'] for r in ood_rows)} malicious, "
          f"{len(ood_rows) - sum(r['label'] for r in ood_rows)} benign) -- held out entirely")
    print(f"remaining pool: {len(remaining)} sessions across other categories")

    fam_rows = defaultdict(list)
    for r in remaining:
        fam_rows[r["family_id"]].append(r)
    families = list(fam_rows.keys())
    rng = np.random.RandomState(seed)
    rng.shuffle(families)
    n = len(families)
    n_test = int(n * 0.15)
    n_val = int(n * 0.15)
    test_fams = set(families[:n_test])
    val_fams = set(families[n_test:n_test + n_val])
    train_fams = set(families[n_test + n_val:])
    assert not (train_fams & val_fams) and not (train_fams & test_fams) and not (val_fams & test_fams)

    def rows_for(fams):
        return [r for fam in fams for r in fam_rows[fam]]

    split = {"train": rows_for(train_fams), "val": rows_for(val_fams),
              "test_iid": rows_for(test_fams), "test_ood": ood_rows}
    for k, v in split.items():
        n_mal = sum(r["label"] for r in v)
        print(f"  {k}: {len(v)} ({n_mal} malicious, {len(v) - n_mal} benign)")
    return split


def run_classical_ml(split):
    print("\n" + "=" * 60 + "\nCLASSICAL ML (OOD)\n" + "=" * 60)
    Xs, ys = {}, {}
    for part, rows in split.items():
        X, y = [], []
        for r in rows:
            G = nx.read_graphml(GRAPHML_DIR / r["file"])
            X.append(extract_features(G))
            y.append(r["label"])
        Xs[part], ys[part] = np.stack(X), np.array(y)

    scaler = StandardScaler().fit(Xs["train"])
    Xs = {k: scaler.transform(v) for k, v in Xs.items()}

    models = {
        "logistic_regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
        "random_forest": RandomForestClassifier(n_estimators=300, max_depth=12, class_weight="balanced",
                                                  random_state=42, n_jobs=-1),
    }
    results = {}
    for name, model in models.items():
        model.fit(Xs["train"], ys["train"])
        theta = cm.best_f1_threshold(ys["val"], model.predict_proba(Xs["val"])[:, 1])
        iid = cm.binary_report(ys["test_iid"], model.predict_proba(Xs["test_iid"])[:, 1], theta)
        ood = cm.binary_report(ys["test_ood"], model.predict_proba(Xs["test_ood"])[:, 1], theta)
        print(f"{name}: iid acc={iid['accuracy']:.4f} f1={iid['f1']:.4f}  |  "
              f"ood acc={ood['accuracy']:.4f} f1={ood['f1']:.4f} fpr={ood['fpr']:.4f} "
              f"fn={ood['fn']} roc_auc={ood['roc_auc']}")
        results[name] = {"theta": theta, "test_iid": iid, "test_ood": ood}
    return results


def build_hetero_dataset(rows):
    ds = []
    for r in rows:
        G = nx.read_graphml(GRAPHML_DIR / r["file"])
        data = a4.build_hetero_data(G)
        data.y = torch.tensor([float(r["label"])])
        ds.append(data)
    return ds


def run_gnn(split, conv_type):
    print(f"\n{'='*60}\n{conv_type.upper()} (OOD)\n{'='*60}")
    train_ds = build_hetero_dataset(split["train"])
    val_ds = build_hetero_dataset(split["val"])
    iid_ds = build_hetero_dataset(split["test_iid"])
    ood_ds = build_hetero_dataset(split["test_ood"])

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)
    iid_loader = DataLoader(iid_ds, batch_size=BATCH_SIZE)
    ood_loader = DataLoader(ood_ds, batch_size=BATCH_SIZE)

    n_pos = sum(int(d.y.item()) for d in train_ds)
    pos_weight = torch.tensor([(len(train_ds) - n_pos) / max(1, n_pos)])

    torch.manual_seed(SEED)
    model = HeteroGNNBaseline(conv_type)
    print(f"parameters: {count_parameters(model):,}  train={len(train_ds)} val={len(val_ds)} "
          f"iid={len(iid_ds)} ood={len(ood_ds)}")
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss, patience_ctr, best_state = float("inf"), 0, None
    t0 = time.time()
    for epoch in range(1, MAX_EPOCHS + 1):
        train_loss = run_epoch(model, train_loader, optimizer, loss_fn, train=True)
        val_loss = run_epoch(model, val_loader, optimizer, loss_fn, train=False)
        print(f"  epoch {epoch}/{MAX_EPOCHS}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")
        if val_loss < best_val_loss:
            best_val_loss, patience_ctr = val_loss, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f"  early stopping at epoch {epoch}")
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    train_time = time.time() - t0

    val_probs, val_y = predict_probs(model, val_loader)
    theta = cm.best_f1_threshold(val_y, val_probs)
    iid_probs, iid_y = predict_probs(model, iid_loader)
    ood_probs, ood_y = predict_probs(model, ood_loader)
    iid_report = cm.binary_report(iid_y, iid_probs, theta)
    ood_report = cm.binary_report(ood_y, ood_probs, theta)

    print(f"  theta(val-tuned)={theta:.3f}  train_time={train_time:.0f}s")
    print(f"  test_iid: acc={iid_report['accuracy']:.4f} f1={iid_report['f1']:.4f} "
          f"fpr={iid_report['fpr']:.4f} roc_auc={iid_report['roc_auc']}")
    print(f"  test_ood: acc={ood_report['accuracy']:.4f} f1={ood_report['f1']:.4f} "
          f"fpr={ood_report['fpr']:.4f} fn={ood_report['fn']} roc_auc={ood_report['roc_auc']}")
    print(f"  ood confusion: tp={ood_report['tp']} fp={ood_report['fp']} "
          f"fn={ood_report['fn']} tn={ood_report['tn']}")

    return {"theta": theta, "train_time_sec": round(train_time, 1),
            "test_iid": iid_report, "test_ood": ood_report}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", default="reverse_shell")
    args = ap.parse_args()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    split = build_split(args.holdout)
    (OUT_DIR / f"split_{args.holdout}_sizes.json").write_text(json.dumps(
        {k: len(v) for k, v in split.items()}, indent=2))

    all_results = {"holdout_category": args.holdout}
    all_results["classical_ml"] = run_classical_ml(split)
    for conv_type in ("gcn", "sage", "gat", "gatv2"):
        all_results[conv_type] = run_gnn(split, conv_type)
        (OUT_DIR / f"ood_{args.holdout}.json").write_text(json.dumps(all_results, indent=2, default=float))

    print(f"\nSaved -> {OUT_DIR / f'ood_{args.holdout}.json'}")


if __name__ == "__main__":
    main()
