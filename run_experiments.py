#!/usr/bin/env python3
"""
CASCE — retraining + honest evaluation harness for the Algorithm 4 GAT.

Consumes the corpus built by `datagen/build_corpus.py` (output/corpus/) and
runs the measurement protocol from the memorisation audit:

  main        family-disjoint 70/15/15 split (all graphs sharing a family_id,
              i.e. both halves of every matched pair, stay on one side; a
              leakage assertion fails the run otherwise). Thresholds are tuned
              on VALIDATION only, then reported once on TEST.
  baselines   majority / depth-3 tree / full tree / logistic regression / hist-GBM
              on hand-built pooled features, same split, same protocol.
  ablations   rule-only, GAT-only, fused; GAT with Algorithm 3 skipped
              (factual graph only); label-permutation control; learning curve;
              model-size sweep.
  ood         leave-one-attack-category-out and leave-one-domain-out: the held-out
              unit is unseen at train/val time, and the test set always also
              contains benign graphs (so FPR is measurable).

Usage:
    python run_experiments.py --stage cache
    python run_experiments.py --stage main
    python run_experiments.py --stage all --out output/experiments
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx
import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

import algorithm_4_hybrid as a4
from casce_metrics import best_f1_threshold, binary_report

torch.set_num_threads(int(os.environ.get("CASCE_THREADS", "8")))
REPO = Path(__file__).resolve().parent
CORPUS = REPO / "output" / "corpus"

BEHAVIOR_LABELS = ["DATA_ACCESS", "DATA_PACKAGING", "EXTERNAL_TRANSFER", "DESTRUCTIVE_DB_OPERATION",
                   "OS_CREDENTIAL_DUMPING", "UNIX_SHELL_EXECUTION", "ACCOUNT_MANIPULATION",
                   "POTENTIAL_INGRESS_TOOL_TRANSFER", "INDICATOR_REMOVAL_FILE", "DEFENSE_IMPAIRMENT"]


# ----------------------------------------------------------------------------
# cache: HeteroData (with & without Algorithm 3), rule scores, tabular features
# ----------------------------------------------------------------------------

def strip_alg3(G):
    """Factual graph G_s: drop Behavior nodes (and with them evidence_for/precedes)."""
    H = G.copy()
    H.remove_nodes_from([n for n, d in G.nodes(data=True) if d.get("type") == "Behavior"])
    return H


def tabular_features(G):
    """Pooled, order-free features for the non-graph baselines."""
    types = Counter(d.get("type") for _, d in G.nodes(data=True))
    rels = Counter()
    for _u, _v, d in G.edges(data=True):
        rels[d.get("relation", d.get("rel"))] += 1
    beh = Counter()
    conf = []
    for _n, d in G.nodes(data=True):
        if d.get("type") == "Behavior":
            beh[d.get("behavior_label")] += 1
            conf.append(a4._safe_float(d.get("confidence")))
    qfeat = [a4._stable_hash_bucket(a4.node_semantic_text(d)) for _n, d in G.nodes(data=True)
             if d.get("type") == "Query"]
    qmean = np.mean(qfeat, axis=0) if qfeat else np.zeros(a4.FEATURE_HASH_DIM)
    vec = [types.get(t, 0) for t in a4.ALL_NODE_TYPES]
    vec += [rels.get(r, 0) for r in ("executes", "accesses", "spawns", "opens", "connects_to", "precedes", "evidence_for")]
    vec += [beh.get(b, 0) for b in BEHAVIOR_LABELS]
    vec += [max(conf) if conf else 0.0, G.number_of_nodes(), G.number_of_edges()]
    return np.concatenate([np.array(vec, dtype=np.float32), qmean.astype(np.float32)])


def build_cache(path):
    rows = [json.loads(l) for l in open(CORPUS / "sessions.jsonl")]
    data, data_f, rule, tab = [], [], [], []
    t0 = time.time()
    for i, r in enumerate(rows):
        G = nx.read_graphml(str(CORPUS / "graphml" / r["file"]))
        data.append(a4.build_hetero_data(G, label=r["label"]))
        data_f.append(a4.build_hetero_data(strip_alg3(G), label=r["label"]))
        rule.append(a4.evaluate_rules(G)[0])
        tab.append(tabular_features(G))
        if (i + 1) % 2000 == 0:
            print(f"  cached {i+1}/{len(rows)} ({time.time()-t0:.0f}s)")
    torch.save({"rows": rows, "data": data, "data_factual": data_f,
                "rule": np.array(rule, dtype=np.float32), "tab": np.stack(tab)}, path)
    print(f"cache written: {path}")


def load_cache(path):
    return torch.load(path, weights_only=False)


# ----------------------------------------------------------------------------
# splits
# ----------------------------------------------------------------------------

def _assert_disjoint(rows, parts):
    fam = {name: {rows[i]["family_id"] for i in idx} for name, idx in parts.items()}
    names = list(fam)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            inter = fam[names[i]] & fam[names[j]]
            assert not inter, f"family leakage {names[i]}/{names[j]}: {len(inter)} families e.g. {sorted(inter)[:3]}"


def family_split(rows, idx_pool, seed, frac=(0.70, 0.15, 0.15)):
    """Split idx_pool by family_id into (train, val, test); families never straddle."""
    fams = sorted({rows[i]["family_id"] for i in idx_pool})
    rng = np.random.RandomState(seed)
    rng.shuffle(fams)
    n = len(fams)
    a, b = int(n * frac[0]), int(n * (frac[0] + frac[1]))
    bucket = {f: 0 for f in fams[:a]}
    bucket.update({f: 1 for f in fams[a:b]})
    bucket.update({f: 2 for f in fams[b:]})
    out = ([], [], [])
    for i in idx_pool:
        out[bucket[rows[i]["family_id"]]].append(i)
    return out


def make_split(rows, kind, seed):
    """kind: 'family' | 'category:<c>' | 'domain:<d>'. Returns dict of index lists.
    For held-out splits `test_ood` is the unseen unit and `test_iid` a family-disjoint
    sample of the seen distribution (guarantees benign negatives in the test set)."""
    n = len(rows)
    if kind == "family":
        tr, va, te = family_split(rows, list(range(n)), seed)
        parts = {"train": tr, "val": va, "test": te}
    else:
        field, val = kind.split(":")
        ood = [i for i in range(n) if rows[i][field] == val]
        rest = [i for i in range(n) if rows[i][field] != val]
        # A matched pair can span categories only if the generator did so; keep families whole.
        ood_fams = {rows[i]["family_id"] for i in ood}
        rest = [i for i in rest if rows[i]["family_id"] not in ood_fams]
        tr, va, te = family_split(rows, rest, seed)
        parts = {"train": tr, "val": va, "test_iid": te, "test_ood": ood}
    _assert_disjoint(rows, parts)
    return parts


# ----------------------------------------------------------------------------
# scoring helpers
# ----------------------------------------------------------------------------

def fused(rule, gat):
    return np.array([a4.fuse_scores(float(r), float(g)) for r, g in zip(rule, gat)])


def eval_scorers(y_val, val_scores, y_test, test_scores):
    """val_scores/test_scores: {name: array}. Threshold per scorer chosen on val, applied to test."""
    out = {}
    for name in val_scores:
        thr = best_f1_threshold(y_val, val_scores[name])
        out[name] = binary_report(y_test, test_scores[name], thr)
        out[name]["val_f1"] = binary_report(y_val, val_scores[name], thr)["f1"]
    return out


def gat_fit_predict(data, y, rule, idx, cfg, log, data_key=None):
    """Train on idx['train'] (early stop on idx['val']); return probs for every partition."""
    tr = [data[i] for i in idx["train"]]
    va = [data[i] for i in idx["val"]]
    model, hist = a4.train_model(tr, va, cfg, log=log)
    probs = {}
    for name, ii in idx.items():
        probs[name] = np.array(a4.predict_probs(model, [data[i] for i in ii]))
    train_probs = probs["train"]
    return model, hist, probs, a4.count_parameters(model)


def run_gat_on_split(cache, idx, cfg, log, use_factual=False, permute_labels_seed=None):
    rows = cache["rows"]
    y = np.array([r["label"] for r in rows])
    data = cache["data_factual"] if use_factual else cache["data"]
    if permute_labels_seed is not None:
        # label-permutation control: shuffle TRAIN labels only (val/test stay true)
        rng = np.random.RandomState(permute_labels_seed)
        perm = rng.permutation(len(idx["train"]))
        ytr = y[np.array(idx["train"])][perm]
        data = list(data)
        for i, lab in zip(idx["train"], ytr):
            d = data[i].clone()
            d.y = torch.tensor([float(lab)])
            data[i] = d
    model, hist, probs, nparams = gat_fit_predict(data, y, cache["rule"], idx, cfg, log)
    return probs, hist, nparams, model


def summarise(rows, idx, probs, cache, extra_scorers=None):
    """Full scorer table (GAT, rule, fused + extras) on val->test."""
    y = np.array([r["label"] for r in rows])
    rule = cache["rule"]
    out = {}
    tests = [k for k in idx if k.startswith("test")]
    for t in tests:
        vi, ti = np.array(idx["val"]), np.array(idx[t])
        vs = {"gat_only": probs["val"], "rule_only": rule[vi], "fused": fused(rule[vi], probs["val"])}
        ts = {"gat_only": probs[t], "rule_only": rule[ti], "fused": fused(rule[ti], probs[t])}
        for name, (v, s) in (extra_scorers or {}).items():
            vs[name], ts[name] = v, s[t]
        out[t] = eval_scorers(y[vi], vs, y[ti], ts)
        out[t]["_class_balance"] = {"n": int(len(ti)), "malicious": int(y[ti].sum())}
    # train/val numbers at the val-tuned fused threshold -> generalisation gap
    thr = best_f1_threshold(y[np.array(idx["val"])], fused(rule[np.array(idx["val"])], probs["val"]))
    gaps = {}
    for part in ("train", "val"):
        ii = np.array(idx[part])
        gaps[part] = binary_report(y[ii], fused(rule[ii], probs[part]), thr)
    out["_gap"] = {"threshold": thr,
                   **{f"{p}_{m}": gaps[p][m] for p in gaps for m in ("accuracy", "f1", "roc_auc")}}
    return out


# ----------------------------------------------------------------------------
# baselines
# ----------------------------------------------------------------------------

def run_baselines(cache, idx, seed):
    rows = cache["rows"]
    y = np.array([r["label"] for r in rows])
    X = cache["tab"]
    tr, va = np.array(idx["train"]), np.array(idx["val"])
    scaler = StandardScaler().fit(X[tr])
    models = {
        "majority": None,
        "tree_depth3": DecisionTreeClassifier(max_depth=3, random_state=seed),
        "tree_full": DecisionTreeClassifier(random_state=seed),
        "logreg": LogisticRegression(max_iter=2000, C=1.0),
        "hist_gbm": HistGradientBoostingClassifier(max_depth=4, max_iter=150, random_state=seed),
    }
    out = {}
    tests = [k for k in idx if k.startswith("test")]
    scores_val, scores_test = {}, {t: {} for t in tests}
    for name, m in models.items():
        if m is None:
            scores_val[name] = np.full(len(va), y[tr].mean())
            for t in tests:
                scores_test[t][name] = np.full(len(idx[t]), y[tr].mean())
            continue
        Xs = scaler.transform(X) if name == "logreg" else X
        m.fit(Xs[tr], y[tr])
        scores_val[name] = m.predict_proba(Xs[va])[:, 1]
        for t in tests:
            scores_test[t][name] = m.predict_proba(Xs[np.array(idx[t])])[:, 1]
    for t in tests:
        out[t] = eval_scorers(y[va], scores_val, y[np.array(idx[t])], scores_test[t])
    return out


# ----------------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------------

def _fmt(v):
    return "  n/a" if v is None else f"{v:5.3f}"


def table(title, block):
    lines = [f"\n{title}"]
    lines.append(f"  {'scorer':<14}{'thr':>5}{'acc':>7}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}{'roc':>7}{'pr':>7}{'brier':>7}{'ece':>7}")
    for name, r in block.items():
        if name.startswith("_"):
            continue
        lines.append(f"  {name:<14}{r['threshold']:5.2f}{r['accuracy']:7.3f}{r['precision']:7.3f}{r['recall']:7.3f}"
                     f"{r['f1']:7.3f}{r['fpr']:7.3f} {_fmt(r['roc_auc'])} {_fmt(r['pr_auc'])}{r['brier']:7.3f}{r['ece']:7.3f}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="all",
                    choices=["cache", "main", "sweep", "ood", "all"])
    ap.add_argument("--out", default="output/experiments")
    ap.add_argument("--seeds", type=int, default=3, help="seeds for the main family split")
    ap.add_argument("--epochs", type=int, default=a4.EPOCHS)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--ood-categories", default="copy_to_program,reverse_shell,sql_injection,data_tamper,os_priv_escalation")
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cache_path = CORPUS / "cache.pt"
    if a.stage == "cache" or not cache_path.exists():
        build_cache(cache_path)
        if a.stage == "cache":
            return
    cache = load_cache(cache_path)
    rows = cache["rows"]
    y = np.array([r["label"] for r in rows])
    log = (lambda *_: None) if a.quiet else print
    base_cfg = {"epochs": a.epochs}
    results = json.loads((out / "results.json").read_text()) if (out / "results.json").exists() else {}

    def save():
        (out / "results.json").write_text(json.dumps(results, indent=2, default=float))

    print(f"corpus: {len(rows)} graphs, {y.sum()} malicious / {len(y)-y.sum()} benign; "
          f"{len({r['family_id'] for r in rows})} families; categories={dict(Counter(r['category'] for r in rows))}")

    # ------------------------------------------------------------------ main
    if a.stage in ("main", "all"):
        per_seed = []
        for seed in range(a.seeds):
            idx = make_split(rows, "family", seed)
            print(f"\n=== main family split seed={seed}: " +
                  ", ".join(f"{k}={len(v)} ({int(y[v].sum())} mal)" for k, v in idx.items()))
            t0 = time.time()
            probs, hist, nparams, _m = run_gat_on_split(cache, idx, {**base_cfg, "seed": seed}, log)
            summ = summarise(rows, idx, probs, cache)
            summ["_baselines"] = run_baselines(cache, idx, seed)
            summ["_params"] = nparams
            summ["_epochs_run"] = len(hist)
            summ["_seconds"] = time.time() - t0
            per_seed.append(summ)
            print(table(f"seed {seed} — TEST (val-tuned thresholds), {nparams:,} params, {len(hist)} epochs", summ["test"]))
            print(table("  baselines — TEST", summ["_baselines"]["test"]))
            print("  gap:", {k: round(v, 3) for k, v in summ["_gap"].items()})
        results["main"] = per_seed
        save()

    # ----------------------------------------------------------------- sweep
    if a.stage in ("sweep", "all"):
        idx = make_split(rows, "family", 0)
        sweep = {}
        print("\n=== model-size sweep (family split, seed 0) ===")
        for hd, heads in ((4, 1), (8, 1), (8, 2), (16, 2), (32, 4)):
            cfg = {**base_cfg, "hidden_dim": hd, "heads": heads, "seed": 0}
            if (hd, heads) == (32, 4):
                cfg.update(dropout=0.2, weight_decay=0.0)  # the original configuration
            probs, hist, nparams, _m = run_gat_on_split(cache, idx, cfg, log)
            s = summarise(rows, idx, probs, cache)
            key = f"h{hd}x{heads}"
            sweep[key] = {"params": nparams, "epochs": len(hist), "test_fused_f1": s["test"]["fused"]["f1"],
                          "test_gat_f1": s["test"]["gat_only"]["f1"], "test_gat_roc": s["test"]["gat_only"]["roc_auc"],
                          "train_acc": s["_gap"]["train_accuracy"], "val_acc": s["_gap"]["val_accuracy"],
                          "test_gat_acc": s["test"]["gat_only"]["accuracy"], "params_per_train_graph": nparams / len(idx["train"])}
            print(f"  {key:>7}: {nparams:>9,} params ({nparams/len(idx['train']):6.1f}/graph)  "
                  f"train acc {sweep[key]['train_acc']:.3f}  val acc {sweep[key]['val_acc']:.3f}  "
                  f"test GAT F1 {sweep[key]['test_gat_f1']:.3f} ROC {sweep[key]['test_gat_roc']:.3f}")
        results["size_sweep"] = sweep

        print("\n=== ablations (family split, seed 0, default model) ===")
        abl = {}
        probs, hist, npar, _ = run_gat_on_split(cache, idx, {**base_cfg, "seed": 0}, log, use_factual=True)
        s = summarise(rows, idx, probs, cache)
        abl["no_algorithm3_factual_graph"] = {"gat_f1": s["test"]["gat_only"]["f1"], "gat_roc": s["test"]["gat_only"]["roc_auc"],
                                              "gat_acc": s["test"]["gat_only"]["accuracy"]}
        print("  GAT on factual graph (Algorithm 3 skipped):", abl["no_algorithm3_factual_graph"])
        probs, hist, npar, _ = run_gat_on_split(cache, idx, {**base_cfg, "seed": 0}, log, permute_labels_seed=123)
        s = summarise(rows, idx, probs, cache)
        abl["label_permutation_control"] = {"gat_f1": s["test"]["gat_only"]["f1"], "gat_roc": s["test"]["gat_only"]["roc_auc"],
                                            "gat_acc": s["test"]["gat_only"]["accuracy"]}
        print("  label-permutation control (expect ROC ~0.5):", abl["label_permutation_control"])
        results["ablations"] = abl

        lc = {}
        tr_all = list(idx["train"])
        rng = np.random.RandomState(0)
        rng.shuffle(tr_all)
        print("\n=== learning curve (train fraction; val/test fixed) ===")
        for frac in (0.02, 0.05, 0.10, 0.25, 0.5, 1.0):
            sub = {**idx, "train": tr_all[: max(20, int(len(tr_all) * frac))]}
            probs, hist, npar, _ = run_gat_on_split(cache, sub, {**base_cfg, "seed": 0}, log)
            s = summarise(rows, sub, probs, cache)
            lc[str(frac)] = {"n_train": len(sub["train"]), "test_gat_f1": s["test"]["gat_only"]["f1"],
                             "test_gat_roc": s["test"]["gat_only"]["roc_auc"], "test_gat_acc": s["test"]["gat_only"]["accuracy"],
                             "train_acc": s["_gap"]["train_accuracy"]}
            print(f"  frac {frac:>5}: n_train={lc[str(frac)]['n_train']:>5}  test GAT acc {lc[str(frac)]['test_gat_acc']:.3f} "
                  f"F1 {lc[str(frac)]['test_gat_f1']:.3f} ROC {lc[str(frac)]['test_gat_roc']:.3f}  train acc {lc[str(frac)]['train_acc']:.3f}")
        results["learning_curve"] = lc
        save()

    # ------------------------------------------------------------------- ood
    if a.stage in ("ood", "all"):
        ood = {}
        kinds = [f"category:{c}" for c in a.ood_categories.split(",") if c] + \
                [f"domain:{d}" for d in sorted({r["domain"] for r in rows})]
        for kind in kinds:
            idx = make_split(rows, kind, 0)
            n_ood = len(idx["test_ood"])
            if n_ood == 0:
                continue
            print(f"\n=== held-out {kind}: train={len(idx['train'])} val={len(idx['val'])} "
                  f"test_iid={len(idx['test_iid'])} test_ood={n_ood} ({int(y[idx['test_ood']].sum())} mal) ===")
            probs, hist, nparams, _m = run_gat_on_split(cache, idx, {**base_cfg, "seed": 0}, log)
            summ = summarise(rows, idx, probs, cache)
            summ["_baselines"] = run_baselines(cache, idx, 0)
            ood[kind] = summ
            print(table(f"{kind} — held-out (unseen) unit", summ["test_ood"]))
            print(table("  baselines — held-out unit", summ["_baselines"]["test_ood"]))
        results["ood"] = ood
        save()

    save()
    print(f"\nresults -> {out/'results.json'}")


if __name__ == "__main__":
    main()
