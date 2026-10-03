#!/usr/bin/env python3
"""
Evaluate the real-time daemon's verdicts on a live run.

Joins
  --scores    realtime_daemon session_scores.jsonl (last line per session wins)
  --labels    session_labels.jsonl written by the pg_telemetry hook
  --manifest  live_manifest.jsonl written by run_live_scenarios.py (optional)
and reports false-positive rate (and detection metrics if malicious sessions
are present), per workload source and per scenario family, plus a threshold
sweep. With --compare-synthetic, every scenario session's live risk is put
next to the risk the same model gives the SAME session in the synthetic
corpus (dataset_*/enriched_graphs), i.e. the synthetic-vs-live gap.

  python3 workload_simulation/evaluate_live.py --run-dir live_runs/4b --scores realtime_out/session_scores.jsonl --compare-synthetic
"""
import argparse
import glob
import json
import re
import statistics
import sys
import warnings
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def family(scenario_id):
    return re.sub(r"_\d+$", "", scenario_id or "")


def rates(rows, theta):
    tp = sum(r["y"] == 1 and r["risk"] >= theta for r in rows)
    fp = sum(r["y"] == 0 and r["risk"] >= theta for r in rows)
    fn = sum(r["y"] == 1 and r["risk"] < theta for r in rows)
    tn = sum(r["y"] == 0 and r["risk"] < theta for r in rows)
    out = {"n": len(rows), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
           "FPR": fp / (fp + tn) if fp + tn else None}
    if tp + fn:
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn)
        out.update(precision=prec, recall=rec,
                   F1=2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return out


def fmt(r):
    s = f"n={r['n']:4d}  FP={r['FP']:3d}  TN={r['TN']:4d}"
    if r["FPR"] is not None:
        s += f"  FPR={r['FPR']:.3f}"
    if "recall" in r:
        s += (f"  TP={r['TP']:3d}  FN={r['FN']:3d}  precision={r['precision']:.3f}"
              f"  recall={r['recall']:.3f}  F1={r['F1']:.3f}")
    return s


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--run-dir", type=Path, required=True,
                    help="capture folder: session_labels.jsonl (+ live_manifest.jsonl)")
    ap.add_argument("--scores", type=Path, default=PROJECT_ROOT / "realtime_out" / "session_scores.jsonl")
    ap.add_argument("--alerts", type=Path, default=None,
                    help="daemon alerts.jsonl (default: next to --scores)")
    ap.add_argument("--theta", type=float, default=None,
                    help="alert threshold (default: the θ_A tuned on validation for --model-path)")
    ap.add_argument("--compare-synthetic", action="store_true")
    ap.add_argument("--model-path", default=str(PROJECT_ROOT / "casce_gat.pt"))
    ap.add_argument("--write-labels-csv", action="store_true",
                    help="also write <run-dir>/labels.csv (session_id,label) for main.py")
    args = ap.parse_args()
    import algorithm_4_hybrid
    args.theta = algorithm_4_hybrid.resolve_theta(args.theta, args.model_path)

    scores = {}
    for r in read_jsonl(args.scores):
        scores[int(r["session_id"])] = r
    labels = {int(r["session_id"]): r["label"] for r in read_jsonl(args.run_dir / "session_labels.jsonl")}
    manifest = {}
    if (args.run_dir / "live_manifest.jsonl").exists():
        manifest = {r["key"]: r for r in read_jsonl(args.run_dir / "live_manifest.jsonl")}

    rows, unlabelled = [], []
    for sid, sc in scores.items():
        lab = labels.get(sid)
        if lab is None:
            unlabelled.append(sc)
            continue
        cls, _, key = lab.partition(":")
        m = manifest.get(key, {})
        rows.append({"session_id": sid, "y": int(cls == "Malicious"), "cls": cls,
                     "source": "pgbench" if key == "pgbench" else ("scenario" if m else key or "other"),
                     "family": family(m.get("scenario_id")) if m else key, "key": key, "m": m,
                     "risk": sc["risk"], "rule": sc["rule_score"], "gat": sc["gat_score"],
                     "status": sc["status"], "scenario": sc.get("scenario"),
                     "n_events": sc.get("n_events"),
                     "behaviors": sc.get("behaviors", [])})

    print(f"== Coverage")
    print(f"  daemon scored {len(scores)} sessions: {len(rows)} labelled, {len(unlabelled)} unlabelled")
    if manifest:
        scored_keys = {r["key"] for r in rows}
        missing = [k for k in manifest if k not in scored_keys]
        errs = [m for m in manifest.values() if m.get("errors")]
        print(f"  runner planned {len(manifest)} scenario sessions: {len(manifest) - len(missing)} scored, "
              f"{len(missing)} never scored, {len(errs)} had SQL errors")
        for k in missing[:10]:
            print(f"    never scored: {k} {manifest[k].get('scenario_id')}/{manifest[k].get('session_label')}")
        for m in errs[:5]:
            print(f"    SQL error in {m['key']} {m.get('scenario_id')}: {m['errors'][0][:120]}")
    if unlabelled:
        print(f"  unlabelled sessions (not from the runner/pgbench), e.g. "
              f"{[u['session_id'] for u in unlabelled[:5]]}")

    alerts_path = args.alerts or args.scores.with_name("alerts.jsonl")
    alerted = {}
    if alerts_path.exists():
        for a in read_jsonl(alerts_path):
            alerted.setdefault(int(a["session_id"]), a)

    print(f"\n== Final verdict per session (score once the session has ended), theta_A = {args.theta}")
    print(f"  ALL        {fmt(rates(rows, args.theta))}")
    by_src = defaultdict(list)
    for r in rows:
        by_src[r["source"]].append(r)
    for src, rs in sorted(by_src.items()):
        print(f"  {src:<10} {fmt(rates(rs, args.theta))}")

    if alerted:
        op_rows = [dict(r, risk=1.0 if r["session_id"] in alerted else 0.0) for r in rows]
        early = [r for r in rows if r["session_id"] in alerted and r["risk"] < args.theta]
        print(f"\n== Real-time view: alerted at ANY point while the session was running")
        print(f"  ALL        {fmt(rates(op_rows, 0.5))}")
        by_src_op = defaultdict(list)
        for r in op_rows:
            by_src_op[r["source"]].append(r)
        for src, rs in sorted(by_src_op.items()):
            print(f"  {src:<10} {fmt(rates(rs, 0.5))}")
        print(f"  alerts raised on a partial session whose final verdict is benign: {len(early)}")
        for r in early[:10]:
            a = alerted[r["session_id"]]
            print(f"    session {r['session_id']} {r['family']}: alert at {a['n_events']} events "
                  f"(risk {a['risk']:.3f}), final {r['risk']:.3f} after {r['n_events']} events")

    print(f"\n== Per scenario family (theta_A = {args.theta})")
    by_fam = defaultdict(list)
    for r in rows:
        by_fam[(r["cls"], r["family"])].append(r)
    for (cls, fam), rs in sorted(by_fam.items()):
        risks = [r["risk"] for r in rs]
        print(f"  {cls:<9} {fam:<32} {fmt(rates(rs, args.theta))}  "
              f"risk median={statistics.median(risks):.3f} max={max(risks):.3f}")

    print("\n== Threshold sweep (all labelled sessions)")
    for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        print(f"  theta={t:.1f}  {fmt(rates(rows, t))}")

    fps = sorted((r for r in rows if r["y"] == 0 and r["risk"] >= args.theta), key=lambda r: -r["risk"])
    if fps:
        print(f"\n== False alarms ({len(fps)})")
        for r in fps[:30]:
            print(f"  session {r['session_id']:>7}  risk={r['risk']:.3f} (rule {r['rule']:.2f}, gat {r['gat']:.2f})"
                  f"  {r['family']:<28} rule={r['scenario']}  behaviors={r['behaviors']}")

    if args.compare_synthetic:
        warnings.filterwarnings("ignore")
        import networkx as nx
        import algorithm_4_hybrid as A
        model = A.load_model(args.model_path)
        print("\n== Same sessions: synthetic corpus vs live (same model, same theta)")
        pairs = []
        for r in rows:
            m = r["m"]
            if not m:
                continue
            hits = glob.glob(str(PROJECT_ROOT / m["dataset"] / "enriched_graphs" / "graphml" /
                                 f"enriched_{m['run']}_{m['synthetic_backend_pid']}_*.graphml"))
            if not hits:
                continue
            a = A.detect(nx.read_graphml(hits[0]), model, session_id=r["session_id"], theta_a=args.theta)
            pairs.append((r, a["risk"]))
        if pairs:
            agree = sum((syn >= args.theta) == (r["risk"] >= args.theta) for r, syn in pairs)
            deltas = [r["risk"] - syn for r, syn in pairs]
            print(f"  {len(pairs)} sessions matched to their synthetic twin")
            print(f"  same verdict: {agree}/{len(pairs)}   live-synthetic risk: "
                  f"mean {statistics.mean(deltas):+.3f}, mean |diff| {statistics.mean(map(abs, deltas)):.3f}")
            syn_rows = [dict(r, risk=syn) for r, syn in pairs]
            live_rows = [r for r, _ in pairs]
            print(f"  synthetic: {fmt(rates(syn_rows, args.theta))}")
            print(f"  live     : {fmt(rates(live_rows, args.theta))}")
            by_f = defaultdict(list)
            for r, syn in pairs:
                by_f[r["family"]].append((syn, r["risk"]))
            for fam, v in sorted(by_f.items()):
                print(f"    {fam:<32} n={len(v):3d}  synthetic median={statistics.median(s for s, _ in v):.3f}"
                      f"  live median={statistics.median(l for _, l in v):.3f}")
            flips = [(r, syn) for r, syn in pairs if (syn >= args.theta) != (r["risk"] >= args.theta)]
            for r, syn in flips[:15]:
                print(f"    verdict changed: session {r['session_id']} {r['m']['run']}/{r['m']['scenario_id']}"
                      f"  synthetic {syn:.3f} -> live {r['risk']:.3f}")

    if args.write_labels_csv:
        out = args.run_dir / "labels.csv"
        with open(out, "w") as f:
            f.write("session_id,label\n")
            for sid, lab in sorted(labels.items()):
                f.write(f"{sid},{lab.partition(':')[0]}\n")
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
