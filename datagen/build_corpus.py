#!/usr/bin/env python3
"""Compile a scale-generated spec corpus into enriched (Algorithm 3) session graphs.

For every run dir under --root:
    codegen -> Algorithm 1 (SAC) -> Algorithm 2 (graph) -> Algorithm 3 (behaviors)

Writes one enriched GraphML per session to <out>/graphml/ plus <out>/sessions.jsonl,
one row per graph carrying the metadata the splitter and the evaluation need
(family_id, matched_pair_id, category, domain, class, behavior labels).

Usage:
    python datagen/build_corpus.py --root datagen/generated/gen --out output/corpus
"""

import argparse
import json
import subprocess
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

import networkx as nx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import algorithm_1  # noqa: E402
import algorithm2  # noqa: E402
import algorithm_3_abstract as alg3  # noqa: E402


def _sanitize(G):
    for _, d in G.nodes(data=True):
        for k, v in list(d.items()):
            if isinstance(v, (list, dict, tuple, bool)):
                d[k] = json.dumps(v) if not isinstance(v, bool) else str(v)
            elif v is None:
                d[k] = ""
    for _, _, _, d in G.edges(keys=True, data=True):
        for k, v in list(d.items()):
            if isinstance(v, (list, dict, tuple, bool)):
                d[k] = json.dumps(v) if not isinstance(v, bool) else str(v)
            elif v is None:
                d[k] = ""
    return G


def _scenario_meta(run_dir: Path) -> dict:
    """backend_pid -> scenario metadata, from codegen's expectation manifest
    joined with the generator's manifest.jsonl (category / domain)."""
    exp = json.loads((run_dir / "expectation_manifest.json").read_text())
    cat = {}
    mpath = run_dir.parent / "manifest.jsonl"
    if not hasattr(_scenario_meta, "_cat"):
        _scenario_meta._cat = {}
        if mpath.exists():
            for line in mpath.read_text().splitlines():
                r = json.loads(line)
                _scenario_meta._cat[r["scenario_id"]] = r
    cat = _scenario_meta._cat

    out = {}
    for sname, sc in exp["scenarios"].items():
        sid = Path(sc["source_file"]).stem
        g = cat.get(sid, {})
        for _label, s in sc["sessions"].items():
            out[s["backend_pid"]] = {
                "scenario_id": sid,
                "family_id": sc["family_id"],
                "matched_pair_id": sc.get("matched_pair_id"),
                "category": g.get("category", "unknown"),
                "domain": g.get("domain", "unknown"),
                "rule_engine_relationship": sc.get("rule_engine_relationship"),
            }
    return out


def process_run(args):
    run_dir, out_dir = Path(args[0]), Path(args[1])
    rc = subprocess.run([sys.executable, str(REPO / "datagen" / "codegen.py"), str(run_dir)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        return run_dir.name, [], f"codegen failed: {rc.stderr[-300:]}"

    run = run_dir.name
    meta = _scenario_meta(run_dir)
    templates = alg3.initialize_templates()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        master_log, correlated = algorithm_1.run_one(run_dir)
        algorithm_1.save_run_output(run, master_log, correlated, tmp)
        graphs, mrows, _orph, _perr = algorithm2.run(
            tmp / f"{run}_event_table.json", tmp / f"{run}_session_correlation.csv",
            tmp / "g", run, run_dir / "labels.csv")
        labels = {r["session_key"]: r["label"] for r in mrows}
        for sk, G in graphs.items():
            label = labels.get(sk, "unknown")
            m = meta.get(sk)
            if m is None or label not in ("Benign", "Malicious"):
                continue  # background/noise sessions are not scenario-labelled
            G_e, beh = alg3.abstract_session_graph(G, templates)
            fname = f"{run}__{sk}.graphml"
            nx.write_graphml(_sanitize(G_e), out_dir / "graphml" / fname)
            rows.append({"file": fname, "run": run, "session_key": sk,
                         "label": 1 if label == "Malicious" else 0,
                         "behaviors": sorted({b["label"] for b in beh}),
                         "n_nodes": G_e.number_of_nodes(), "n_edges": G_e.number_of_edges(),
                         **m})
    return run, rows, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datagen/generated/gen")
    ap.add_argument("--out", default="output/corpus")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()

    root, out = Path(a.root).resolve(), Path(a.out).resolve()
    (out / "graphml").mkdir(parents=True, exist_ok=True)
    runs = sorted(p for p in root.iterdir() if (p / "specs").is_dir())
    print(f"{len(runs)} run dirs under {root}")

    all_rows, failures = [], []
    with Pool(a.workers) as pool:
        for i, (run, rows, err) in enumerate(pool.imap_unordered(process_run, [(r, out) for r in runs]), 1):
            if err:
                failures.append((run, err))
            all_rows.extend(rows)
            if i % 50 == 0:
                print(f"  {i}/{len(runs)} runs, {len(all_rows)} graphs")
    all_rows.sort(key=lambda r: r["file"])
    (out / "sessions.jsonl").write_text("\n".join(json.dumps(r) for r in all_rows) + "\n")

    n_mal = sum(r["label"] for r in all_rows)
    print(f"\n{len(all_rows)} enriched graphs ({n_mal} malicious, {len(all_rows) - n_mal} benign); "
          f"{len(failures)} failed runs")
    for run, err in failures[:5]:
        print("  FAIL", run, err)


if __name__ == "__main__":
    main()
