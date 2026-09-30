#!/usr/bin/env python3
"""
Build enriched session graphs for training, including PREFIX graphs.

Same pipeline as main.py (Algorithm 1 -> 2 -> 3 -> GraphML), per session:
  - the full-session graph   enriched_<run>_<pid>_<Label>.graphml   (main.py's name)
  - up to --prefixes prefix graphs, i.e. the session as it looked after its
    first k statements (with everything the kernel logged before statement
    k+1 started):            enriched_<run>_<pid>_p<k>_<Label>.graphml

Why prefixes: the model was only trained on complete sessions, so while a
session is still running (real-time scoring) its partial graph is unfamiliar
and scored ~1.0. A prefix is labelled Benign while only the role's padding
statements have run (the first --padding statements of every scenario
session, see codegen.DEFAULT_PADDING_PROFILE), and with the session's own
label once a real scenario step has run.

Labels come from <run>/labels.csv (synthetic corpus) or <run>/session_labels.jsonl
(live runs; "Benign:<key>" / "Malicious:<key>").

  python3 build_training_graphs.py --runs dataset_dev/run_* --only dataset_dev/algo4_splits/train_labels.json \\
      --out-dir training_v2/dev_train --no-full
  python3 build_training_graphs.py --runs live_runs/train_pgbench_1 --max-sessions 100 --out-dir training_v2/pgbench_1

Writes <out-dir>/graphml/*.graphml, <out-dir>/labels.json (file -> 0/1, the
format algorithm_4_hybrid.py --train-labels expects) and <out-dir>/index.jsonl.
"""
import argparse
import copy
import csv
import json
import random
import re
import warnings
from pathlib import Path

import networkx as nx

import algorithm_1
import algorithm2
import algorithm_3_abstract
from main import sanitize_for_graphml

warnings.filterwarnings("ignore")


def load_labels(run_dir: Path):
    if (run_dir / "session_labels.jsonl").exists():
        out = {}
        for line in open(run_dir / "session_labels.jsonl"):
            r = json.loads(line)
            out[int(r["session_id"])] = r["label"].partition(":")[0]
        return out
    with open(run_dir / "labels.csv") as f:
        return {int(r["session_id"]): r["label"] for r in csv.DictReader(f) if r["session_id"]}


def prefix_points(n_statements, max_prefixes, padding):
    """Statement counts k (1 <= k < n) to cut at: the padding boundaries first
    (k = 1..padding), then evenly spaced points in the scenario part."""
    ks = [k for k in range(1, padding + 1) if k < n_statements]
    rest = list(range(padding + 1, n_statements))
    room = max_prefixes - len(ks)
    if room > 0 and rest:
        step = len(rest) / room
        ks += sorted({rest[min(len(rest) - 1, int(i * step + step / 2))] for i in range(room)})
    return ks[:max_prefixes]


def build_graph(session_key, events, templates):
    graphs = {}
    for e in events:
        algorithm2.process_event(session_key, copy.deepcopy(e), graphs)
    G, _behaviors = algorithm_3_abstract.abstract_session_graph(graphs[session_key], templates)
    return sanitize_for_graphml(G)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--runs", nargs="+", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--only", type=Path, default=None,
                    help="label JSON of full-session graphs (e.g. train_labels.json): "
                         "only build for those sessions")
    ap.add_argument("--prefixes", type=int, default=3, help="max prefix graphs per session")
    ap.add_argument("--padding", type=int, default=2,
                    help="leading padding statements per scenario session (0 for non-scenario traffic)")
    ap.add_argument("--no-full", action="store_true",
                    help="skip full-session graphs (they already exist, e.g. from main.py)")
    ap.add_argument("--max-sessions", type=int, default=0, help="sample at most N sessions per run")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    wanted = None
    if args.only:
        wanted = set()
        for fname in json.load(open(args.only)):
            m = re.match(r"enriched_(.+)_(\d+)_[A-Za-z]+\.graphml$", fname)
            if m:
                wanted.add((m.group(1), int(m.group(2))))

    gdir = args.out_dir / "graphml"
    gdir.mkdir(parents=True, exist_ok=True)
    templates = algorithm_3_abstract.initialize_templates()
    rng = random.Random(args.seed)
    labels_out, index = {}, []

    for run_dir in sorted(args.runs):
        run = run_dir.name
        labels = load_labels(run_dir)
        master_log, correlated = algorithm_1.run_one(run_dir)
        by_id = {e.event_id: e for e in master_log}
        sessions = {}
        for sk, eid in correlated:
            ev = by_id[eid]
            sessions.setdefault(sk, []).append({**ev.raw, "session_key": sk, "event_id": eid,
                                                "source": ev.source, "timestamp_unix": ev.timestamp})
        keys = [sk for sk in sessions if sk in labels and (wanted is None or (run, sk) in wanted)]
        if args.max_sessions and len(keys) > args.max_sessions:
            keys = sorted(rng.sample(keys, args.max_sessions))
        n_written = 0
        for sk in keys:
            label = "Malicious" if labels[sk].lower() in ("malicious", "attack") else "Benign"
            events = sorted(sessions[sk], key=lambda e: e["timestamp_unix"])
            starts = [i for i, e in enumerate(events)
                      if e["source"] == "postgres" and e.get("event_type") != "ExecutorEnd"]
            cuts = [(k, starts[k]) for k in prefix_points(len(starts), args.prefixes, args.padding)]
            if not args.no_full:
                cuts.append((None, len(events)))
            for k, end in cuts:
                y = label if (k is None or k > args.padding) else "Benign"
                name = (f"enriched_{run}_{sk}_{y}.graphml" if k is None
                        else f"enriched_{run}_{sk}_p{k}_{y}.graphml")
                nx.write_graphml(build_graph(sk, events[:end], templates), gdir / name)
                labels_out[name] = int(y == "Malicious")
                index.append({"file": name, "run": run, "session": sk, "prefix_statements": k,
                              "session_statements": len(starts), "label": y, "session_label": label})
                n_written += 1
        print(f"[build] {run}: {len(keys)} sessions -> {n_written} graphs", flush=True)

    with open(args.out_dir / "labels.json", "w") as f:
        json.dump(labels_out, f, indent=1)
    with open(args.out_dir / "index.jsonl", "w") as f:
        for r in index:
            f.write(json.dumps(r) + "\n")
    n_mal = sum(labels_out.values())
    print(f"[build] {len(labels_out)} graphs ({n_mal} malicious, {len(labels_out) - n_mal} benign) "
          f"-> {args.out_dir}")


if __name__ == "__main__":
    main()
