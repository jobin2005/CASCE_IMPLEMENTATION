#!/usr/bin/env python3
"""
Check that a live capture has exactly the shape of the synthetic corpus and
survives Algorithms 1 and 2 the same way.

    python3 workload_simulation/check_capture.py <run_dir> [--reference dataset_dev/run_001]

<run_dir> holds postgres_events.json and kernel_events.json from logger.sh.
Nothing is written into <run_dir>; Algorithm 1/2 output goes to a temp dir.
"""
import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import algorithm_1  # noqa: E402
import algorithm2  # noqa: E402


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def shape(records):
    """key -> set of python type names, over non-marker records."""
    out = {}
    for r in records:
        if "marker" in r:
            continue
        for k, v in r.items():
            out.setdefault(k, set()).add(type(v).__name__)
    return out


def compare(name, live, ref):
    ok = True
    for k in sorted(set(ref) | set(live)):
        if k not in live:
            print(f"  [DIFF] {name}: field '{k}' missing in live capture")
            ok = False
        elif k not in ref and k not in ("dest_ip", "dest_port"):
            print(f"  [DIFF] {name}: extra field '{k}' not in synthetic corpus")
            ok = False
        elif k in ref and not live[k] <= ref[k] | {"int", "float"} & ref[k]:
            print(f"  [DIFF] {name}: '{k}' types {sorted(live[k])} vs synthetic {sorted(ref[k])}")
            ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--reference", type=Path, default=PROJECT_ROOT / "dataset_dev" / "run_001")
    args = ap.parse_args()

    pg = read_jsonl(args.run_dir / "postgres_events.json")
    kern = read_jsonl(args.run_dir / "kernel_events.json")
    ref_pg = read_jsonl(args.reference / "postgres_events.json")
    ref_kern = read_jsonl(args.reference / "kernel_events.json")

    print("== 1. Record format vs synthetic corpus")
    ok = compare("postgres", shape(pg), shape(ref_pg))
    ok &= compare("kernel", shape(kern), shape(ref_kern))
    pg_ev = [r for r in pg if "marker" not in r]
    k_ev = [r for r in kern if "marker" not in r]
    print(f"  postgres event types : {dict(Counter(r['event_type'] for r in pg_ev))}")
    print(f"  kernel syscalls      : {dict(Counter(r['syscall'] for r in k_ev))}")
    extra = {r["syscall"] for r in k_ev} - {r["syscall"] for r in ref_kern if "marker" not in r}
    if extra:
        print(f"  [DIFF] syscalls not in synthetic corpus: {sorted(extra)}")
        ok = False
    frac = sum(1 for r in pg_ev if float(r["timestamp"]) != int(float(r["timestamp"])))
    print(f"  postgres timestamps with sub-second precision: {frac}/{len(pg_ev)}")
    if pg_ev and frac == 0:
        print("  [DIFF] postgres timestamps are whole seconds")
        ok = False
    first_k = next((r for r in kern if "marker" in r or "pid" in r), None)
    anchor = next((r for r in k_ev), None)
    if not (first_k and first_k.get("marker") == "LOGGING_START"
            and anchor and anchor.get("comm") == "clock_anchor"):
        print("  [DIFF] kernel log does not start with LOGGING_START + clock_anchor")
        ok = False
    print("  format:", "MATCHES synthetic corpus" if ok else "DIFFERS (see above)")

    print("\n== 2. Algorithm 1 (session-anchored correlation)")
    master_log, correlated = algorithm_1.run_one(args.run_dir)
    by_id = {e.event_id: e for e in master_log}
    k_total = sum(1 for e in master_log if not e.is_postgres and e.raw.get("comm") != "clock_anchor")
    k_linked = {eid for _, eid in correlated if not by_id[eid].is_postgres}
    print(f"  sessions: {len({s for s, _ in correlated})}   "
          f"kernel events linked to a session: {len(k_linked)}/{k_total}")
    pg_ts = [e.timestamp for e in master_log if e.is_postgres]
    for sid in sorted({s for s, _ in correlated}):
        evs = sorted((by_id[eid] for s, eid in correlated if s == sid), key=lambda e: e.timestamp)
        kev = [e for e in evs if not e.is_postgres]
        if not kev:
            continue
        print(f"  session {sid}:")
        for e in evs:
            if e.is_postgres:
                print(f"    {e.timestamp:.6f}  PG   {e.raw['event_type']:<15} {e.raw['query'][:70]}")
            else:
                r = e.raw
                extra = f" -> {r['dest_ip']}:{r['dest_port']}" if "dest_ip" in r else ""
                print(f"    {e.timestamp:.6f}  KERN {r['syscall']:<7} pid={r['pid']} ppid={r['ppid']} "
                      f"{r['comm']}: {r['arg'][:60]}{extra}")
    unlinked = [e for e in master_log if not e.is_postgres and e.event_id not in k_linked
                and e.raw.get("comm") != "clock_anchor"]
    if unlinked:
        print(f"  [WARN] {len(unlinked)} kernel events not linked to any session, e.g.:")
        for e in unlinked[:5]:
            print(f"    {e.raw}")

    print("\n== 3. Algorithm 2 (graph construction)")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        run_name = args.run_dir.name
        algorithm_1.save_run_output(run_name, master_log, correlated, tmp)
        graphs, _rows, orphans, parse_errs = algorithm2.run(
            tmp / f"{run_name}_event_table.json", tmp / f"{run_name}_session_correlation.csv",
            tmp / "g", run_name, None)
        for sid, G in graphs.items():
            types = Counter(d.get("type") for _, d in G.nodes(data=True))
            rels = Counter(d.get("relation", d.get("rel")) for *_, d in G.edges(data=True))
            print(f"  session {sid}: nodes {dict(types)}  edges {dict(rels)}")
        print(f"  orphaned events: {len(orphans) if orphans is not None else 0}   "
              f"SQL parse errors: {len(parse_errs) if parse_errs is not None else 0}")
        if orphans:
            for o in list(orphans)[:5]:
                print(f"    orphan: {o}")


if __name__ == "__main__":
    main()
