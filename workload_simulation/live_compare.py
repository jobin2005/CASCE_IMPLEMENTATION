#!/usr/bin/env python3
"""
Side-by-side comparison of several daemons that scored the SAME live capture
(run_full_live.sh with several models): final verdicts per traffic group,
attacks split into attempted / refused-by-Postgres / executed, real-time
alerts on sessions whose final verdict is benign, and alert latency.

  python3 workload_simulation/live_compare.py live_runs/8_final daemon_v2_live daemon_v3_live daemon_v3p_live
"""
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def read(p):
    return [json.loads(l) for l in open(p) if l.strip()]


def group_of(m, key):
    if key == "pgbench":
        return "pgbench"
    if m is None:
        return "other"
    tpl = re.sub(r"_\d+$", "", m["scenario_id"]).replace("banking_", "")
    if m["class"] == "malicious":
        return "attack"
    return "benign_extra" if m.get("dataset", "").startswith("dataset_benign") else "benign_seen"


def main():
    run = Path(sys.argv[1])
    daemons = sys.argv[2:]
    labels = {r["session_id"]: r["label"] for r in read(run / "session_labels.jsonl")}
    manifest = {r["key"]: r for r in read(run / "live_manifest.jsonl")}
    rows = []
    for d in daemons:
        scores = {}
        for r in read(run / d / "session_scores.jsonl"):
            scores[r["session_id"]] = r
        alerts = {a["session_id"]: a for a in read(run / d / "alerts.jsonl")}
        g = defaultdict(lambda: [0, 0])          # group -> [flagged, n]
        per_tpl = defaultdict(lambda: [0, 0])
        transient, lat = 0, []
        for sid, lab in labels.items():
            if sid not in scores:
                continue
            cls, _, key = lab.partition(":")
            m = manifest.get(key)
            grp = group_of(m, key)
            flagged = scores[sid]["risk"] >= scores[sid]["theta_a"]
            g[grp][0] += flagged
            g[grp][1] += 1
            if m is not None and grp != "attack":
                t = re.sub(r"_\d+$", "", m["scenario_id"]).replace("banking_", "")
                per_tpl[t][0] += flagged
                per_tpl[t][1] += 1
            if grp == "attack":
                denied = any("permission denied" in e for e in m.get("errors", []))
                sub = "attack_refused" if denied else "attack_executed"
                g[sub][0] += flagged
                g[sub][1] += 1
                if sid in alerts:
                    lat.append(alerts[sid]["detection_latency_s"])
            elif sid in alerts and not flagged:
                transient += 1
        benign = [k for k in ("pgbench", "benign_seen", "benign_extra")]
        fp = sum(g[k][0] for k in benign)
        nb = sum(g[k][1] for k in benign)
        tp, na = g["attack"]
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, na)
        rows.append((d, g, per_tpl, transient, lat, fp, nb, prec, rec))

    def cell(x):
        return f"{x[0]}/{x[1]}" if x[1] else "–"
    print(f"## {run.name}: final verdicts per traffic group (flagged / sessions)\n")
    print("| Group | " + " | ".join(r[0] for r in rows) + " |")
    print("|---|" + "---|" * len(rows))
    for grp, name in (("attack", "Attacks: all attempted"), ("attack_executed", "Attacks: executed"),
                      ("attack_refused", "Attacks: refused by Postgres"),
                      ("benign_seen", "Benign scenarios (13 standard templates)"),
                      ("benign_extra", "Benign extra templates"), ("pgbench", "pgbench")):
        print(f"| {name} | " + " | ".join(cell(r[1][grp]) for r in rows) + " |")
    print("| Precision / recall / F1 | " + " | ".join(
        f"{r[7]:.3f} / {r[8]:.3f} / {2 * r[7] * r[8] / max(1e-9, r[7] + r[8]):.3f}" for r in rows) + " |")
    print("| FPR (all benign) | " + " | ".join(f"{r[5] / max(1, r[6]):.4f} ({r[5]}/{r[6]})" for r in rows) + " |")
    print("| Real-time alerts on sessions finally benign | " + " | ".join(str(r[3]) for r in rows) + " |")
    print("| Attack alert latency median / p90 / max (s) | " + " | ".join(
        f"{statistics.median(r[4]):.2f} / {sorted(r[4])[int(.9 * len(r[4]))]:.2f} / {max(r[4]):.2f}"
        if r[4] else "–" for r in rows) + " |")
    print("\n## Benign templates: false alarms\n")
    tpls = sorted({t for r in rows for t in r[2]})
    print("| Template | " + " | ".join(r[0] for r in rows) + " |")
    print("|---|" + "---|" * len(rows))
    for t in tpls:
        print(f"| {t} | " + " | ".join(cell(r[2][t]) for r in rows) + " |")


if __name__ == "__main__":
    main()
