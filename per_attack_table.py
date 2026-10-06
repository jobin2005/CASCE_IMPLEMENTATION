#!/usr/bin/env python3
"""
Results per attack type (and per benign workload), from the existing result
files -- no retraining. One row per scenario template, columns:

  seen, offline   E1 test set (dataset_test), v2, seeds 42/1/2   (models_seeds, holdout_report)
  seen, live      live mixed run 5b, v2 scoring live              (live_runs/5b_mixed/daemon_v2)
  unseen, offline template-disjoint folds, template held out of training:
                  v2 (3 seeds, loto/) and v3 (seed 1, loto_v3_f1/)
  4D              live, unseen techniques -- filled in after the 4D run

Attacks report detection rate (and live alert latency); benign workloads report
the false-alarm rate. Precision is not defined per attack (a false alarm on a
benign session belongs to no attack type) -- see the overall rows instead.

  python3 per_attack_table.py --out results_per_attack.md
"""
import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

E1_V2 = [("42", "eval_test_report_holdout_priv_abuse/holdout_report.json"),
         ("1", "models_seeds/v2_s1.report.json"), ("2", "models_seeds/v2_s2.report.json")]
LIVE = Path("live_runs/5b_mixed")


def tpl(name):
    return re.sub(r"_\d+$", "", name.split(":")[0]).replace("banking_", "")


def e1(path):
    """template -> (hits, n) from a holdout_report (v2 model), summing a template's sessions."""
    out = defaultdict(lambda: [0, 0])
    for k, v in json.loads(Path(path).read_text())["models"]["v2"]["per_template"].items():
        t = tpl(k)
        out[t][0] += v.get("detected", v.get("false_alarms", 0))
        out[t][1] += v["n"]
    return out


def live_5b():
    """template -> dict(hits, n, latencies) for v2 scoring the live 5b capture."""
    read = lambda p: [json.loads(l) for l in open(p) if l.strip()]
    theta = None
    scores = {}
    for r in read(LIVE / "daemon_v2/session_scores.jsonl"):
        scores[r["session_id"]] = r                     # last score per session = final verdict
        theta = r["theta_a"]
    lat = {r["session_id"]: r["detection_latency_s"] for r in read(LIVE / "daemon_v2/alerts.jsonl")}
    manifest = {r["key"]: r for r in read(LIVE / "live_manifest.jsonl")}
    out = defaultdict(lambda: {"hits": 0, "n": 0, "lat": []})
    for lab in read(LIVE / "session_labels.jsonl"):
        cls, _, key = lab["label"].partition(":")
        sid = lab["session_id"]
        if sid not in scores:
            continue
        t = "pgbench" if key == "pgbench" else tpl(manifest[key]["scenario_id"])
        flagged = scores[sid]["risk"] >= theta
        out[t]["n"] += 1
        out[t]["hits"] += flagged
        if cls == "Malicious" and sid in lat:
            out[t]["lat"].append(lat[sid])
    return out


def live_split(run, daemon):
    """Attack sessions of a live run, split by whether Postgres refused a statement
    ("permission denied" in the runner's per-session stderr, live_manifest.jsonl).
    template -> {attempted: [hits, n], denied: [...], executed: [...]}.
    A refused session never did what it attempted, but the hook logged the
    statement before Postgres refused it, so the detector still saw it."""
    read = lambda p: [json.loads(l) for l in open(p) if l.strip()]
    d = Path("live_runs") / run
    scores = {}
    for r in read(d / daemon / "session_scores.jsonl"):
        scores[r["session_id"]] = r
    manifest = {r["key"]: r for r in read(d / "live_manifest.jsonl")}
    out = defaultdict(lambda: {"attempted": [0, 0], "denied": [0, 0], "executed": [0, 0]})
    for lab in read(d / "session_labels.jsonl"):
        cls, _, key = lab["label"].partition(":")
        sc = scores.get(lab["session_id"])
        if cls != "Malicious" or key not in manifest or sc is None:
            continue
        denied = any("permission denied" in e for e in manifest[key].get("errors", []))
        hit = int(sc["risk"] >= sc["theta_a"])
        for part in ("attempted", "denied" if denied else "executed"):
            out[tpl(manifest[key]["scenario_id"])][part][0] += hit
            out[tpl(manifest[key]["scenario_id"])][part][1] += 1
    return out


def loto(folder, seeds):
    """template -> list of (hits, n), one per seed, summed over the folds where it was a
    test template (a benign template can be the test template of two folds)."""
    out = defaultdict(list)
    for s in seeds:
        per_seed = defaultdict(lambda: [0, 0])
        for p in sorted(Path(folder).glob(f"*_s{s}.report.json")):
            for k, v in json.loads(p.read_text())["per_template_unseen"].items():
                per_seed[tpl(k)][0] += v.get("detected", v.get("false_alarms", 0))
                per_seed[tpl(k)][1] += v["n"]
        for t, (h, n) in per_seed.items():
            out[t].append((h, n))
    return out


def rate(pairs):
    """'x.xx ± y.yy' over seeds (each pair = hits, n), or a single value."""
    vals = [h / n for h, n in pairs if n]
    if not vals:
        return "–"
    if len(vals) == 1:
        h, n = pairs[0]
        return f"{vals[0]:.2f} ({h}/{n})"
    return f"{statistics.mean(vals):.2f} ± {statistics.stdev(vals):.2f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", type=Path, default=Path("results_per_attack.md"))
    args = ap.parse_args()

    e1_runs = [e1(p) for _, p in E1_V2]
    live = live_5b()
    lv2 = loto("loto", [1, 2, 3])
    lv3 = loto("loto_v3_f1", [1])
    labels = {}
    for k in json.loads(Path(E1_V2[0][1]).read_text())["models"]["v2"]["per_template"]:
        labels[tpl(k)] = "benign" if "(benign)" in k else "attack"

    rows = {"attack": [], "benign": []}
    for t in sorted(labels):
        lv = live.get(t, {"hits": 0, "n": 0, "lat": []})
        live_txt = f"{lv['hits'] / lv['n']:.2f} ({lv['hits']}/{lv['n']})" if lv["n"] else "–"
        lat = f"{statistics.median(lv['lat']):.2f} s" if lv["lat"] else "–"
        cells = [t, rate([r[t] for r in e1_runs if t in r]), live_txt]
        if labels[t] == "attack":
            cells.append(lat)
        cells += [rate(lv2.get(t, [])), rate(lv3.get(t, [])), "_pending_"]
        rows[labels[t]].append(cells)
    pg = live.get("pgbench", {"hits": 0, "n": 0})

    split_md = []
    for run, label in (("5a_attacks", "5a (attacks only)"), ("5b_mixed", "5b (mixed)")):
        for daemon, model in (("daemon_v2", "v2"), ("daemon_v3", "v3")):
            if not (Path("live_runs") / run / daemon / "session_scores.jsonl").exists():
                continue
            sp = live_split(run, daemon)
            cell = lambda h, n: f"{h}/{n}" if n else "–"
            split_md += [f"**{label}, {model}**", "",
                         "| Attack template | Attempted (caught/all) | Refused by Postgres | Executed |",
                         "|---|---|---|---|"]
            tot = {"attempted": [0, 0], "denied": [0, 0], "executed": [0, 0]}
            for t in sorted(sp):
                split_md.append(f"| {t} | " + " | ".join(cell(*sp[t][k]) for k in tot) + " |")
                for k in tot:
                    tot[k][0] += sp[t][k][0]
                    tot[k][1] += sp[t][k][1]
            split_md += ["| **all attacks** | " + " | ".join(f"**{cell(*tot[k])}**" for k in tot) + " |", ""]

    md = [
        "# Results per attack type",
        "",
        "Generated by `per_attack_table.py` from existing result files; see EXPERIMENTS.md for how each was produced.",
        "Thresholds: each model's validation-tuned θ (v2 0.55; per-fold θ for the template-disjoint models). Nothing here is tuned on test data.",
        "",
        "- **Seen, offline:** E1 synthetic test set; v2 retrained with seeds 42, 1 and 2 (mean ± std over seeds).",
        "- **Seen, live:** live mixed run 5b. Real Postgres + eBPF capture, 1,025 pgbench + 133 benign + 93 attack sessions, scored live by v2.",
        "- **Unseen, offline:** template-disjoint folds. The template was absent from training and validation. v2 uses 3 seeds; v3 (feature version 3, original θ rule) uses 1 seed and is provisional.",
        "- **4D:** live, attack techniques not in the 13 templates, on the banking database. Not run yet.",
        "",
        "## Attacks: detection rate (recall)",
        "",
        "| Attack template | Seen, offline (E1, v2) | Seen, live (5b, v2) | Live alert latency (median) | Unseen, offline, v2 | Unseen, offline, v3 | 4D (live, unseen) |",
        "|---|---|---|---|---|---|---|",
        *["| " + " | ".join(r) + " |" for r in rows["attack"]],
        "",
        "## Benign workloads: false-alarm rate",
        "",
        "| Benign template | Seen, offline (E1, v2) | Seen, live (5b, v2) | Unseen, offline, v2 | Unseen, offline, v3 | 4D (live, unseen) |",
        "|---|---|---|---|---|---|",
        *["| " + " | ".join(r) + " |" for r in rows["benign"]],
        f"| pgbench (background load) | – | {pg['hits'] / pg['n']:.2f} ({pg['hits']}/{pg['n']}) | – | – | _pending_ |" if pg["n"] else "",
        "",
        "## Live attacks: attempted vs executed",
        "",
        "Some live attack sessions were **refused by Postgres** (\"permission denied\", recorded per session in `live_manifest.jsonl`): the attack was attempted but never took effect.",
        "The Postgres hook logs a statement *before* Postgres checks permissions, so the detector still sees the attempt.",
        "*Attempted* counts every attack session; *executed* only those with no refused statement.",
        "Failed outbound `curl` calls are not refusals: the statement and its OS process ran, only the network connection was refused by design.",
        "",
        *split_md,
        "## Reading the table",
        "- **Seen attacks** (offline and live) are detected almost perfectly. Live alerts arrive within about 2 s.",
        "- **Unseen attacks.** Detection depends on how close the attack is to a trained one. v3 improves several templates over v2.",
        "- **Unseen benign workloads.** False alarms are concentrated on data-movement jobs (ETL replication). This is the main remaining weakness.",
        "- **Live and synthetic agree.** The live 5b verdicts equal the synthetic verdicts for 226/226 scenario sessions (EXPERIMENTS.md).",
    ]
    args.out.write_text("\n".join(md) + "\n")
    print("\n".join(md[10:]))
    print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()
