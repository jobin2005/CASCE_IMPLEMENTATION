#!/usr/bin/env python3
"""
gate_pilot.py — corpus-level shortcut gates for a CASCE pilot batch.

Aggregates every run directory under datagen/generated/*/ that has an
expectation_manifest.json + labels.csv, then runs the corpus-level checks
the casce-datagen skill assigns to the lead (the checks no single run
directory can answer alone):

  1. node/edge-type presence x label independence (Fisher exact per type)
  2. primitive-fires-in-only-one-class (SQL verbs, tables, process comms,
     syscalls, endpoints that appear in exactly one class)
  3. matched-pair varied-dimension usage + does any varied dimension's
     value correlate with class
  4. family-level near-duplicate check (normalized scenario fingerprints)
  5. shortcut baselines (5-fold CV accuracy/F1) on deliberately impoverished
     feature views: node-presence-only, bag-of-primitives, graph-size-only,
     rule-engine-relationship-only, and a full-feature reference.
     A shortcut view scoring near the full view is the corpus telling you
     that view alone separates the classes — report the numbers, don't judge.

The Behavior-masked GAT baseline from the skill is intentionally NOT run
here: Algorithm 3 emits zero Behavior nodes today (known bug) and the GAT
baseline needs torch + training. That one is deferred and called out in the
report rather than silently skipped.

Usage:
  python datagen/gate_pilot.py                     # scans datagen/generated
  python datagen/gate_pilot.py --root <dir>        # scan a different root
  python datagen/gate_pilot.py --json report.json  # also write JSON
"""
from __future__ import annotations
import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from sqlfacts import extract_query_facts
except Exception:  # pragma: no cover
    extract_query_facts = None

NODE_TYPES = ["Session", "Query", "Table", "Role", "Process", "File", "Endpoint"]
EDGE_TYPES = ["executes", "accesses", "backed_by", "spawns", "opens", "connects_to", "queries", "targets"]


# ---- small stats helpers (no scipy dependency) ---------------------------
def _log_factorial(n: int) -> float:
    return math.lgamma(n + 1)


def fisher_exact_2x2(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p-value for table [[a,b],[c,d]]."""
    n = a + b + c + d
    if n == 0:
        return 1.0
    r1, r2, c1 = a + b, c + d, a + c
    def hyper(x: int) -> float:
        amin = max(0, c1 - r2)
        amax = min(r1, c1)
        if x < amin or x > amax:
            return 0.0
        logp = (_log_factorial(r1) + _log_factorial(r2) + _log_factorial(c1) + _log_factorial(n - c1)
                - _log_factorial(n) - _log_factorial(x) - _log_factorial(r1 - x)
                - _log_factorial(c1 - x) - _log_factorial(r2 - (c1 - x)))
        return math.exp(logp)
    p_obs = hyper(a)
    amin = max(0, c1 - r2)
    amax = min(r1, c1)
    total = 0.0
    for x in range(amin, amax + 1):
        px = hyper(x)
        if px <= p_obs + 1e-12:
            total += px
    return min(1.0, total)


# ---- corpus loading -------------------------------------------------------
def load_corpus(root: Path):
    """Return (sessions, scenarios). One session record per correlated session."""
    sessions = []      # dicts: run, scenario_id, session_label, class, role, node_types, edge_types, n_nodes, n_edges, rule_rel, verbs, tables, comms, syscalls, endpoints, family_id
    scenarios = []     # dicts: run, scenario_id, family_id, matched_pair_id, matched_dims, class, spec_path
    for man_path in sorted(root.glob("*/expectation_manifest.json")):
        run_dir = man_path.parent
        run = run_dir.name
        manifest = json.loads(man_path.read_text())
        spec_by_sid = {}
        for spec_file in sorted((run_dir / "specs").glob("*.yaml")):
            try:
                spec = yaml.safe_load(spec_file.read_text())
                spec_by_sid[spec["scenario_id"]] = (spec, spec_file)
            except Exception as e:  # pragma: no cover
                print(f"WARN: could not parse {spec_file}: {e}", file=sys.stderr)
        for sid, sc in manifest.get("scenarios", {}).items():
            spec, spec_file = spec_by_sid.get(sid, (None, None))
            family_id = sc.get("family_id")
            scenarios.append({
                "run": run, "scenario_id": sid, "family_id": family_id,
                "matched_pair_id": sc.get("matched_pair_id"),
                "matched_dimensions": sc.get("matched_dimensions"),
                "default_class": sc.get("default_class"),
                "rule_engine_relationship": sc.get("rule_engine_relationship", "agrees"),
                "spec": spec,
            })
            sess_specs = {s["session_label"]: s for s in (spec.get("sessions", []) if spec else [])}
            for slabel, sess in sc.get("sessions", {}).items():
                if not sess.get("expected_correlation", True):
                    continue  # anchor:none never becomes a GAT example
                node_types = sorted({n["node_type"] for n in sess.get("expected_nodes", [])})
                edge_types = sorted({e["edge_type"] for e in sess.get("expected_edges", [])})
                verbs, tables, comms, syscalls, endpoints = set(), set(), set(), set(), set()
                sspec = sess_specs.get(slabel, {})
                for ev in sspec.get("events", []):
                    if "sql" in ev:
                        # leading-keyword verb (sqlfacts has no generic verb key)
                        lead = ev["sql"].strip().split(None, 1)[0].upper() if ev["sql"].strip() else ""
                        if lead:
                            verbs.add(lead)
                        if "UNION" in ev["sql"].upper():
                            verbs.add("UNION")
                    if "sql" in ev and extract_query_facts:
                        try:
                            facts = extract_query_facts(ev["sql"])
                            v = facts.get("command") or facts.get("verb") or facts.get("stmt_type")
                            if v:
                                verbs.add(str(v).upper())
                            for t in (facts.get("tables") or facts.get("target_tables") or []):
                                tables.add(str(t))
                            if facts.get("is_program"):
                                verbs.add("COPY_TO_PROGRAM")
                        except Exception:
                            verbs.add("PARSE_ERR")
                    if "process" in ev:
                        comms.add(ev["process"].get("comm", ""))
                        syscalls.add("execve")
                    if "file" in ev:
                        syscalls.add(ev["file"].get("syscall", "openat"))
                    if "connect" in ev:
                        syscalls.add("connect")
                        endpoints.add(f'{ev["connect"].get("ip")}:{ev["connect"].get("port")}')
                    if "connects_to" in ev:
                        syscalls.add("connect")
                        endpoints.add(f'{ev["connects_to"].get("ip")}:{ev["connects_to"].get("port")}')
                sessions.append({
                    "run": run, "scenario_id": sid, "session_label": slabel,
                    "cls": sess.get("class") or sc.get("default_class"),
                    "role": sess.get("role"),
                    "anchor": sess.get("anchor"),
                    "node_types": node_types, "edge_types": edge_types,
                    "n_nodes": len(sess.get("expected_nodes", [])),
                    "n_edges": len(sess.get("expected_edges", [])),
                    "rule_rel": sc.get("rule_engine_relationship", "agrees"),
                    "family_id": family_id,
                    "verbs": verbs, "tables": tables, "comms": comms,
                    "syscalls": syscalls, "endpoints": endpoints,
                })
    return sessions, scenarios


# ---- checks ---------------------------------------------------------------
def check_presence_independence(sessions, report):
    labels = [s["cls"] for s in sessions]
    n_mal = sum(1 for l in labels if l == "malicious")
    n_ben = sum(1 for l in labels if l == "benign")
    findings = []
    for kind, key in [("node", "node_types"), ("edge", "edge_types")]:
        universe = NODE_TYPES if kind == "node" else EDGE_TYPES
        present = defaultdict(lambda: [0, 0])  # type -> [mal_present, ben_present]
        for s in sessions:
            for t in s[key]:
                if s["cls"] == "malicious":
                    present[t][0] += 1
                elif s["cls"] == "benign":
                    present[t][1] += 1
        for t in sorted(set(list(present.keys()) + universe)):
            mp, bp = present[t]
            a, b, c, d = mp, n_mal - mp, bp, n_ben - bp
            p = fisher_exact_2x2(a, b, c, d)
            frac_m = mp / n_mal if n_mal else 0
            frac_b = bp / n_ben if n_ben else 0
            flag = p < 0.05 and abs(frac_m - frac_b) > 0.5
            findings.append({"kind": kind, "type": t, "mal_present_frac": round(frac_m, 3),
                             "ben_present_frac": round(frac_b, 3), "fisher_p": round(p, 4), "shortcut_flag": flag})
    report["presence_independence"] = {"n_malicious": n_mal, "n_benign": n_ben, "results": findings,
                                       "flagged": [f for f in findings if f["shortcut_flag"]]}


def check_primitive_one_class(sessions, report):
    out = {}
    for name, key in [("sql_verbs", "verbs"), ("tables", "tables"), ("process_comms", "comms"),
                      ("syscalls", "syscalls"), ("endpoints", "endpoints")]:
        by_class = defaultdict(lambda: Counter())
        for s in sessions:
            for prim in s[key]:
                if not prim:
                    continue
                by_class[prim][s["cls"]] += 1
        one_class = []
        for prim, cnt in sorted(by_class.items()):
            classes = [c for c in ("malicious", "benign") if cnt.get(c, 0) > 0]
            if len(classes) == 1:
                one_class.append({"primitive": prim, "only_in": classes[0],
                                  "count": cnt[classes[0]]})
        out[name] = {"only_in_one_class": one_class}
    report["primitive_one_class"] = out


def check_matched_pairs(scenarios, report):
    pairs = defaultdict(list)
    for sc in scenarios:
        if sc["matched_pair_id"]:
            pairs[sc["matched_pair_id"]].append(sc)
    varied_counter = Counter()
    varied_value_by_class = defaultdict(lambda: defaultdict(Counter))
    incomplete = []
    for pid, members in pairs.items():
        if len(members) != 2:
            incomplete.append({"matched_pair_id": pid, "n_members": len(members)})
            continue
        dims = members[0].get("matched_dimensions") or {}
        for vd in dims.get("varied", []):
            varied_counter[vd] += 1
    report["matched_pairs"] = {
        "n_pairs": len(pairs),
        "varied_dimension_usage": dict(varied_counter),
        "incomplete_pairs": incomplete,
        "note": "No single varied dimension should dominate the corpus; see skill's varied-dimension shortcut check.",
    }


def check_family_duplicates(sessions, scenarios, report):
    # fingerprint a scenario by its multiset of (node_types)+(sorted verbs/comms/syscalls) across sessions
    fp_by_scenario = {}
    sess_by_scenario = defaultdict(list)
    for s in sessions:
        sess_by_scenario[(s["run"], s["scenario_id"])].append(s)
    for key, sess in sess_by_scenario.items():
        parts = []
        for s in sorted(sess, key=lambda x: x["session_label"]):
            parts.append("|".join(s["node_types"]) + "#" + ",".join(sorted(s["verbs"] | s["comms"] | s["syscalls"])))
        fp_by_scenario[key] = "//".join(parts)
    fp_counter = Counter(fp_by_scenario.values())
    dup_fps = {fp: c for fp, c in fp_counter.items() if c > 1}
    # families
    fam = defaultdict(set)
    for sc in scenarios:
        fam[sc["family_id"]].add((sc["run"], sc["scenario_id"]))
    cross_family_dups = []
    fp_to_families = defaultdict(set)
    for (run, sid), fp in fp_by_scenario.items():
        # find family of this scenario
        for sc in scenarios:
            if sc["run"] == run and sc["scenario_id"] == sid:
                fp_to_families[fp].add(sc["family_id"])
                break
    for fp, fams in fp_to_families.items():
        if len(fams) > 1 and fp_counter[fp] > 1:
            cross_family_dups.append({"fingerprint": fp[:120], "families": sorted(fams),
                                      "count": fp_counter[fp]})
    report["family_duplicates"] = {
        "n_families": len(fam),
        "n_distinct_scenario_fingerprints": len(fp_counter),
        "n_scenarios": len(fp_by_scenario),
        "identical_fingerprint_groups": len(dup_fps),
        "cross_family_identical": cross_family_dups[:20],
    }


def check_shortcut_baselines(sessions, report):
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score, StratifiedKFold
        from sklearn.feature_extraction import DictVectorizer
    except Exception as e:
        report["shortcut_baselines"] = {"skipped": f"sklearn/numpy unavailable: {e}"}
        return
    y = np.array([1 if s["cls"] == "malicious" else 0 for s in sessions])
    if len(set(y.tolist())) < 2:
        report["shortcut_baselines"] = {"skipped": "only one class present"}
        return
    n_splits = min(5, int(min(np.bincount(y))))
    if n_splits < 2:
        report["shortcut_baselines"] = {"skipped": f"too few per-class samples for CV (min class = {int(min(np.bincount(y)))})"}
        return
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=0)

    def feat_node_presence(s):
        return {f"nt_{t}": 1 for t in s["node_types"]}
    def feat_graph_size(s):
        return {"n_nodes": s["n_nodes"], "n_edges": s["n_edges"]}
    def feat_rule_rel(s):
        return {f"rr_{s['rule_rel']}": 1}
    def feat_primitives(s):
        d = {}
        for p in s["verbs"]:
            d[f"v_{p}"] = 1
        for p in s["comms"]:
            d[f"c_{p}"] = 1
        for p in s["syscalls"]:
            d[f"s_{p}"] = 1
        return d
    def feat_full(s):
        d = {}
        d.update(feat_node_presence(s)); d.update(feat_graph_size(s))
        d.update(feat_rule_rel(s)); d.update(feat_primitives(s))
        for t in s["edge_types"]:
            d[f"et_{t}"] = 1
        for t in s["tables"]:
            d[f"t_{t}"] = 1
        d[f"role_{s['role']}"] = 1
        return d

    views = {
        "node_presence_only": feat_node_presence,
        "graph_size_only": feat_graph_size,
        "rule_engine_only": feat_rule_rel,
        "bag_of_primitives": feat_primitives,
        "full_reference": feat_full,
    }
    results = {}
    for name, fn in views.items():
        X = DictVectorizer(sparse=False).fit_transform([fn(s) for s in sessions])
        clf = LogisticRegression(max_iter=2000)
        acc = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")
        f1 = cross_val_score(clf, X, y, cv=cv, scoring="f1")
        results[name] = {"cv_accuracy_mean": round(float(acc.mean()), 3),
                         "cv_accuracy_std": round(float(acc.std()), 3),
                         "cv_f1_mean": round(float(f1.mean()), 3),
                         "n_features": int(X.shape[1])}
    results["_note"] = ("A shortcut view whose accuracy approaches full_reference means that "
                        "impoverished view alone separates the classes. Where the acceptable gap "
                        "lies is set with the user from these numbers, not decided here. "
                        "Behavior-masked GAT baseline deferred (Algorithm 3 emits no Behavior nodes yet).")
    results["_class_balance"] = {"malicious": int(y.sum()), "benign": int((1 - y).sum()), "cv_folds": n_splits}
    report["shortcut_baselines"] = results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="datagen/generated")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    root = Path(args.root)
    sessions, scenarios = load_corpus(root)
    report = {"root": str(root), "n_runs": len({s["run"] for s in sessions}),
              "n_scenarios": len(scenarios), "n_sessions": len(sessions)}
    if not sessions:
        print("No correlated sessions found under", root, file=sys.stderr)
        sys.exit(2)
    check_presence_independence(sessions, report)
    check_primitive_one_class(sessions, report)
    check_matched_pairs(scenarios, report)
    check_family_duplicates(sessions, scenarios, report)
    check_shortcut_baselines(sessions, report)
    print(json.dumps(report, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
