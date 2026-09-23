#!/usr/bin/env python3
"""validate_run.py -- validate a generated CASCE run directory.

Usage:
    python datagen/validate_run.py <run_dir>

Runs four checks in order (spec 2.2), collecting every failure rather than
stopping at the first:

  1. schema and enum conformance of ``<run_dir>/specs/*.yaml``
  2. pglast parse check of every sql string
  3. full pipeline correlation + graph-shape check against
     ``expectation_manifest.json``
  4. matched-pair sibling / class / fixed / varied dimension checks

Check 1 is implemented independently of codegen.py (spec 2.2 explicitly wants
it to be able to catch a bug in codegen's own validation); only the schema
file and a couple of pure constants/data structures are shared.

Exit codes: 0 pass, 1 one or more checks failed, 2 internal error.
A JSON report is written to ``<run_dir>/validation_report.json``; the same
failures go to stderr.  ``<run_dir>/tmp_validate/`` is always removed.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlfacts import extract_query_facts  # noqa: E402

_SCHEMA_PATH = Path(__file__).resolve().parent / "scenario_spec.schema.json"

REQUIRED_FILES = ("postgres_events.json", "kernel_events.json",
                  "labels.csv", "expectation_manifest.json")

# Shared pure constants (data only -- not validation logic).
DIMENSION_VOCAB = {
    "process_tree_shape", "syscall_sequence", "timing_pattern",
    "sql_content", "connects_to_destination", "role",
}
EVENT_KINDS = ("sql", "process", "file", "connect")
FILE_SYSCALLS = {"openat", "unlink", "rename"}
ANCHOR_KEY = "__anchor_query__"
BACKEND = object()  # canonical-tree sentinel: process rooted at the backend


# ==========================================================================
# Small helpers
# ==========================================================================

@dataclass
class SpecFile:
    filename: str
    path: Path
    data: Any


def _fail_line(check: str, scenario_id, session_label, reason: str) -> str:
    return f"FAIL [{check}] {scenario_id or '-'}/{session_label or '-'}: {reason}"


def _f(sid, label, step, reason: str) -> Dict[str, Any]:
    return {
        "scenario_id": sid,
        "session_label": label,
        "step_id": step,
        "reason": reason,
    }


def _sid(sf: SpecFile):
    return sf.data.get("scenario_id") if isinstance(sf.data, dict) else None


def _spec_sessions(sf: SpecFile) -> List[Any]:
    if not isinstance(sf.data, dict):
        return []
    sessions = sf.data.get("sessions")
    return sessions if isinstance(sessions, list) else []


def _event_parent(ev: Dict[str, Any]) -> Optional[str]:
    for kind in ("process", "file", "connect"):
        info = ev.get(kind)
        if isinstance(info, dict):
            return info.get("parent")
    return None


def _event_kind(ev: Dict[str, Any]) -> Optional[str]:
    for kind in EVENT_KINDS:
        if kind in ev:
            return kind
    return None


def _facts(query) -> Dict[str, Any]:
    if not isinstance(query, str) or not query:
        return {}
    try:
        return extract_query_facts(query)
    except Exception:
        return {}


DEFAULT_PADDING_PROFILE = {
    "teller": {
        "pre": [{"sql": "SELECT 1"}, {"sql": "SELECT column_name FROM information_schema.columns WHERE table_name = 'accounts'"}],
        "post": [{"sql": "SELECT branch_id FROM branches WHERE is_active = true"}]
    },
    "branch_manager": {
        "pre": [{"sql": "SELECT 1"}, {"sql": "SELECT setting, unit FROM pg_settings WHERE name = 'work_mem'"}],
        "post": [{"sql": "SELECT count(*) FROM branches"}]
    },
    "compliance_officer": {
        "pre": [{"sql": "SELECT 1"}, {"sql": "SELECT session_user, current_user"}],
        "post": [{"sql": "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"}]
    },
    "batch_etl_service": {
        "pre": [{"sql": "SELECT 1"}, {"sql": "SELECT setting FROM pg_settings WHERE name = 'server_version'"}],
        "post": [{"sql": "SELECT pg_is_in_recovery()"}]
    }
}


def _event_list(sess: Any) -> List[Dict[str, Any]]:
    """Session events including synthetic anchor and padding (mirrors codegen)."""
    out: List[Dict[str, Any]] = []
    if not isinstance(sess, dict):
        return out
    role = sess.get("role", "postgres")
    padding = DEFAULT_PADDING_PROFILE.get(role, {
        "pre": [{"sql": "SELECT 1"}],
        "post": [{"sql": "SELECT 1"}]
    })
    out.extend(padding.get("pre", []))
    if sess.get("anchor", "db") == "synthetic":
        out.append({ANCHOR_KEY: sess.get("anchor_query") or "SELECT 1"})
    events = sess.get("events")
    if isinstance(events, list):
        out.extend(ev for ev in events if isinstance(ev, dict))
    out.extend(padding.get("post", []))
    return out



def _explicit_events(sess: Any) -> List[Dict[str, Any]]:
    if not isinstance(sess, dict):
        return []
    events = sess.get("events")
    return [ev for ev in events if isinstance(ev, dict)] if isinstance(events, list) else []


# ==========================================================================
# Spec loading (independent of codegen.py)
# ==========================================================================

def load_specs(specs_dir: Path) -> Tuple[List[SpecFile], List[Dict[str, Any]]]:
    """Load specs, collecting YAML errors as Check-1 failures instead of raising."""
    import yaml

    files: List[SpecFile] = []
    failures: List[Dict[str, Any]] = []
    if not specs_dir.is_dir():
        return files, failures
    for path in sorted(specs_dir.glob("*.yaml"), key=lambda p: p.name):
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            failures.append(_f(None, None, None,
                               f"YAML parse failure: {exc}"))
            continue
        except OSError as exc:
            failures.append(_f(None, None, None, f"cannot read spec: {exc}"))
            continue
        files.append(SpecFile(filename=path.name, path=path, data=data))
    return files, failures


# ==========================================================================
# Check 1: schema and enum conformance (independent implementation)
# ==========================================================================

def schema_failures(sf: SpecFile) -> List[Dict[str, Any]]:
    import jsonschema

    try:
        schema = json.loads(_SCHEMA_PATH.read_text())
        validator = jsonschema.Draft7Validator(schema)
    except Exception as exc:  # pragma: no cover - environment problem
        return [_f(_sid(sf), None, None, f"schema load failure: {exc}")]
    try:
        errors = sorted(validator.iter_errors(sf.data),
                        key=lambda e: list(e.path))
    except Exception as exc:
        return [_f(_sid(sf), None, None, f"schema validation error: {exc}")]
    out = []
    for err in errors:
        where = "/".join(str(p) for p in err.path) or "<root>"
        out.append(_f(_sid(sf), None, None,
                      f"schema violation at {where}: {err.message}"))
    return out


def static_failures(sf: SpecFile) -> List[Dict[str, Any]]:
    """Per-spec invariants from spec 1.9 / 2.2 Check 1, schedule-independent."""
    fails: List[Dict[str, Any]] = []
    if not isinstance(sf.data, dict):
        fails.append(_f(None, None, None, "spec root must be a mapping"))
        return fails
    sid = sf.data.get("scenario_id")
    default_class = sf.data.get("default_class")

    md = sf.data.get("matched_dimensions")
    if md is not None:
        if not isinstance(md, dict):
            fails.append(_f(sid, None, None, "matched_dimensions must be a mapping"))
        else:
            for bucket in ("fixed", "varied"):
                dims = md.get(bucket)
                if dims is None:
                    continue
                if not isinstance(dims, list):
                    fails.append(_f(sid, None, None,
                                    f"matched_dimensions.{bucket} must be a list"))
                    continue
                for dim in dims:
                    if dim not in DIMENSION_VOCAB:
                        fails.append(_f(
                            sid, None, None,
                            f"matched_dimensions.{bucket} entry {dim!r} is not in "
                            f"the closed vocabulary"))

    sessions = sf.data.get("sessions")
    if not isinstance(sessions, list):
        fails.append(_f(sid, None, None, "sessions must be a list"))
        sessions = []

    seen_labels: set = set()
    scenario_has_os = False
    for sess in sessions:
        if not isinstance(sess, dict):
            fails.append(_f(sid, None, None, "session entry must be a mapping"))
            continue
        label = sess.get("session_label")
        if label in seen_labels:
            fails.append(_f(sid, label, None,
                            "duplicate session_label within scenario"))
        seen_labels.add(label)

        eff_class = sess.get("class") or default_class
        if eff_class is None:
            fails.append(_f(sid, label, None,
                            "session has no class and scenario has no "
                            "default_class"))

        anchor = sess.get("anchor", "db")
        events = sess.get("events")
        if not isinstance(events, list):
            fails.append(_f(sid, label, None, "events must be a list"))
            events = []
        sql_events = [ev for ev in events
                      if isinstance(ev, dict) and "sql" in ev]
        if anchor == "db" and not sql_events:
            fails.append(_f(sid, label, None,
                            "anchor: db session has zero sql events"))

        timing = sess.get("timing")
        tempo = None
        gaps = [1.0]
        if isinstance(timing, dict):
            tempo = timing.get("tempo")
            g = timing.get("step_gaps_seconds")
            if isinstance(g, list) and g:
                try:
                    gaps = [float(x) for x in g]
                except (TypeError, ValueError):
                    fails.append(_f(sid, label, None,
                                    "step_gaps_seconds must be numeric"))
                    gaps = [1.0]
            elif g is not None and not isinstance(g, list):
                fails.append(_f(sid, label, None,
                                "step_gaps_seconds must be a list"))
        if tempo == "bursty" and any(not (g < 2.0) for g in gaps):
            fails.append(_f(sid, label, None,
                            f"tempo 'bursty' but step_gaps_seconds {gaps} "
                            f"contains a gap >= 2.0"))
        elif tempo == "steady":
            mean = sum(gaps) / len(gaps)
            if any(abs(g - mean) > 0.2 * mean for g in gaps):
                fails.append(_f(sid, label, None,
                                f"tempo 'steady' but step_gaps_seconds {gaps} "
                                f"is not within 20% of the mean ({mean})"))

        seen_steps: set = set()
        session_has_os = False
        for ev in events:
            if not isinstance(ev, dict):
                fails.append(_f(sid, label, None, "event entry must be a mapping"))
                continue
            step_id = ev.get("step_id")
            kinds = [k for k in EVENT_KINDS if k in ev]
            if len(kinds) != 1:
                fails.append(_f(sid, label, step_id,
                                f"event must have exactly one of "
                                f"sql/process/file/connect (found "
                                f"{kinds or 'none'})"))
            parent = _event_parent(ev)
            if kinds and kinds[0] in ("file", "connect") and not parent:
                fails.append(_f(sid, label, step_id,
                                f"{kinds[0]} event has no parent"))
            if parent is not None and parent not in seen_steps:
                fails.append(_f(sid, label, step_id,
                                f"parent {parent!r} does not resolve to a prior "
                                f"step in this session"))
            if step_id is not None:
                if step_id in seen_steps:
                    fails.append(_f(sid, label, step_id,
                                    "duplicate step_id within session"))
                seen_steps.add(step_id)

            if kinds and kinds[0] in ("process", "file", "connect"):
                session_has_os = True
            elif kinds and kinds[0] == "sql":
                if _facts(ev.get("sql")).get("is_program"):
                    session_has_os = True
        scenario_has_os = scenario_has_os or session_has_os

    if sessions and not scenario_has_os:
        fails.append(_f(sid, None, None,
                        "scenario has no OS-layer activity in any session (no "
                        "process/file/connect event and no COPY ... TO PROGRAM)"))
    return fails


def _tod_epoch(gen_date, hhmm) -> float:
    from datetime import time as dtime
    try:
        hh, mm = str(hhmm).split(":")
        hh, mm = int(hh), int(mm)
    except (ValueError, AttributeError, TypeError):
        hh, mm = 0, 0
    return datetime.combine(gen_date, dtime(hh, mm)).timestamp()


def _schedule_times(sf: SpecFile, gen_date) -> Dict[int, List[float]]:
    """Independent schedule resolution (spec 1.4) for off_hours + cycle checks."""
    data = sf.data
    if not isinstance(data, dict):
        return {}
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        return {}
    labels = [s.get("session_label") if isinstance(s, dict) else None
              for s in sessions]
    t0 = _tod_epoch(gen_date, data.get("time_of_day") or "00:00")

    def gaps_of(sess):
        if not isinstance(sess, dict):
            return [1.0]
        timing = sess.get("timing")
        if isinstance(timing, dict):
            g = timing.get("step_gaps_seconds")
            if isinstance(g, list) and g:
                return [float(x) for x in g]
        return [1.0]

    def times(start, n, gaps):
        out = [float(start)]
        for i in range(1, n):
            out.append(out[i - 1] + gaps[(i - 1) % len(gaps)])
        return out

    resolved: Dict[int, List[float]] = {}
    in_progress: set = set()

    class _Cycle(Exception):
        pass

    class _BadRef(Exception):
        pass

    def resolve(i: int) -> List[float]:
        if i in resolved:
            return resolved[i]
        if i in in_progress:
            raise _Cycle(labels[i])
        in_progress.add(i)
        sess = sessions[i]
        n_events = len(_event_list(sess))
        cw = sess.get("concurrent_with") if isinstance(sess, dict) else None
        if cw:
            if cw not in labels:
                raise _BadRef(cw)
            ref = resolve(labels.index(cw))
            first, last = ref[0], ref[-1]
            start = first if (first == last or n_events == 0) \
                else first + (last - first) * 0.5
        else:
            if i == 0:
                start = t0
            else:
                prev = resolve(i - 1)
                delay = sess.get("delay_after_previous_seconds") \
                    if isinstance(sess, dict) else None
                start = prev[-1] + (0.0 if delay is None else float(delay))
        result = times(start, n_events, gaps_of(sess))
        resolved[i] = result
        in_progress.discard(i)
        return result

    for i in range(len(sessions)):
        resolve(i)
    return resolved


def off_hours_failures(sf: SpecFile, gen_date) -> List[Dict[str, Any]]:
    data = sf.data
    if not isinstance(data, dict):
        return []
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        return []
    sid = data.get("scenario_id")
    fails: List[Dict[str, Any]] = []
    try:
        resolved = _schedule_times(sf, gen_date)
    except Exception as exc:
        label = getattr(exc, "args", [None])[0]
        fails.append(_f(sid, label, None,
                        f"concurrent_with is unresolved or creates a cycle: "
                        f"{exc}"))
        return fails
    for i, sess in enumerate(sessions):
        if not isinstance(sess, dict):
            continue
        timing = sess.get("timing")
        if not isinstance(timing, dict) or timing.get("tempo") != "off_hours":
            continue
        times = resolved.get(i) or []
        if not times:
            continue
        when = datetime.fromtimestamp(times[0])
        if 8 <= when.hour < 18:
            fails.append(_f(sid, sess.get("session_label"), None,
                            f"tempo 'off_hours' but session's first event "
                            f"resolves to {when.isoformat()} (inside 08:00-18:00)"))
    return fails


def check_schema(spec_files: List[SpecFile], yaml_failures: List[Dict[str, Any]],
                 gen_date) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = list(yaml_failures)
    for sf in spec_files:
        failures.extend(schema_failures(sf))
        failures.extend(static_failures(sf))
    for sf in spec_files:
        failures.extend(off_hours_failures(sf, gen_date))
    return failures


# ==========================================================================
# Check 2: pglast parse check
# ==========================================================================

def check_pglast(spec_files: List[SpecFile]) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    for sf in spec_files:
        data = sf.data
        if not isinstance(data, dict):
            continue
        sid = data.get("scenario_id")
        sessions = data.get("sessions")
        if not isinstance(sessions, list):
            continue
        for sess in sessions:
            if not isinstance(sess, dict):
                continue
            label = sess.get("session_label")
            queries = []
            if sess.get("anchor", "db") == "synthetic":
                queries.append((None, sess.get("anchor_query") or "SELECT 1"))
            events = sess.get("events")
            if isinstance(events, list):
                for ev in events:
                    if isinstance(ev, dict) and "sql" in ev:
                        queries.append((ev.get("step_id"), ev.get("sql")))
            for step_id, sql in queries:
                if not isinstance(sql, str):
                    continue
                facts = _facts(sql)
                if facts.get("parse_error"):
                    failures.append(_f(
                        sid, label, step_id,
                        f"pglast parse error: {facts['parse_error']}"))
    return failures


# ==========================================================================
# Check 3: pipeline correlation and graph shape
# ==========================================================================

def _parse_key(node_type: str, hint: str):
    if node_type in ("Session", "Query", "Process"):
        return int(hint)
    if node_type == "Endpoint":
        inner = hint.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
        ip, port = inner.rsplit(",", 1)
        return (ip.strip(), int(port.strip()))
    return hint


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def check_pipeline(run_dir: Path, manifest: Dict[str, Any],
                   tmp_dir: Path) -> Tuple[List[Dict[str, Any]], set]:
    from algorithm_1 import run_one
    from algorithm2 import run as run_alg2

    failures: List[Dict[str, Any]] = []
    tmp_dir.mkdir(parents=True, exist_ok=True)
    graphs_dir = tmp_dir / "graphs"

    master_log, correlated = run_one(run_dir)

    referenced = sorted({eid for _sk, eid in correlated})
    lookup = [master_log[eid] for eid in referenced]
    event_table = [
        {
            "event_id": e.event_id,
            "source": e.source,
            "timestamp": e.timestamp,
            "pid": e.pid,
            "raw": e.raw,
        }
        for e in lookup
    ]
    (tmp_dir / "event_table.json").write_text(json.dumps(event_table))
    with (tmp_dir / "correlation.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["session_key", "event_id"])
        writer.writerows(correlated)

    active_graphs, _rows, _orphans, _parse_errors = run_alg2(
        event_table_path=tmp_dir / "event_table.json",
        correlation_path=tmp_dir / "correlation.csv",
        out_dir=graphs_dir,
        run_id="validate",
        labels_path=run_dir / "labels.csv",
    )

    correlated_keys = {sk for sk, _eid in correlated}
    scenarios = _as_dict(manifest.get("scenarios"))
    expected_true_pids = set()
    for sc in scenarios.values():
        for s in _as_dict(_as_dict(sc).get("sessions")).values():
            if _as_dict(s).get("expected_correlation"):
                expected_true_pids.add(_as_dict(s).get("backend_pid"))

    for sid, sc in scenarios.items():
        sessions = _as_dict(_as_dict(sc).get("sessions"))
        for label, s in sessions.items():
            s = _as_dict(s)
            pid = s.get("backend_pid")
            present = pid in correlated_keys
            if s.get("expected_correlation") and not present:
                failures.append({
                    "scenario_id": sid, "session_label": label,
                    "check_type": "correlation",
                    "expected": "session_key present",
                    "actual": "not in Algorithm 1 correlated output",
                    "reason": f"backend_pid {pid} did not correlate",
                })
            if (not s.get("expected_correlation")) and present:
                failures.append({
                    "scenario_id": sid, "session_label": label,
                    "check_type": "correlation",
                    "expected": "session_key absent (anchor: none)",
                    "actual": "session_key present",
                    "reason": f"anchor: none backend_pid {pid} unexpectedly correlated",
                })
            if not s.get("expected_correlation"):
                continue

            G = active_graphs.get(pid)
            nodes = s.get("expected_nodes")
            for node in (nodes if isinstance(nodes, list) else []):
                if not isinstance(node, dict):
                    continue
                nt = node.get("node_type")
                hint = node.get("key_hint")
                expected = f"{nt}:{hint}"
                if G is None:
                    failures.append({
                        "scenario_id": sid, "session_label": label,
                        "check_type": "node_type", "expected": expected,
                        "actual": "no graph for session",
                        "reason": "session graph missing",
                    })
                    continue
                try:
                    key = _parse_key(nt, hint)
                except Exception:
                    key = hint
                if (nt, key) not in G.nodes:
                    failures.append({
                        "scenario_id": sid, "session_label": label,
                        "check_type": "node_type", "expected": expected,
                        "actual": sorted(str(n) for n in G.nodes),
                        "reason": f"expected {nt} node with key {hint!r} missing",
                    })
            edges = s.get("expected_edges")
            for edge in (edges if isinstance(edges, list) else []):
                if not isinstance(edge, dict):
                    continue
                src = edge.get("source_node_type")
                tgt = edge.get("target_node_type")
                rel = edge.get("edge_type")
                expected = f"({src})-[{rel}]->({tgt})"
                if G is None:
                    failures.append({
                        "scenario_id": sid, "session_label": label,
                        "check_type": "edge_type", "expected": expected,
                        "actual": "no graph for session",
                        "reason": "session graph missing",
                    })
                    continue
                found = any(
                    u[0] == src and v[0] == tgt and d.get("rel") == rel
                    for u, v, d in G.edges(data=True)
                )
                if not found:
                    actual = sorted(
                        f"({u[0]})-[{d.get('rel')}]->({v[0]})"
                        for u, v, d in G.edges(data=True)
                    )
                    failures.append({
                        "scenario_id": sid, "session_label": label,
                        "check_type": "edge_type", "expected": expected,
                        "actual": actual,
                        "reason": f"expected edge {expected} missing",
                    })

    extras = correlated_keys - expected_true_pids
    if extras:
        failures.append({
            "scenario_id": None, "session_label": None,
            "check_type": "extra_session",
            "expected": "no extra sessions",
            "actual": sorted(extras),
            "reason": f"Algorithm 1 resolved unexpected session_key(s) "
                      f"{sorted(extras)}",
        })

    return failures, correlated_keys


# ==========================================================================
# Check 4: matched-pair checks
# ==========================================================================

def _session_process_nodes(sess: Any) -> List[Tuple[str, str, Any]]:
    """(nid, comm, parent_nid_or_BACKEND) for explicit + shell-implied processes.

    Parent links are resolved through the same pid-attribution codegen uses
    (spec 1.6): a process parented on a sql/file/connect step attaches to the
    process that actually owns that step's pid, or to the backend root when no
    process owns it -- never to a synthetic placeholder.
    """
    nodes: List[Tuple[str, str, Any]] = []
    steps: Dict[str, Any] = {}  # step_id -> owning process nid, or BACKEND
    idx = 0
    for ev in _event_list(sess):
        if ANCHOR_KEY in ev:
            idx += 1
            continue  # codegen emits no kernel events for the anchor query
        kind = _event_kind(ev)
        step_id = ev.get("step_id") or f"__{kind or 'ev'}{idx}"
        if kind == "sql":
            facts = _facts(ev.get("sql"))
            implied: List[str] = []
            if facts.get("is_program") and facts.get("shell_cmd"):
                try:
                    segments = _parse_shell(facts["shell_cmd"])
                except Exception:
                    segments = []
                for k, seg in enumerate(segments):
                    nid = f"{step_id}::{k}"
                    parent = BACKEND if k == 0 else implied[-1]
                    nodes.append((nid, seg[0], parent))
                    implied.append(nid)
            steps[step_id] = implied[-1] if implied else BACKEND
        elif kind == "process":
            pinfo = _as_dict(ev.get("process"))
            parent_step = pinfo.get("parent")
            parent = steps.get(parent_step, BACKEND) \
                if parent_step is not None else BACKEND
            nodes.append((step_id, pinfo.get("comm"), parent))
            steps[step_id] = step_id
        elif kind in ("file", "connect"):
            info = _as_dict(ev.get(kind))
            parent_step = info.get("parent")
            steps[step_id] = steps.get(parent_step, BACKEND) \
                if parent_step is not None else BACKEND
        idx += 1
    return nodes


def _parse_shell(cmd: str):
    """Thin wrapper returning (comm, [redirect_paths]) per pipeline segment."""
    import codegen as cg
    segments = cg.parse_shell_command(cmd)
    return [(seg.comm, list(seg.redirects)) for seg in segments]


def _canonical_tree(sess: Any) -> Counter:
    nodes = _session_process_nodes(sess)
    comm_of = {nid: comm for nid, comm, _p in nodes}
    parent_of = {nid: p for nid, _c, p in nodes}
    counter: Counter = Counter()
    for nid, _comm, _p in nodes:
        chain: List[str] = []
        cur: Any = nid
        seen: set = set()
        while cur is not BACKEND and cur is not None and \
                cur in comm_of and cur not in seen:
            seen.add(cur)
            chain.append(comm_of.get(cur, "?"))
            cur = parent_of.get(cur)
        chain.append("ROOT")
        counter[tuple(reversed(chain))] += 1
    return counter


def _sql_contents(sess: Any) -> List[str]:
    return [ev["sql"] for ev in _explicit_events(sess) if "sql" in ev]


def _destinations(sess: Any) -> List[Optional[Tuple[str, int]]]:
    out: List[Optional[Tuple[str, int]]] = []
    for ev in _explicit_events(sess):
        c = ev.get("connects_to")
        connect = ev.get("connect")
        if isinstance(c, dict) and "ip" in c and "port" in c:
            out.append((c["ip"], c["port"]))
        elif isinstance(connect, dict) and "ip" in connect and "port" in connect:
            out.append((connect["ip"], connect["port"]))
        else:
            out.append(None)
    return out


def _syscall_sequence(sf: SpecFile) -> List[str]:
    seq: List[str] = []
    for sess in _spec_sessions(sf):
        for ev in _event_list(sess):
            if ANCHOR_KEY in ev:
                continue
            kind = _event_kind(ev)
            if kind == "sql":
                facts = _facts(ev.get("sql"))
                if facts.get("is_program") and facts.get("shell_cmd"):
                    try:
                        segments = _parse_shell(facts["shell_cmd"])
                    except Exception:
                        segments = []
                    for _comm, redirects in segments:
                        seq.append("execve")
                        seq.extend("openat" for _ in redirects)
                if ev.get("connects_to"):
                    seq.append("connect")
            elif kind == "process":
                seq.append("execve")
                if ev.get("connects_to"):
                    seq.append("connect")
            elif kind == "file":
                seq.append(_as_dict(ev.get("file")).get("syscall"))
            elif kind == "connect":
                seq.append("connect")
    return seq


def _within_20(a: float, b: float) -> bool:
    m = max(abs(a), abs(b))
    if m == 0:
        return a == b
    return abs(a - b) <= 0.2 * m


def _gaps_of(sess: Any) -> List[float]:
    if not isinstance(sess, dict):
        return [1.0]
    timing = sess.get("timing")
    if isinstance(timing, dict):
        g = timing.get("step_gaps_seconds")
        if isinstance(g, list) and g:
            return [float(x) for x in g]
    return [1.0]


def _tempo_of(sess: Any):
    if not isinstance(sess, dict):
        return None
    timing = sess.get("timing")
    return timing.get("tempo") if isinstance(timing, dict) else None


def _ast_signature(sql: str):
    import pglast
    from pglast import ast as pgast
    try:
        parsed = pglast.parse_sql(sql)
    except Exception:
        return None
    if not parsed:
        return None

    def ser(o):
        if isinstance(o, pgast.Node):
            if isinstance(o, pgast.A_Const):
                return ("A_Const", "?")
            fields = {}
            for name in o.__slots__:
                try:
                    v = getattr(o, name)
                except Exception:
                    continue
                if v is None:
                    continue
                fields[name] = ser(v)
            return (type(o).__name__, fields)
        if isinstance(o, (list, tuple)):
            return tuple(ser(x) for x in o)
        if isinstance(o, bool) or isinstance(o, (int, float, str)):
            return o
        return repr(o)

    return repr(ser(parsed[0].stmt))


def _md_sets(sf: SpecFile):
    md = sf.data.get("matched_dimensions") if isinstance(sf.data, dict) else None
    md = md if isinstance(md, dict) else {}
    fixed = md.get("fixed") if isinstance(md.get("fixed"), list) else []
    varied = md.get("varied") if isinstance(md.get("varied"), list) else []
    return frozenset(fixed), frozenset(varied)


def _check_pair(mpid: str, a: SpecFile, b: SpecFile,
                failures: List[Dict[str, Any]]) -> None:
    sid_a = a.data.get("scenario_id") if isinstance(a.data, dict) else None
    sess_a = _spec_sessions(a)
    sess_b = _spec_sessions(b)

    def fail(check_type, scenario_id, dimension, reason):
        failures.append({
            "matched_pair_id": mpid,
            "scenario_id": scenario_id,
            "check_type": check_type,
            "dimension": dimension,
            "reason": reason,
        })

    # Both halves must declare identical fixed/varied dimension sets.
    if _md_sets(a) != _md_sets(b):
        fa, va = _md_sets(a)
        fb, vb = _md_sets(b)
        fail("dimension_mismatch", sid_a, None,
             f"paired scenarios declare different matched_dimensions: "
             f"{sid_a} fixed={sorted(fa)} varied={sorted(va)} vs "
             f"{b.data.get('scenario_id')} fixed={sorted(fb)} varied={sorted(vb)}")
        return

    # --- opposite class, per corresponding session pair ------------------
    for i in range(min(len(sess_a), len(sess_b))):
        sa, sb = sess_a[i], sess_b[i]
        ca = _eff_class(sa, a.data)
        cb = _eff_class(sb, b.data)
        if {ca, cb} != {"benign", "malicious"}:
            fail("same_class", sid_a, None,
                 f"corresponding session {i} classes are {ca!r} and {cb!r} "
                 f"(must be opposite)")

    fixed_dims, varied_dims = _md_sets(a)

    def corresponding():
        return [(sess_a[i], sess_b[i])
                for i in range(min(len(sess_a), len(sess_b)))]

    for dim in fixed_dims:
        if dim == "process_tree_shape":
            for i, (sa, sb) in enumerate(corresponding()):
                if _canonical_tree(sa) != _canonical_tree(sb):
                    fail("fixed_mismatch", sid_a, dim,
                         f"corresponding session {i} process trees differ")
        elif dim == "syscall_sequence":
            if _syscall_sequence(a) != _syscall_sequence(b):
                fail("fixed_mismatch", sid_a, dim,
                     "implied syscall sequences differ")
        elif dim == "timing_pattern":
            for i, (sa, sb) in enumerate(corresponding()):
                ta, tb = _tempo_of(sa), _tempo_of(sb)
                if ta != tb:
                    fail("fixed_mismatch", sid_a, dim,
                         f"corresponding session {i} tempo {ta!r} != {tb!r}")
                    continue
                ga, gb = _gaps_of(sa), _gaps_of(sb)
                for j in range(max(len(ga), len(gb))):
                    if not _within_20(ga[j % len(ga)], gb[j % len(gb)]):
                        fail("fixed_mismatch", sid_a, dim,
                             f"corresponding session {i} gaps differ at {j}")
                        break
        elif dim == "sql_content":
            for i, (sa, sb) in enumerate(corresponding()):
                qa, qb = _sql_contents(sa), _sql_contents(sb)
                if any(qa[j] != qb[j] for j in range(min(len(qa), len(qb)))):
                    fail("fixed_mismatch", sid_a, dim,
                         f"corresponding session {i} sql differs")
        elif dim == "connects_to_destination":
            for i, (sa, sb) in enumerate(corresponding()):
                da, db = _destinations(sa), _destinations(sb)
                for j in range(min(len(da), len(db))):
                    if (da[j] is not None or db[j] is not None) and da[j] != db[j]:
                        fail("fixed_mismatch", sid_a, dim,
                             f"corresponding session {i} destinations differ "
                             f"at event {j}: {da[j]} != {db[j]}")
                        break
        elif dim == "role":
            for i, (sa, sb) in enumerate(corresponding()):
                if _eff_role(sa) != _eff_role(sb):
                    fail("fixed_mismatch", sid_a, dim,
                         f"corresponding session {i} roles differ")

    for dim in varied_dims:
        if dim == "process_tree_shape":
            satisfied = len(sess_a) != len(sess_b) or any(
                _canonical_tree(sa) != _canonical_tree(sb)
                for sa, sb in corresponding())
            if not satisfied:
                fail("varied_not_different", sid_a, dim,
                     "process trees are identical across both halves")
        elif dim == "syscall_sequence":
            if _syscall_sequence(a) == _syscall_sequence(b):
                fail("varied_not_different", sid_a, dim,
                     "implied syscall sequences are identical")
        elif dim == "timing_pattern":
            satisfied = len(sess_a) != len(sess_b)
            for sa, sb in corresponding():
                if _tempo_of(sa) != _tempo_of(sb):
                    satisfied = True
                    break
                ga, gb = _gaps_of(sa), _gaps_of(sb)
                if any(not _within_20(ga[j % len(ga)], gb[j % len(gb)])
                       for j in range(max(len(ga), len(gb)))):
                    satisfied = True
                    break
            if not satisfied:
                fail("varied_not_different", sid_a, dim,
                     "timing pattern is identical across both halves")
        elif dim == "sql_content":
            satisfied = len(sess_a) != len(sess_b) or any(
                len(_sql_contents(sa)) != len(_sql_contents(sb))
                for sa, sb in corresponding())
            if not satisfied:
                for sa, sb in corresponding():
                    qa, qb = _sql_contents(sa), _sql_contents(sb)
                    for j in range(min(len(qa), len(qb))):
                        if qa[j] != qb[j]:
                            sig_a, sig_b = _ast_signature(qa[j]), _ast_signature(qb[j])
                            if sig_a is None or sig_b is None or sig_a != sig_b:
                                satisfied = True
                                break
                    if satisfied:
                        break
            if not satisfied:
                fail("varied_not_different", sid_a, dim,
                     "sql content differs only by literals (AST structure identical)")
        elif dim == "connects_to_destination":
            satisfied = len(sess_a) != len(sess_b)
            for sa, sb in corresponding():
                da, db = _destinations(sa), _destinations(sb)
                if len(da) != len(db):
                    satisfied = True
                    break
                if any((da[j] is not None or db[j] is not None) and da[j] != db[j]
                       for j in range(min(len(da), len(db)))):
                    satisfied = True
                    break
            if not satisfied:
                fail("varied_not_different", sid_a, dim,
                     "resolved destinations are identical across both halves")
        elif dim == "role":
            satisfied = len(sess_a) != len(sess_b) or any(
                _eff_role(sa) != _eff_role(sb) for sa, sb in corresponding())
            if not satisfied:
                fail("varied_not_different", sid_a, dim,
                     "roles are identical across both halves")


def _eff_class(sess: Any, scenario: Any) -> Optional[str]:
    if not isinstance(sess, dict) or not isinstance(scenario, dict):
        return None
    return sess.get("class") or scenario.get("default_class")


def _eff_role(sess: Any) -> str:
    return (sess.get("role") or "postgres") if isinstance(sess, dict) else "postgres"


def check_matched_pairs(spec_files: List[SpecFile]) -> Tuple[List[Dict[str, Any]], int]:
    failures: List[Dict[str, Any]] = []
    by_pair: Dict[str, List[SpecFile]] = defaultdict(list)
    for sf in spec_files:
        if isinstance(sf.data, dict) and sf.data.get("matched_pair_id"):
            by_pair[sf.data["matched_pair_id"]].append(sf)

    pairs_checked = 0
    for mpid, group in by_pair.items():
        if len(group) != 2:
            for sf in group:
                failures.append({
                    "matched_pair_id": mpid,
                    "scenario_id": sf.data.get("scenario_id")
                    if isinstance(sf.data, dict) else None,
                    "check_type": "sibling_missing",
                    "dimension": None,
                    "reason": f"matched_pair_id {mpid!r} has {len(group) - 1} "
                              f"sibling(s) in specs/ (exactly 1 required)",
                })
            continue
        pairs_checked += 1
        try:
            _check_pair(mpid, group[0], group[1], failures)
        except Exception as exc:
            failures.append({
                "matched_pair_id": mpid,
                "scenario_id": group[0].data.get("scenario_id")
                if isinstance(group[0].data, dict) else None,
                "check_type": "dimension_mismatch",
                "dimension": None,
                "reason": f"matched-pair check could not run: "
                          f"{type(exc).__name__}: {exc}",
            })
    return failures, pairs_checked


# ==========================================================================
# Report / driver
# ==========================================================================

def _status(failures: List[Any]) -> str:
    return "pass" if not failures else "fail"


def _safe_rmtree(path: Path, stage: str) -> bool:
    """Remove path; on failure warn loudly (spec 2.4 requires deletion)."""
    if not path.exists():
        return True
    try:
        shutil.rmtree(path)
        return True
    except OSError as exc:
        print(f"WARNING: could not delete {path} ({stage}): {exc}; "
              f"a stale tmp_validate/ may affect the next run", file=sys.stderr)
        return False


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a generated CASCE run directory.")
    parser.add_argument("run_dir", help="run directory written by codegen.py")
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir)

    for name in REQUIRED_FILES:
        if not (run_dir / name).exists():
            print(f"ERROR: internal: required file missing: {run_dir / name}",
                  file=sys.stderr)
            return 2
    try:
        manifest = json.loads((run_dir / "expectation_manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: internal: cannot read expectation_manifest.json: {exc}",
              file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("ERROR: internal: expectation_manifest.json is not an object",
              file=sys.stderr)
        return 2

    # Preflight the pipeline imports so an import failure is a clean exit 2.
    try:
        import importlib
        importlib.import_module("algorithm_1")
        importlib.import_module("algorithm2")
    except Exception as exc:
        print(f"ERROR: internal: pipeline import failure: {exc}", file=sys.stderr)
        return 2

    gen_date_str = manifest.get("generation_date")
    try:
        gen_date = datetime.strptime(gen_date_str, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        gen_date = datetime.now().date()

    spec_files, yaml_failures = load_specs(run_dir / "specs")

    tmp_dir = run_dir / "tmp_validate"
    _safe_rmtree(tmp_dir, "startup cleanup")  # spec 2.4: delete before starting

    pipeline_failures: List[Dict[str, Any]] = []
    matched_failures: List[Dict[str, Any]] = []
    pairs_checked = 0
    pipeline_error: Optional[Exception] = None
    try:
        schema_failures = check_schema(spec_files, yaml_failures, gen_date)
        pglast_failures = check_pglast(spec_files)
        try:
            pipeline_failures, _correlated = check_pipeline(
                run_dir, manifest, tmp_dir)
        except Exception as exc:
            pipeline_error = exc
        matched_failures, pairs_checked = check_matched_pairs(spec_files)
    finally:
        _safe_rmtree(tmp_dir, "post-run cleanup")

    if pipeline_error is not None:
        print(f"ERROR: internal: pipeline check crashed: "
              f"{type(pipeline_error).__name__}: {pipeline_error}",
              file=sys.stderr)
        return 2

    sessions_checked = sum(len(_spec_sessions(sf)) for sf in spec_files)
    total_failures = (len(schema_failures) + len(pglast_failures) +
                      len(pipeline_failures) + len(matched_failures))
    overall = "pass" if total_failures == 0 else "fail"

    report = {
        "run_dir": str(run_dir),
        "timestamp": datetime.now().isoformat(),
        "overall": overall,
        "checks": {
            "schema": {"status": _status(schema_failures),
                       "failures": schema_failures},
            "pglast": {"status": _status(pglast_failures),
                       "failures": pglast_failures},
            "pipeline": {"status": _status(pipeline_failures),
                         "algorithm_3_checked": False,
                         "failures": pipeline_failures},
            "matched_pairs": {"status": _status(matched_failures),
                              "failures": matched_failures},
        },
        "summary": {
            "scenarios_checked": len(spec_files),
            "sessions_checked": sessions_checked,
            "pairs_checked": pairs_checked,
            "total_failures": total_failures,
        },
    }
    (run_dir / "validation_report.json").write_text(
        json.dumps(report, indent=2) + "\n")

    for f in schema_failures:
        print(_fail_line("schema", f.get("scenario_id"), f.get("session_label"),
                         f.get("reason", "")), file=sys.stderr)
    for f in pglast_failures:
        print(_fail_line("pglast", f.get("scenario_id"), f.get("session_label"),
                         f.get("reason", "")), file=sys.stderr)
    for f in pipeline_failures:
        print(_fail_line("pipeline", f.get("scenario_id"), f.get("session_label"),
                         f.get("reason", "")), file=sys.stderr)
    for f in matched_failures:
        print(_fail_line("matched_pairs", f.get("scenario_id"), None,
                         f.get("reason", "")), file=sys.stderr)

    if overall == "pass":
        print(f"VALIDATION PASSED: {len(spec_files)} scenarios, "
              f"{sessions_checked} sessions, {pairs_checked} pairs checked")
        return 0
    print(f"VALIDATION FAILED: {total_failures} failures across "
          f"{len(spec_files)} scenarios")
    return 1


if __name__ == "__main__":
    sys.exit(main())
