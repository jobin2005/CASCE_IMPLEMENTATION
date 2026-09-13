#!/usr/bin/env python3
"""codegen.py -- turn hand-written scenario specs into CASCE run artifacts.

Usage:
    python datagen/codegen.py <run_dir> [--date YYYY-MM-DD]

Reads every ``<run_dir>/specs/*.yaml`` (lexicographic filename order),
validates it against ``datagen/scenario_spec.schema.json`` and the rules in
``datagen/scenario_spec.md``, then writes -- all-or-nothing -- into
``<run_dir>/``:

    postgres_events.json     kernel_events.json
    labels.csv               expectation_manifest.json

The implementation follows ``datagen/codegen_and_validator_spec.md`` sections
1.1-1.10.  Shared validation helpers are also imported by ``validate_run.py``
so the two tools cannot silently drift apart on what a valid spec is.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlfacts import extract_query_facts  # noqa: E402  (needs sys.path above)

SCHEMA_PATH = Path(__file__).resolve().parent / "scenario_spec.schema.json"

# ---- run-wide constants (spec 1.3 / 1.4) ---------------------------------
PID_START = 20000
MONOTONIC_BASE_NS = 5_000_000_000_000  # spec 1.4 example base
D_MAX = 8                               # spec 1.3, Algorithm 1 D_MAX
IMPLIED_DELTA_SEC = 0.001               # spec 1.4 point 5
SPAWN_WINDOW_SEC = 5.0                  # spec 1.4/1.5; mirrors graphsops

DIMENSION_VOCAB = {
    "process_tree_shape",
    "syscall_sequence",
    "timing_pattern",
    "sql_content",
    "connects_to_destination",
    "role",
}

EVENT_KINDS = ("sql", "process", "file", "connect")
FILE_SYSCALLS = {"openat", "unlink", "rename"}

# Shell builtins that are not real executables (spec 1.5 out-of-scope bullet).
# Comprehensive POSIX/bash builtin list. Commands that also exist as real
# binaries on a typical Linux PATH (echo, printf, test, true, false, pwd,
# kill, [, ...) are intentionally NOT listed -- the spec rejects only builtins
# that aren't real executables.
SHELL_BUILTINS = {
    ".", ":", "alias", "bg", "bind", "break", "builtin", "cd", "command",
    "compgen", "complete", "continue", "declare", "dirs", "disown",
    "enable", "eval", "exec", "exit", "export", "fc", "fg", "getopts",
    "hash", "help", "history", "jobs", "let", "local", "logout", "mapfile",
    "popd", "pushd", "read", "readarray", "readonly", "return", "set",
    "shift", "shopt", "source", "suspend", "times", "trap", "type",
    "typeset", "ulimit", "umask", "unalias", "unset", "wait",
    # Reserved words -- a "command" starting with one is a shell construct,
    # never a real executable.
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do",
    "done", "case", "esac", "function", "select", "time", "coproc", "in",
}


# ==========================================================================
# Errors / failures
# ==========================================================================

@dataclass
class Failure:
    filename: str
    scenario_id: Optional[str]
    session_label: Optional[str]
    step_id: Optional[str]
    reason: str


class BuildError(Exception):
    """A hard build error carrying structured context (spec 1.9 / 1.10)."""

    def __init__(self, failure: Failure):
        super().__init__(failure.reason)
        self.failure = failure


class ShellParseError(Exception):
    """Raised by parse_shell_command for out-of-v1-scope constructs."""


def format_error(f: Failure) -> str:
    scen = f.scenario_id if f.scenario_id else "-"
    sess = f.session_label if f.session_label else "-"
    step = f.step_id if f.step_id else "-"
    return f"ERROR: {f.filename}: {scen}/{sess}/{step}: {f.reason}"


# ==========================================================================
# Schema / spec loading
# ==========================================================================

@dataclass
class SpecFile:
    filename: str
    path: Path
    data: Dict[str, Any]


def load_schema() -> Dict[str, Any]:
    with SCHEMA_PATH.open() as f:
        return json.load(f)


def load_spec_files(specs_dir: Path) -> List[SpecFile]:
    """Load every *.yaml under specs_dir, sorted lexicographically.

    A YAML parse failure is a hard build error (spec 1.9 bullet 1).
    """
    import yaml  # local import keeps module import cheap for validate_run

    files: List[SpecFile] = []
    if not specs_dir.is_dir():
        return files
    for path in sorted(specs_dir.glob("*.yaml"), key=lambda p: p.name):
        try:
            with path.open() as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise BuildError(Failure(path.name, None, None, None,
                                     f"YAML parse failure: {exc}"))
        files.append(SpecFile(filename=path.name, path=path, data=data))
    return files


def schema_failures(sf: SpecFile) -> List[Failure]:
    """Validate one spec against scenario_spec.schema.json (spec 1.9 bullet 2)."""
    import jsonschema

    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(sf.data), key=lambda e: list(e.path))
    out: List[Failure] = []
    sid = sf.data.get("scenario_id") if isinstance(sf.data, dict) else None
    for err in errors:
        where = "/".join(str(p) for p in err.path) or "<root>"
        out.append(Failure(sf.filename, sid, None, None,
                           f"schema violation at {where}: {err.message}"))
    return out


# ==========================================================================
# Static (schedule-independent) spec invariants -- spec 1.9
# ==========================================================================

def _event_parent(ev: Dict[str, Any]) -> Optional[str]:
    for kind in ("process", "file", "connect"):
        if kind in ev and isinstance(ev[kind], dict):
            return ev[kind].get("parent")
    return None


def static_failures(sf: SpecFile, check_sql_parse: bool = False) -> List[Failure]:
    """Every per-spec invariant that does not require a resolved schedule.

    ``check_sql_parse`` mirrors codegen's hard error on sqlfacts parse_error
    (spec 1.9 bullet 3); validate_run leaves it to its own Check 2 and passes
    False.
    """
    fails: List[Failure] = []
    if not isinstance(sf.data, dict):
        return fails  # schema_failures reports this
    data = sf.data
    sid = data.get("scenario_id")
    default_class = data.get("default_class")

    # matched_dimensions closed vocabulary (spec 1.9 bullet 7).
    md = data.get("matched_dimensions")
    if isinstance(md, dict):
        for bucket in ("fixed", "varied"):
            for dim in (md.get(bucket) or []):
                if dim not in DIMENSION_VOCAB:
                    fails.append(Failure(
                        sf.filename, sid, None, None,
                        f"matched_dimensions.{bucket} entry {dim!r} is not in the "
                        f"closed vocabulary"))

    sessions = data.get("sessions") or []
    seen_labels: set = set()
    scenario_has_os = False

    for sess in sessions:
        if not isinstance(sess, dict):
            continue
        label = sess.get("session_label")
        if label in seen_labels:
            fails.append(Failure(sf.filename, sid, label, None,
                                 "duplicate session_label within scenario"))
        seen_labels.add(label)

        eff_class = sess.get("class") or default_class
        if eff_class is None:
            fails.append(Failure(
                sf.filename, sid, label, None,
                "session has no class and scenario has no default_class"))

        anchor = sess.get("anchor", "db")
        events = sess.get("events") or []
        sql_events = [ev for ev in events
                      if isinstance(ev, dict) and "sql" in ev]
        if anchor == "db" and not sql_events:
            fails.append(Failure(
                sf.filename, sid, label, None,
                "anchor: db session has zero sql events"))

        # tempo validation (bursty / steady); off_hours needs a schedule and
        # is checked in off_hours_failures.
        timing = sess.get("timing") or {}
        gaps = timing.get("step_gaps_seconds")
        gaps_eff = list(gaps) if gaps else [1.0]
        tempo = timing.get("tempo")
        if tempo == "bursty":
            for g in gaps_eff:
                if not (g < 2.0):
                    fails.append(Failure(
                        sf.filename, sid, label, None,
                        f"tempo 'bursty' but step_gaps_seconds contains {g} "
                        f"(must be < 2.0)"))
                    break
        elif tempo == "steady":
            mean = sum(gaps_eff) / len(gaps_eff)
            for g in gaps_eff:
                if abs(g - mean) > 0.2 * mean:
                    fails.append(Failure(
                        sf.filename, sid, label, None,
                        f"tempo 'steady' but step_gaps_seconds {gaps_eff} is not "
                        f"within 20% of the mean ({mean})"))
                    break

        seen_steps: set = set()
        session_has_os = False
        for ev in events:
            if not isinstance(ev, dict):
                continue
            step_id = ev.get("step_id")
            kinds = [k for k in EVENT_KINDS if k in ev]
            if len(kinds) != 1:
                fails.append(Failure(
                    sf.filename, sid, label, step_id,
                    f"event must have exactly one of sql/process/file/connect "
                    f"(found {kinds or 'none'})"))
                if step_id is not None:
                    if step_id in seen_steps:
                        pass
                    seen_steps.add(step_id)
                continue

            kind = kinds[0]
            parent = _event_parent(ev)
            if kind in ("file", "connect") and not parent:
                fails.append(Failure(
                    sf.filename, sid, label, step_id,
                    f"{kind} event has no parent"))
            if parent is not None and parent not in seen_steps:
                fails.append(Failure(
                    sf.filename, sid, label, step_id,
                    f"parent {parent!r} does not resolve to a prior step in "
                    f"this session"))

            if step_id is not None:
                if step_id in seen_steps:
                    fails.append(Failure(
                        sf.filename, sid, label, step_id,
                        "duplicate step_id within session"))
                seen_steps.add(step_id)

            if kind in ("process", "file", "connect"):
                session_has_os = True
            elif kind == "sql":
                facts = extract_query_facts(ev["sql"])
                if facts.get("is_program"):
                    session_has_os = True
                if check_sql_parse and facts.get("parse_error"):
                    fails.append(Failure(
                        sf.filename, sid, label, step_id,
                        f"sqlfacts parse error: {facts['parse_error']}"))

        scenario_has_os = scenario_has_os or session_has_os

    # Cross-layer scope invariant (spec 1.9 bullet; scenario_spec cross-layer).
    if sessions and not scenario_has_os:
        fails.append(Failure(
            sf.filename, sid, None, None,
            "scenario has no OS-layer activity in any session (no "
            "process/file/connect event and no COPY ... TO PROGRAM)"))

    return fails


def global_failures(spec_files: List[SpecFile]) -> List[Failure]:
    """Run-wide invariants spanning spec files (spec 1.9 bullets 6 and 12)."""
    fails: List[Failure] = []

    # Duplicate scenario_id (spec 1.9 bullet 12).
    counts = Counter(sf.data.get("scenario_id")
                     for sf in spec_files if isinstance(sf.data, dict))
    for sf in spec_files:
        if not isinstance(sf.data, dict):
            continue
        sid = sf.data.get("scenario_id")
        if counts[sid] > 1:
            fails.append(Failure(sf.filename, sid, None, None,
                                 f"duplicate scenario_id {sid!r} across spec files"))

    # matched_pair_id sibling presence (spec 1.9 bullet 6).
    pair_counts = Counter(sf.data.get("matched_pair_id")
                          for sf in spec_files
                          if isinstance(sf.data, dict)
                          and sf.data.get("matched_pair_id"))
    for sf in spec_files:
        if not isinstance(sf.data, dict):
            continue
        pid = sf.data.get("matched_pair_id")
        if not pid:
            continue
        if pair_counts[pid] != 2:
            fails.append(Failure(
                sf.filename, sf.data.get("scenario_id"), None, None,
                f"matched_pair_id {pid!r} has {pair_counts[pid] - 1} sibling(s) "
                f"in specs/ (exactly 1 required)"))

    return fails


# ==========================================================================
# Shell parsing (spec 1.5)
# ==========================================================================

@dataclass
class ShellSegment:
    comm: str
    command: str
    redirects: List[str] = field(default_factory=list)


def parse_shell_command(shell_cmd: str) -> List[ShellSegment]:
    """Parse a COPY ... TO PROGRAM command into pipeline segments.

    Raises ShellParseError for anything outside the v1 scope (spec 1.5).
    """
    raw = shell_cmd
    if "$(" in raw:
        raise ShellParseError("subshell $(...) is out of v1 scope")
    if "`" in raw:
        raise ShellParseError("backtick command substitution is out of v1 scope")
    if "<(" in raw or ">(" in raw:
        raise ShellParseError("process substitution is out of v1 scope")
    if re.search(r"\$\{?[A-Za-z_]", raw):
        raise ShellParseError("variable expansion ($VAR) is out of v1 scope")
    if "<<" in raw:
        raise ShellParseError("here-documents/here-strings are out of v1 scope")

    segments: List[ShellSegment] = []
    for segment_text in raw.split("|"):
        stripped = segment_text.strip()
        if not stripped:
            raise ShellParseError("empty pipeline segment")
        try:
            toks = shlex.split(stripped)
        except ValueError as exc:
            raise ShellParseError(f"shell quoting error: {exc}")
        if not toks:
            raise ShellParseError("empty pipeline segment")

        if any(t in ("&", ";") for t in toks):
            raise ShellParseError(
                "background (&) and semicolon chaining (;) are out of v1 scope")

        cmd_tokens: List[str] = []
        redirects: List[str] = []
        i = 0
        while i < len(toks):
            tok = toks[i]
            op: Optional[str] = None
            target: Optional[str] = None
            if tok in (">", ">>", "<"):
                op = tok
                if i + 1 >= len(toks):
                    raise ShellParseError(f"redirection {op} without a target")
                target = toks[i + 1]
                i += 2
            else:
                m = re.match(r"^(?:\d+)?(>>|>|<)(.*)$", tok)
                if m and m.group(1) in (">", ">>", "<"):
                    op = m.group(1)
                    rest = m.group(2)
                    if rest.startswith("&"):
                        raise ShellParseError(
                            f"file-descriptor duplication {tok!r} is out of v1 scope")
                    if rest:
                        target = rest
                        i += 1
                    elif i + 1 < len(toks):
                        target = toks[i + 1]
                        i += 2
                    else:
                        raise ShellParseError(f"redirection {op} without a target")
            if op is not None:
                redirects.append(target)
                continue
            cmd_tokens.append(tok)
            i += 1

        if not cmd_tokens:
            raise ShellParseError("pipeline segment has no executable command")
        comm = cmd_tokens[0]
        if comm in SHELL_BUILTINS:
            raise ShellParseError(
                f"shell builtin {comm!r} is not a real executable (out of v1 scope)")
        segments.append(ShellSegment(comm=comm, command=stripped,
                                     redirects=redirects))

    return segments


# ==========================================================================
# Scheduling (spec 1.4)
# ==========================================================================

ANCHOR_KEY = "__anchor_query__"

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


def event_list_for_session(sess: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Session's event list including synthetic anchor and domain/role padding."""
    out: List[Dict[str, Any]] = []
    role = sess.get("role", "postgres")
    padding = DEFAULT_PADDING_PROFILE.get(role, {
        "pre": [{"sql": "SELECT 1"}],
        "post": [{"sql": "SELECT 1"}]
    })

    # Generator-level session padding (cover traffic)
    out.extend(padding.get("pre", []))

    if sess.get("anchor", "db") == "synthetic":
        out.append({ANCHOR_KEY: sess.get("anchor_query") or "SELECT 1"})
    out.extend(sess.get("events") or [])

    out.extend(padding.get("post", []))
    return out



def get_gaps(sess: Dict[str, Any]) -> List[float]:
    timing = sess.get("timing") or {}
    gaps = timing.get("step_gaps_seconds")
    if not gaps:
        return [1.0]  # spec 1.9 "not errors": no timing -> default gaps
    return [float(g) for g in gaps]


def compute_event_times(start: float, n_events: int, gaps: List[float]) -> List[float]:
    """i-th event time = start + sum(gaps[j % len] for j in range(i-1))."""
    times = [float(start)]
    for i in range(1, n_events):
        times.append(times[i - 1] + gaps[(i - 1) % len(gaps)])
    return times


def _time_of_day_epoch(gen_date, hhmm: str) -> float:
    try:
        hh, mm = hhmm.split(":")
        hh = int(hh)
        mm = int(mm)
    except (ValueError, AttributeError):
        hh, mm = 0, 0
    return datetime.combine(gen_date, dtime(hh, mm)).timestamp()


def resolve_scenario_times(sf: SpecFile, gen_date) -> List[List[float]]:
    """Resolve per-session per-event wall-clock times for one scenario.

    Raises BuildError for an unresolvable/cyclic concurrent_with reference.
    """
    data = sf.data
    sid = data.get("scenario_id")
    sessions = data.get("sessions") or []
    labels = [s.get("session_label") for s in sessions]
    t0 = _time_of_day_epoch(gen_date, data.get("time_of_day") or "00:00")

    resolved: Dict[int, List[float]] = {}
    in_progress: set = set()

    def resolve(i: int) -> List[float]:
        if i in resolved:
            return resolved[i]
        if i in in_progress:
            raise BuildError(Failure(
                sf.filename, sid, labels[i], None,
                f"concurrent_with creates a cycle involving "
                f"{labels[i]!r}"))
        in_progress.add(i)
        sess = sessions[i]
        n_events = len(event_list_for_session(sess))
        cw = sess.get("concurrent_with")
        if cw:
            if cw not in labels:
                raise BuildError(Failure(
                    sf.filename, sid, sess.get("session_label"), None,
                    f"concurrent_with {cw!r} does not resolve to another "
                    f"session label in this scenario"))
            ref = resolve(labels.index(cw))
            first, last = ref[0], ref[-1]
            if first == last or n_events == 0:
                start = first
            else:
                # Deterministic pseudo-random placement strictly inside the
                # referenced session's [first, last] window (spec 1.4 pt 3).
                import hashlib
                seed = int(hashlib.sha256(
                    f"{sid}:{labels[i]}:{cw}".encode()).hexdigest(), 16)
                import random
                r = random.Random(seed).random()
                start = first + (last - first) * (0.05 + 0.9 * r)
        else:
            if i == 0:
                start = t0
            else:
                prev = resolve(i - 1)
                delay = sess.get("delay_after_previous_seconds")
                delay = 0.0 if delay is None else float(delay)
                start = prev[-1] + delay
        times = compute_event_times(start, n_events, get_gaps(sess))
        resolved[i] = times
        in_progress.discard(i)
        return times

    for i in range(len(sessions)):
        resolve(i)
    return [resolved[i] for i in range(len(sessions))]


def off_hours_failures(sf: SpecFile, gen_date) -> List[Failure]:
    """tempo 'off_hours' check (spec 1.4) -- needs resolved session times."""
    fails: List[Failure] = []
    if not isinstance(sf.data, dict):
        return fails
    sessions = sf.data.get("sessions") or []
    try:
        times_by_session = resolve_scenario_times(sf, gen_date)
    except BuildError as exc:
        fails.append(exc.failure)
        return fails
    except Exception:
        # Malformed specs are reported by schema_failures; don't crash here.
        return fails
    sid = sf.data.get("scenario_id")
    for sess, times in zip(sessions, times_by_session):
        timing = sess.get("timing") or {}
        if timing.get("tempo") != "off_hours" or not times:
            continue
        hour = datetime.fromtimestamp(times[0]).hour
        if 8 <= hour < 18:
            fails.append(Failure(
                sf.filename, sid, sess.get("session_label"), None,
                f"tempo 'off_hours' but session's first event resolves to "
                f"{datetime.fromtimestamp(times[0]).isoformat()} "
                f"(inside 08:00-18:00)"))
    return fails


# ==========================================================================
# Runtime model
# ==========================================================================

@dataclass
class EmittedRecord:
    session: "SessionRuntime"
    source: str                      # "kernel" | "postgres"
    timestamp: float                 # desired wall-clock unix epoch seconds
    raw: Dict[str, Any]
    facts: Dict[str, Any]
    step_id: Optional[str]
    source_event_type: str           # sql|process|file|connect|implied
    event_index: int                 # index within the session's event list
    raw_ns: int = 0                  # kernel only, filled once T_min is known
    event_id: int = -1


@dataclass
class StepInfo:
    kind: str
    pid: Optional[int]
    ppid: Optional[int]
    comm: Optional[str]
    depth: int = 0


@dataclass
class SessionRuntime:
    scenario: "ScenarioRuntime"
    index: int
    sess: Dict[str, Any]
    label: Optional[str]
    backend_pid: int
    anchor: str
    role: str
    effective_class: str
    times: List[float]
    records: List[EmittedRecord] = field(default_factory=list)
    expected_correlation: bool = True


@dataclass
class ScenarioRuntime:
    sf: SpecFile
    index: int
    sessions: List[SessionRuntime] = field(default_factory=list)


class PidAllocator:
    def __init__(self) -> None:
        self.next = PID_START
        self.used: set = set()

    def alloc(self) -> int:
        pid = self.next
        self.next += 1
        self.used.add(pid)
        return pid


# ==========================================================================
# Event building (spec 1.3 / 1.6)
# ==========================================================================

def _kernel_record(pid, ppid, comm, syscall, arg,
                   dest_ip=None, dest_port=None):
    rec = {
        "pid": pid,
        "ppid": ppid,
        "uid": 0,
        "timestamp": 0,  # replaced after clock base is known
        "comm": comm,
        "syscall": syscall,
        "arg": arg,
    }
    if dest_ip is not None:
        rec["dest_ip"] = dest_ip
        rec["dest_port"] = dest_port
    return rec


def _postgres_record(session: SessionRuntime, ts: float, query: str, event_type: str = "ProcessUtility") -> Dict[str, Any]:
    return {
        "session_id": session.backend_pid,
        "session_start_time": int(session.times[0]),
        "backend_pid": session.backend_pid,
        "timestamp": ts,
        "event_type": event_type,
        "query": query,
        "database": "casce_synthetic",
        "username": session.role,
        "client_addr": "192.168.1.200",
        "client_port": str(session.backend_pid),
    }


def build_session(scenario: ScenarioRuntime, index: int, alloc: PidAllocator) -> SessionRuntime:
    sf = scenario.sf
    data = sf.data
    sid = data.get("scenario_id")
    sess = data["sessions"][index]
    label = sess.get("session_label")
    anchor = sess.get("anchor", "db")
    role = sess.get("role") or "postgres"  # spec 1.9 "not errors"
    eff_class = sess.get("class") or data.get("default_class")

    backend_pid = alloc.alloc()  # one per session (spec 1.3 pt 1)

    try:
        times = resolve_scenario_times(sf, STATIC_GEN_DATE)[index]
    except BuildError:
        raise
    runtime = SessionRuntime(
        scenario=scenario, index=index, sess=sess, label=label,
        backend_pid=backend_pid, anchor=anchor, role=role,
        effective_class=eff_class, times=times,
        expected_correlation=(anchor != "none"),
    )

    raw_events = event_list_for_session(sess)
    steps: Dict[str, StepInfo] = {}
    emit_postgres = anchor != "none"  # anchor:none never registers in Alg 1

    for ev_index, ev in enumerate(raw_events):
        ts = times[ev_index]
        if ANCHOR_KEY in ev:
            query = ev[ANCHOR_KEY]
            facts = extract_query_facts(query)
            if facts.get("parse_error"):
                raise BuildError(Failure(
                    sf.filename, sid, label, None,
                    f"anchor_query sqlfacts parse error: {facts['parse_error']}"))
            if emit_postgres:
                raw = _postgres_record(runtime, ts, query, event_type="ExecutorStart")
                runtime.records.append(EmittedRecord(
                    session=runtime, source="postgres", timestamp=ts, raw=raw,
                    facts=facts, step_id=None, source_event_type="sql",
                    event_index=ev_index))
                raw_end = _postgres_record(runtime, ts + 0.0005, query, event_type="ExecutorEnd")
                runtime.records.append(EmittedRecord(
                    session=runtime, source="postgres", timestamp=ts + 0.0005, raw=raw_end,
                    facts=facts, step_id=None, source_event_type="sql",
                    event_index=ev_index))
            continue

        step_id = ev.get("step_id")
        kinds = [k for k in EVENT_KINDS if k in ev]
        if len(kinds) != 1:
            raise BuildError(Failure(
                sf.filename, sid, label, step_id,
                f"event must have exactly one of sql/process/file/connect "
                f"(found {kinds or 'none'})"))
        kind = kinds[0]
        parent = _event_parent(ev)
        if parent is not None and parent not in steps:
            raise BuildError(Failure(
                sf.filename, sid, label, step_id,
                f"parent {parent!r} does not resolve to a prior step in this "
                f"session"))

        if kind == "sql":
            _build_sql_event(runtime, ev, step_id, ts, ev_index,
                             steps=steps, alloc=alloc, sf=sf)
        elif kind == "process":
            _build_process_event(runtime, ev, step_id, ts, ev_index, steps, alloc, sf)
        elif kind == "file":
            _build_file_event(runtime, ev, step_id, ts, ev_index, steps, sf)
        elif kind == "connect":
            _build_connect_event(runtime, ev, step_id, ts, ev_index, steps, sf)

    return runtime


def _register_step(steps, step_id, info):
    if step_id is not None:
        steps[step_id] = info


def _parent_step(steps, parent):
    return steps.get(parent) if parent else None


def _build_sql_event(runtime, ev, step_id, ts, ev_index, steps, alloc, sf):
    sf_data = sf.data
    sid = sf_data.get("scenario_id")
    label = runtime.label
    query = ev["sql"]
    facts = extract_query_facts(query)
    if facts.get("parse_error"):
        raise BuildError(Failure(sf.filename, sid, label, step_id,
                                 f"sqlfacts parse error: {facts['parse_error']}"))

    q_upper = query.strip().upper()
    is_dml = any(q_upper.startswith(kw) for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"])

    if runtime.anchor != "none":
        if is_dml:
            # Emit ExecutorStart
            runtime.records.append(EmittedRecord(
                session=runtime, source="postgres", timestamp=ts,
                raw=_postgres_record(runtime, ts, query, event_type="ExecutorStart"), facts=facts,
                step_id=step_id, source_event_type="sql", event_index=ev_index))
            # Emit ExecutorEnd
            runtime.records.append(EmittedRecord(
                session=runtime, source="postgres", timestamp=ts + 0.0005,
                raw=_postgres_record(runtime, ts + 0.0005, query, event_type="ExecutorEnd"), facts=facts,
                step_id=step_id, source_event_type="sql", event_index=ev_index))
        else:
            runtime.records.append(EmittedRecord(
                session=runtime, source="postgres", timestamp=ts,
                raw=_postgres_record(runtime, ts, query, event_type="ProcessUtility"), facts=facts,
                step_id=step_id, source_event_type="sql", event_index=ev_index))


    spawned: List[StepInfo] = []
    if facts.get("is_program") and facts.get("shell_cmd"):
        try:
            segments = parse_shell_command(facts["shell_cmd"])
        except ShellParseError as exc:
            raise BuildError(Failure(
                sf.filename, sid, label, step_id,
                f"COPY ... TO PROGRAM shell string out of v1 scope: {exc}"))
        for k, seg in enumerate(segments):
            pid = alloc.alloc()
            if k == 0:
                ppid = runtime.backend_pid
                depth = 1
            else:
                ppid = spawned[-1].pid
                depth = spawned[-1].depth + 1
            if depth > D_MAX:
                raise BuildError(Failure(
                    sf.filename, sid, label, step_id,
                    f"process tree exceeds D_MAX={D_MAX} levels below "
                    f"backend_pid"))
            raw = _kernel_record(pid, ppid, seg.comm, "execve", seg.command)
            runtime.records.append(EmittedRecord(
                session=runtime, source="kernel", timestamp=ts + IMPLIED_DELTA_SEC * (k + 1),
                raw=raw, facts={}, step_id=step_id,
                source_event_type="implied", event_index=ev_index))
            spawned.append(StepInfo(kind="process", pid=pid, ppid=ppid,
                                    comm=seg.comm, depth=depth))
            # redirections -> openat file syscalls by this same process
            for ridx, path in enumerate(seg.redirects):
                fraw = _kernel_record(pid, ppid, seg.comm, "openat", path)
                runtime.records.append(EmittedRecord(
                    session=runtime, source="kernel",
                    timestamp=ts + IMPLIED_DELTA_SEC * (len(segments) + ridx + 1),
                    raw=fraw, facts={}, step_id=step_id,
                    source_event_type="implied", event_index=ev_index))

    # connects_to emitted after the event's own records (spec 1.6: a
    # connects_to on any sql/process event always emits an additional connect
    # record). For an explicit COPY ... TO PROGRAM this is attributed to the
    # last spawned pipeline process, whether or not its command is one of the
    # recognized network tools (spec 1.5 only says codegen must not *guess* a
    # destination from the command text when connects_to is absent).
    connects = ev.get("connects_to")
    if connects:
        if spawned:
            last = spawned[-1]
            _emit_connect(runtime, last.pid, last.ppid, last.comm, ts +
                          IMPLIED_DELTA_SEC * (len(spawned) + 1),
                          step_id, "implied", ev_index, connects)
        else:
            # Non-COPY sql with connects_to -> 1.6 emits a connect record.
            _emit_connect(runtime, runtime.backend_pid, 0, "postgres",
                          ts + IMPLIED_DELTA_SEC, step_id, "implied", ev_index,
                          connects)

    last = spawned[-1] if spawned else None
    _register_step(steps, step_id, StepInfo(
        kind="sql",
        pid=last.pid if last else None,
        ppid=last.ppid if last else None,
        comm=last.comm if last else None,
        depth=last.depth if last else 0,
    ))


def _build_process_event(runtime, ev, step_id, ts, ev_index, steps, alloc, sf):
    pinfo = ev["process"]
    comm = pinfo.get("comm")
    args = pinfo.get("args") or []
    parent = pinfo.get("parent")
    parent_step = _parent_step(steps, parent)
    ppid = parent_step.pid if (parent_step and parent_step.pid is not None) \
        else runtime.backend_pid
    depth = (parent_step.depth + 1) if parent_step else 1
    if depth > D_MAX:
        raise BuildError(Failure(
            sf.filename, sf.data.get("scenario_id"), runtime.label, step_id,
            f"process tree exceeds D_MAX={D_MAX} levels below backend_pid"))
    pid = alloc.alloc()
    arg = comm + (" " + " ".join(args) if args else "")
    raw = _kernel_record(pid, ppid, comm, "execve", arg)
    runtime.records.append(EmittedRecord(
        session=runtime, source="kernel", timestamp=ts, raw=raw, facts={},
        step_id=step_id, source_event_type="process", event_index=ev_index))
    info = StepInfo(kind="process", pid=pid, ppid=ppid, comm=comm, depth=depth)
    _register_step(steps, step_id, info)
    connects = ev.get("connects_to")
    if connects:
        _emit_connect(runtime, pid, ppid, comm, ts + IMPLIED_DELTA_SEC,
                      step_id, "process", ev_index, connects)


def _resolve_syscall_parent(runtime, parent, steps):
    parent_step = _parent_step(steps, parent)
    if parent_step is None:
        return runtime.backend_pid, 0, "postgres"
    pid = parent_step.pid if parent_step.pid is not None else runtime.backend_pid
    ppid = parent_step.ppid if parent_step.ppid is not None else 0
    comm = parent_step.comm or "postgres"
    return pid, ppid, comm


def _build_file_event(runtime, ev, step_id, ts, ev_index, steps, sf):
    finfo = ev["file"]
    pid, ppid, comm = _resolve_syscall_parent(runtime, finfo.get("parent"), steps)
    raw = _kernel_record(pid, ppid, comm, finfo["syscall"], finfo["path"])
    runtime.records.append(EmittedRecord(
        session=runtime, source="kernel", timestamp=ts, raw=raw, facts={},
        step_id=step_id, source_event_type="file", event_index=ev_index))
    _register_step(steps, step_id, StepInfo(kind="file", pid=pid, ppid=ppid,
                                            comm=comm))


def _build_connect_event(runtime, ev, step_id, ts, ev_index, steps, sf):
    cinfo = ev["connect"]
    pid, ppid, comm = _resolve_syscall_parent(runtime, cinfo.get("parent"), steps)
    _emit_connect(runtime, pid, ppid, comm, ts, step_id, "connect",
                  ev_index, cinfo)


def _emit_connect(runtime, pid, ppid, comm, ts, step_id, source_event_type,
                  ev_index, connects):
    raw = _kernel_record(pid, ppid, comm, "connect", "",
                         dest_ip=connects["ip"], dest_port=connects["port"])
    runtime.records.append(EmittedRecord(
        session=runtime, source="kernel", timestamp=ts, raw=raw, facts={},
        step_id=step_id, source_event_type=source_event_type,
        event_index=ev_index))


# ==========================================================================
# Event-id assignment -- mirrors algorithm_1.load_master_log exactly
# ==========================================================================

def assign_event_ids(all_records: List[EmittedRecord]) -> None:
    kernel = sorted((r for r in all_records if r.source == "kernel"),
                    key=lambda r: r.raw_ns)
    postgres = sorted((r for r in all_records if r.source == "postgres"),
                      key=lambda r: r.timestamp)
    combined = kernel + postgres  # kernel appended first, stable sort follows
    combined.sort(key=lambda r: r.timestamp)
    for i, rec in enumerate(combined):
        rec.event_id = i


# ==========================================================================
# Expectation manifest graph derivation (spec 1.7.4)
# ==========================================================================

def _identify_node_types(rec: EmittedRecord) -> List[str]:
    if rec.source == "postgres":
        if rec.raw.get("event_type") == "ExecutorEnd":
            return []
        types = ["Query"]
        facts = rec.facts or {}
        if facts.get("table_name"):
            types.append("Table")
        if facts.get("role_name"):
            types.append("Role")
        return types

    syscall = rec.raw.get("syscall")
    if syscall == "execve":
        return ["Process"]
    if syscall in FILE_SYSCALLS:
        return ["Process", "File"]
    if syscall == "connect":
        types = ["Process"]
        if rec.raw.get("dest_ip"):
            types.append("Endpoint")
        return types
    return []


def _node_key_hint(node_type, rec: EmittedRecord):
    facts = rec.facts or {}
    if node_type == "Session":
        return rec.session.backend_pid, str(rec.session.backend_pid)
    if node_type == "Query":
        return rec.event_id, str(rec.event_id)
    if node_type == "Table":
        v = facts.get("table_name")
        return v, str(v)
    if node_type == "Role":
        v = facts.get("role_name")
        return v, str(v)
    if node_type == "Process":
        v = rec.raw.get("pid")
        return v, str(v)
    if node_type == "File":
        v = rec.raw.get("arg")
        return v, str(v)
    if node_type == "Endpoint":
        v = (rec.raw.get("dest_ip"), rec.raw.get("dest_port"))
        return v, f"({v[0]}, {v[1]})"
    return None, ""


def _find_connection(node_type, rec, process_keys, pending, pending_ts):
    if node_type == "Query":
        return ("Session", rec.session.backend_pid), "executes"
    if node_type in ("Table", "Role"):
        return ("Query", rec.event_id), "accesses"
    if node_type == "Process":
        ppid = rec.raw.get("ppid")
        if ppid and ("Process", ppid) in process_keys:
            return ("Process", ppid), "spawns"
        if pending is not None and pending_ts is not None and \
                (rec.timestamp - pending_ts) < SPAWN_WINDOW_SEC:
            return ("Query", pending), "spawns"
        return None, None
    if node_type == "Endpoint":
        return ("Process", rec.raw.get("pid")), "connects_to"
    if node_type == "File":
        return ("Process", rec.raw.get("pid")), "opens"
    return None, None


def simulate_expected(session: SessionRuntime):
    """Derive (expected_nodes, expected_edges) for one correlated session."""
    if not session.expected_correlation:
        return [], []
    recs = sorted(session.records, key=lambda r: (r.timestamp, r.event_id))
    node_hints: Dict[Tuple[str, str], Dict[str, Any]] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    process_keys: set = set()
    pending = None
    pending_ts = None

    # Algorithm 2 materializes a Session node the first time it processes a
    # Query for the session (find_connection_rule), so the manifest must
    # expect it -- otherwise validate_run can never catch a missing Session.
    first_sql_step = next((r.step_id for r in recs if r.source == "postgres"),
                          None)
    node_hints[("Session", str(session.backend_pid))] = {
        "node_type": "Session",
        "key_hint": str(session.backend_pid),
        "source_step_id": first_sql_step,
        "source_event_type": "sql",
    }

    for rec in recs:
        for nt in _identify_node_types(rec):
            key, hint = _node_key_hint(nt, rec)
            if (nt, hint) not in node_hints:
                node_hints[(nt, hint)] = {
                    "node_type": nt,
                    "key_hint": hint,
                    "source_step_id": rec.step_id,
                    "source_event_type": rec.source_event_type,
                }
            if nt == "Process":
                process_keys.add(("Process", key))
            u, rel = _find_connection(nt, rec, process_keys, pending, pending_ts)
            if u is not None:
                src_type = u[0]
                edge_key = (rel, src_type, nt)
                if edge_key not in edges:
                    edges[edge_key] = {
                        "edge_type": rel,
                        "source_node_type": src_type,
                        "target_node_type": nt,
                        "source_step_id": None,
                        "target_step_id": rec.step_id,
                    }
        if rec.source == "postgres" and (rec.facts or {}).get("is_program"):
            pending = rec.event_id
            pending_ts = rec.timestamp

    nodes = sorted(node_hints.values(),
                   key=lambda n: (n["node_type"], n["key_hint"]))
    edge_list = sorted(edges.values(),
                       key=lambda e: (e["edge_type"], e["source_node_type"],
                                      e["target_node_type"]))
    return nodes, edge_list


# ==========================================================================
# Full build
# ==========================================================================

STATIC_GEN_DATE = datetime.now().date()


def build(run_dir: Path, gen_date) -> Dict[str, Any]:
    global STATIC_GEN_DATE
    STATIC_GEN_DATE = gen_date

    specs_dir = run_dir / "specs"
    spec_files = load_spec_files(specs_dir)

    # Hard errors: schema + static invariants (spec 1.9), first error wins.
    for sf in spec_files:
        for f in schema_failures(sf):
            raise BuildError(f)
        for f in static_failures(sf, check_sql_parse=True):
            raise BuildError(f)
    for f in global_failures(spec_files):
        raise BuildError(f)
    for sf in spec_files:
        for f in off_hours_failures(sf, gen_date):
            raise BuildError(f)

    alloc = PidAllocator()
    scenarios: List[ScenarioRuntime] = []
    for s_idx, sf in enumerate(spec_files):
        scenario = ScenarioRuntime(sf=sf, index=s_idx)
        n_sessions = len(sf.data.get("sessions") or [])
        for i in range(n_sessions):
            scenario.sessions.append(build_session(scenario, i, alloc))
        scenarios.append(scenario)

    all_records: List[EmittedRecord] = [r for sc in scenarios
                                        for s in sc.sessions for r in s.records]
    real_event_count = len(all_records)

    # Run clock base. LOGGING_START must not be later than any event in either
    # output file, so W = the minimum wall-clock timestamp across *all* events
    # (postgres and kernel), not just the earliest kernel event (spec 1.4/1.8).
    #
    # algorithm_1._calibrate_kernel_clock derives its offset from the FIRST
    # kernel record in the file, so for the calibration to recover each event's
    # intended T exactly the first kernel record's raw value must be
    # MONOTONIC_BASE_NS. When the earliest overall event is a postgres event
    # that precedes all kernel activity, we emit one calibration anchor kernel
    # record at W with raw == MONOTONIC_BASE_NS. It is never correlated (pid 0
    # has no ppid chain), is ignored by identify_node_types, and never reaches
    # Algorithm 2 because only correlated events do.
    all_ts = [r.timestamp for r in all_records]
    w_marker = min(all_ts) if all_ts else _time_of_day_epoch(gen_date, "00:00")
    clock_offset = w_marker - MONOTONIC_BASE_NS / 1e9

    kernel_records = [r for r in all_records if r.source == "kernel"]
    t_kmin = min((r.timestamp for r in kernel_records), default=None)
    if all_ts and (t_kmin is None or t_kmin > w_marker):
        anchor = EmittedRecord(
            session=None, source="kernel", timestamp=w_marker,
            raw={"pid": 0, "ppid": 0, "uid": 0,
                 "timestamp": MONOTONIC_BASE_NS,
                 "comm": "clock_anchor", "syscall": "clock_nanosleep",
                 "arg": ""},
            facts={}, step_id=None, source_event_type="implied", event_index=-1)
        all_records.append(anchor)
        kernel_records.append(anchor)

    for r in kernel_records:
        r.raw_ns = int(round((r.timestamp - clock_offset) * 1e9))
        r.raw["timestamp"] = r.raw_ns

    assign_event_ids(all_records)

    postgres_records = [r for r in all_records if r.source == "postgres"]
    postgres_records.sort(key=lambda r: (r.timestamp, r.session.scenario.index,
                                         r.session.index, r.event_index))
    kernel_sorted = sorted(kernel_records, key=lambda r: (r.raw_ns,))

    # ---- labels.csv rows -------------------------------------------------
    label_rows: List[Tuple[str, str]] = [("", "Normal")]
    for sc in scenarios:
        for s in sc.sessions:
            label_rows.append((str(s.backend_pid),
                               s.effective_class.replace("_", " ").title()))

    # ---- expectation manifest -------------------------------------------
    manifest_scenarios: Dict[str, Any] = {}
    for sc in scenarios:
        data = sc.sf.data
        sessions_manifest: Dict[str, Any] = {}
        for s in sc.sessions:
            nodes, edges = simulate_expected(s)
            sessions_manifest[s.label] = {
                "backend_pid": s.backend_pid,
                "class": s.effective_class,
                "role": s.role,
                "anchor": s.anchor,
                "expected_correlation": s.expected_correlation,
                "expected_nodes": nodes,
                "expected_edges": edges,
            }
        md = data.get("matched_dimensions")
        manifest_scenarios[data.get("scenario_id")] = {
            "source_file": sc.sf.filename,
            "family_id": data.get("family_id"),
            "matched_pair_id": data.get("matched_pair_id"),
            "matched_dimensions": md,
            "default_class": data.get("default_class"),
            "rule_engine_relationship": data.get("rule_engine_relationship",
                                                 "agrees"),
            "sessions": sessions_manifest,
        }

    manifest = {
        "run_dir": str(run_dir),
        "generation_date": gen_date.isoformat(),
        "logging_start_timestamp": w_marker,
        "scenarios": manifest_scenarios,
    }

    def jlines(records: List[EmittedRecord]) -> str:
        lines = [json.dumps({"marker": "LOGGING_START", "timestamp": w_marker})]
        for r in records:
            lines.append(json.dumps(r.raw))
        return "\n".join(lines) + "\n"

    outputs = {
        "postgres_events.json": jlines(postgres_records),
        "kernel_events.json": jlines(kernel_sorted),
        "labels.csv": _render_csv(label_rows),
        "expectation_manifest.json": json.dumps(manifest, indent=2) + "\n",
    }

    return {
        "outputs": outputs,
        "scenarios": len(scenarios),
        "sessions": sum(len(sc.sessions) for sc in scenarios),
        "events": real_event_count,
    }


def _render_csv(rows: List[Tuple[str, str]]) -> str:
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["session_id", "label"])
    for r in rows:
        writer.writerow(list(r))
    return buf.getvalue()


OUTPUT_FILES = ("postgres_events.json", "kernel_events.json", "labels.csv",
                "expectation_manifest.json")


def write_outputs_atomic(run_dir: Path, outputs: Dict[str, str]) -> None:
    """Stage all outputs, then commit the whole set or none of it.

    Writes every file into a private staging directory first; only once all
    writes have succeeded does it move them into place. Existing files are
    backed up during the commit and restored if any move fails, so a failure
    never leaves a mix of old and new artifacts (spec 1.10).
    """
    import shutil
    import tempfile

    staging = Path(tempfile.mkdtemp(prefix=".codegen_staging_", dir=run_dir))
    backups: Dict[str, Path] = {}
    moved: List[str] = []
    try:
        # Stage + verify every file before touching the run directory.
        for name, text in outputs.items():
            path = staging / name
            path.write_text(text)
            if path.stat().st_size != len(text.encode()):
                raise OSError(f"short write staging {name}")
        # Commit, keeping backups so a mid-commit failure can roll back.
        for name in outputs:
            final = run_dir / name
            if final.exists():
                bak = run_dir / (name + ".bak")
                os.replace(final, bak)
                backups[name] = bak
            os.replace(staging / name, final)
            moved.append(name)
    except Exception:
        for name in moved:
            try:
                (run_dir / name).unlink()
            except OSError:
                pass
        for name, bak in backups.items():
            try:
                os.replace(bak, run_dir / name)
            except OSError:
                pass
        raise
    else:
        for bak in backups.values():
            try:
                bak.unlink()
            except OSError:
                pass
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# ==========================================================================
# CLI
# ==========================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate CASCE run artifacts from scenario specs.")
    parser.add_argument("run_dir", help="run directory containing specs/*.yaml")
    parser.add_argument("--date", default=None,
                        help="generation date YYYY-MM-DD (default: today)")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if args.date:
        try:
            gen_date = datetime.strptime(args.date, "%Y-%m-%d").date()
        except ValueError:
            print(f"ERROR: --date {args.date!r} is not YYYY-MM-DD", file=sys.stderr)
            return 1
    else:
        gen_date = datetime.now().date()

    try:
        result = build(run_dir, gen_date)
    except BuildError as exc:
        print(format_error(exc.failure), file=sys.stderr)
        _cleanup_temps(run_dir)
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        print(f"ERROR: internal failure: {exc}", file=sys.stderr)
        _cleanup_temps(run_dir)
        return 1

    try:
        write_outputs_atomic(run_dir, result["outputs"])
    except Exception as exc:
        # Spec 1.10: failure means no output files; report cleanly, no traceback.
        print(f"ERROR: {run_dir}: failed to write output files: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        _cleanup_temps(run_dir)
        return 1

    print(f"OK: {result['scenarios']} scenarios, {result['sessions']} sessions, "
          f"{result['events']} events \u2192 {run_dir}")
    return 0


def _cleanup_temps(run_dir: Path) -> None:
    import shutil
    for name in OUTPUT_FILES:
        for suffix in (".tmp", ".bak"):
            path = run_dir / (name + suffix)
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                elif path.exists():
                    path.unlink()
            except OSError:
                pass
    for staging in run_dir.glob(".codegen_staging_*"):
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
