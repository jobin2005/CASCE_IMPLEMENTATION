"""
Algorithm 1: Session-Anchored Correlation (SAC)
================================================

Correlates raw OS-kernel / PostgreSQL events with the DB session that
produced them, by walking the OS process tree back to a known session PID.

Design note
-----------
In production this algorithm consumes a live stream of *log records*
emitted by an eBPF logger (kernel side) and a PostgreSQL logging hook
(DB side) as they happen. To develop and evaluate it offline, this module
replays the frozen `kernel_events.json` / `postgres_events.json` files
from the CASCE dataset as if they were arriving one log line at a time,
in timestamp order. Every function below (`track_new_session`,
`link_event_to_session`, `trace_to_parent_session`, ...) operates on a
single incoming log record at a time -- exactly as it would against a
live tailer -- so swapping the offline `iter_log_stream()` generator for
a real-time log tailer later is a drop-in change.

Expected repo layout (this file lives at the project root):

    CASCE_IMPLEMENTATION/
        algorithm_1.py
        dataset_dev/
            run_1/  run_2/  run_3/
        dataset_test/
            run_1/  run_2/  run_3/

    Each run_N/ directory contains:
        kernel_events.json
        postgres_events.json
        labels.csv
        time_sync.json
        attack_scripts/
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

# --------------------------------------------------------------------------
# Repo layout
# --------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_DEV = PROJECT_ROOT / "dataset_dev"
DATASET_TEST = PROJECT_ROOT / "dataset_test"

D_MAX = 8  # max ancestor hops TraceToParentSession will walk


# --------------------------------------------------------------------------
# Log record model
# --------------------------------------------------------------------------

@dataclass
class LogEvent:
    """A single normalized log line, from either source."""
    source: str                 # "kernel" | "postgres"
    timestamp: float            # unix epoch seconds, for stream ordering
    pid: int                    # process id (kernel) / backend pid (postgres)
    raw: Dict[str, Any]         # original decoded JSON record

    @property
    def is_postgres(self) -> bool:
        return self.source == "postgres"


# --------------------------------------------------------------------------
# Offline log replay (stands in for the live eBPF / PG logger feed)
# --------------------------------------------------------------------------

def _iter_raw_lines(path: Path) -> Iterator[Dict[str, Any]]:
    """Read every JSON line in a log file, markers included."""
    if not path.exists():
        return
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _calibrate_kernel_clock(run_dir: Path) -> float:
    """
    Kernel events are timestamped with a monotonic clock (nanoseconds
    since some local reference point), not wall-clock time, so they must
    be converted to unix time before they can be merged with PostgreSQL's
    wall-clock timestamps.

    `time_sync.json`'s server_boot_unix_time is not reliable for this
    conversion in this dataset -- on these runs it puts kernel events
    ~1980s outside the run's own logging window. Both the kernel and
    postgres logs independently stamp a LOGGING_START marker with the
    *actual* wall-clock time the run began, and the two agree with each
    other, so we calibrate off that marker instead: offset = (wall time
    of LOGGING_START) - (monotonic time of the first captured kernel
    event). Falls back to time_sync.json only if no marker is present.
    """
    start_marker: Optional[float] = None
    first_raw_ns: Optional[int] = None

    for rec in _iter_raw_lines(run_dir / "kernel_events.json"):
        if rec.get("marker") == "LOGGING_START":
            start_marker = float(rec["timestamp"])
        elif "pid" in rec and first_raw_ns is None:
            first_raw_ns = rec["timestamp"]
        if start_marker is not None and first_raw_ns is not None:
            break

    if start_marker is not None and first_raw_ns is not None:
        return start_marker - first_raw_ns / 1e9

    # Fallback: trust time_sync.json's recorded boot time.
    with (run_dir / "time_sync.json").open("r") as f:
        return float(json.load(f)["server_boot_unix_time"])


def iter_log_stream(run_dir: Path) -> Iterator[LogEvent]:
    """
    Replay one run's kernel + postgres logs as a single, time-ordered
    stream of LogEvent records -- as if a logger were emitting them live.
    """
    clock_offset = _calibrate_kernel_clock(run_dir)
    events = []

    for rec in _iter_raw_lines(run_dir / "kernel_events.json"):
        if "marker" in rec:
            continue  # LOGGING_START / LOGGING_STOP framing line, not an event
        ts = rec["timestamp"] / 1e9 + clock_offset  # monotonic ns -> unix seconds
        events.append(LogEvent(source="kernel", timestamp=ts, pid=rec["pid"], raw=rec))

    for rec in _iter_raw_lines(run_dir / "postgres_events.json"):
        if "marker" in rec:
            continue
        ts = float(rec["timestamp"])
        events.append(LogEvent(source="postgres", timestamp=ts, pid=rec["backend_pid"], raw=rec))

    events.sort(key=lambda e: e.timestamp)
    yield from events


# --------------------------------------------------------------------------
# Algorithm 1: Session-Anchored Correlation
# --------------------------------------------------------------------------

class SessionAnchoredCorrelator:
    """
    Stateful implementation of Algorithm 1. Feed it one LogEvent at a time
    (via process_event) and it will tag each event with its session key,
    or drop it as unrelated OS background noise.

    State
    -----
    active_sessions : dict[pid -> start_time]
        Mirrors the algorithm's ActiveSessions table of currently running
        DB backend processes.
    parent_map : dict[pid -> ppid]
        Learned on the fly from kernel events, since offline replay has no
        live /proc to query. GetParentPid(pid) is backed by this map.
    """

    def __init__(self, d_max: int = D_MAX):
        self.d_max = d_max
        self.active_sessions: Dict[int, float] = {}
        self.parent_map: Dict[int, int] = {}

    # ---- ActiveSessions bookkeeping -------------------------------------

    def track_new_session(self, pid: int, start_time: float) -> None:
        """TrackNewSession(pid, start_time): register a new DB session."""
        self.active_sessions[pid] = start_time

    def end_session(self, pid: int) -> None:
        """Not in the paper pseudocode, but needed to keep ActiveSessions
        accurate over a long-running stream once a backend disconnects."""
        self.active_sessions.pop(pid, None)

    # ---- process-tree lookups --------------------------------------------

    def observe_process(self, pid: int, ppid: int) -> None:
        """Learn a pid->ppid edge from a kernel log line, so
        TraceToParentSession can walk it later."""
        if pid and ppid:
            self.parent_map[pid] = ppid

    def get_parent_pid(self, pid: int) -> Optional[int]:
        """GetParentPid(pid)."""
        return self.parent_map.get(pid)

    # ---- Algorithm 1, lines 16-27 -----------------------------------------

    def trace_to_parent_session(self, pid: int) -> Optional[int]:
        """
        function TraceToParentSession(pid)
            current_pid <- pid
            depth <- 0
            while current_pid != 0 and depth < D_max do
                if current_pid exists in ActiveSessions then
                    return current_pid
                current_pid <- GetParentPid(current_pid)
                depth <- depth + 1
            return null
        """
        current_pid = pid
        depth = 0
        while current_pid and current_pid != 0 and depth < self.d_max:
            if current_pid in self.active_sessions:
                return current_pid
            current_pid = self.get_parent_pid(current_pid)
            depth += 1
        return None

    # ---- Algorithm 1, lines 4-15 -------------------------------------------

    def link_event_to_session(self, e: LogEvent) -> Optional[tuple[int, LogEvent]]:
        """
        procedure LinkEventToSession(e)
            if e is a PostgreSQL event then
                session_key <- e.pid          # DB events come directly from the session
            else
                session_key <- TraceToParentSession(e.pid)  # OS events may come from child processes
            if session_key is found then
                return (session_key, e)
            else
                return null                    # ignore standard OS background noise
        """
        if e.is_postgres:
            session_key = e.pid
        else:
            session_key = self.trace_to_parent_session(e.pid)

        if session_key is not None:
            return (session_key, e)
        return None

    # ---- top-level driver for one incoming log line ----------------------

    def process_event(self, e: LogEvent) -> Optional[tuple[int, LogEvent]]:
        """
        Full per-event pipeline: update state from the event, then attempt
        correlation. This is the function a live log tailer would call for
        every line as it arrives.
        """
        if e.is_postgres:
            session_id = e.raw.get("session_id", e.pid)
            if session_id not in self.active_sessions:
                self.track_new_session(session_id, e.raw.get("session_start_time", e.timestamp))
        else:
            self.observe_process(e.pid, e.raw.get("ppid", 0))

        return self.link_event_to_session(e)


# --------------------------------------------------------------------------
# Run-level driver (offline replay over the dataset layout above)
# --------------------------------------------------------------------------

def load_labels(run_dir: Path) -> Dict[Optional[int], str]:
    """session_id -> threat label, from labels.csv."""
    labels: Dict[Optional[int], str] = {}
    labels_path = run_dir / "labels.csv"
    if not labels_path.exists():
        return labels
    with labels_path.open("r", newline="") as f:
        for row in csv.DictReader(f):
            sid_raw = row["session_id"].strip()
            sid = int(sid_raw) if sid_raw else None
            labels[sid] = row["label"]
    return labels


def run_correlation(run_dir: Path, d_max: int = D_MAX) -> list[tuple[int, LogEvent]]:
    """
    Replay one run directory's logs through Algorithm 1 and return every
    (session_key, event) pair it managed to correlate.
    """
    correlator = SessionAnchoredCorrelator(d_max=d_max)
    correlated: list[tuple[int, LogEvent]] = []

    for event in iter_log_stream(run_dir):
        result = correlator.process_event(event)
        if result is not None:
            correlated.append(result)

    return correlated


def summarize_run(run_dir: Path) -> None:
    correlated = run_correlation(run_dir)
    labels = load_labels(run_dir)

    by_session: Dict[int, int] = {}
    for session_key, _event in correlated:
        by_session[session_key] = by_session.get(session_key, 0) + 1

    kernel_linked = sum(1 for sk, e in correlated if not e.is_postgres)
    pg_linked = sum(1 for sk, e in correlated if e.is_postgres)

    print(f"\n{run_dir.parent.name}/{run_dir.name}")
    print(f"  sessions correlated : {len(by_session)}")
    print(f"  postgres events linked : {pg_linked}")
    print(f"  kernel events linked to a session : {kernel_linked}")
    if labels:
        flagged = {sk for sk in by_session if labels.get(sk, "Normal") != "Normal"}
        print(f"  sessions with a non-Normal label : {len(flagged)}")


if __name__ == "__main__":
    for dataset_root in (DATASET_DEV, DATASET_TEST):
        if not dataset_root.exists():
            continue
        for run_dir in sorted(dataset_root.glob("run_*")):
            summarize_run(run_dir)