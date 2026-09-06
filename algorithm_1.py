"""
Algorithm 1: Session-Anchored Correlation (SAC)
================================================

Pure functions only -- no driver loop, no output queue. main.py owns the
event loop and the queue(s) feeding Algorithm 2; this module just:

  1. reads + time-calibrates the kernel and postgres log files into one
     merged, sorted list of LogEvent (load_master_log) -- stands in for
     a live tailer's feed during offline development,
  2. given one event at a time plus Algorithm 1's own running state,
     returns the session_key(s) resolved by that event
     (process_event_with_retry).

Usage from main.py:

    from algorithm_1 import load_master_log, process_event_with_retry
    from collections import deque

    active_sessions, parent_map, pending = {}, {}, deque()
    master_log = load_master_log(run_dir)          # or a live tailer, later

    for event in master_log:
        for session_key, event_id in process_event_with_retry(
            event, active_sessions, parent_map, pending
        ):
            alg2_queue.put((session_key, event_id))   # main.py's queue, not ours
"""

from __future__ import annotations

import csv
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# Expected repo layout when running this file directly:
#
#   algorithm_1.py
#   dataset_dev/  run_1/  run_2/  run_3/
#   dataset_test/ run_1/  run_2/  run_3/
#   output/                          <- created by this script
#       run_1_event_table.json
#       run_1_session_correlation.csv
#       ...
PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_DEV = PROJECT_ROOT / "dataset_dev"
DATASET_TEST = PROJECT_ROOT / "dataset_test"
OUTPUT_DIR = PROJECT_ROOT / "output"

D_MAX = 8  # max ancestor hops when tracing a kernel event up to its session

# Kernel events that fail to correlate on first attempt are held here, not
# discarded -- a backend's own pre-query OS activity (fork, connect, auth)
# regularly happens *before* its first Postgres event registers the
# session. Measured gap across the CASCE dataset runs: 0.4s-9s; padded
# generously here.
PENDING_RETRY_WINDOW_SECONDS = 20.0


# --------------------------------------------------------------------------
# Log record model -- one shape for both kernel and postgres events
# --------------------------------------------------------------------------

@dataclass
class LogEvent:
    event_id: int                # stable handle Alg 2 can use to look up this event
    source: str                  # "kernel" | "postgres"
    timestamp: float             # unix epoch seconds, post-calibration
    pid: int                     # process id (kernel) / backend pid (postgres)
    raw: Dict[str, Any]          # original decoded record

    @property
    def is_postgres(self) -> bool:
        return self.source == "postgres"


# --------------------------------------------------------------------------
# Log reading + time calibration
# --------------------------------------------------------------------------

def _iter_raw_lines(path: Path):
    if not path.exists():
        return
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _calibrate_kernel_clock(run_dir: Path, kernel_file: str) -> float:
    """
    Kernel events are timestamped with a monotonic clock (ns since some
    local reference point), not wall-clock time. Both logs independently
    stamp a LOGGING_START marker whose own timestamp IS wall-clock time,
    at (approximately) the same instant as the first captured kernel
    event, so:

        offset = (wall time of LOGGING_START) - (monotonic time of first event)

    Falls back to time_sync.json's server_boot_unix_time only if no
    marker is present -- that field has been confirmed unreliable on this
    dataset otherwise (puts events ~1980s off).
    """
    start_marker: Optional[float] = None
    first_raw_ns: Optional[int] = None

    for rec in _iter_raw_lines(run_dir / kernel_file):
        if rec.get("marker") == "LOGGING_START":
            start_marker = float(rec["timestamp"])
        elif "pid" in rec and first_raw_ns is None:
            first_raw_ns = rec["timestamp"]
        if start_marker is not None and first_raw_ns is not None:
            break

    if start_marker is not None and first_raw_ns is not None:
        return start_marker - first_raw_ns / 1e9

    with (run_dir / "time_sync.json").open("r") as f:
        return float(json.load(f)["server_boot_unix_time"])


def load_master_log(run_dir: Path, kernel_file: str = "kernel_events.json") -> list[LogEvent]:
    """
    Read both logs for one run, calibrate the kernel clock, tag each
    record with its source, and return one list sorted by timestamp.
    event_id = index into this list. Reads the RAW kernel log by default
    (not kernel_events.clean.json) -- production will be tailing raw,
    uncleaned eBPF output, so developing against raw is the honest test.
    """
    clock_offset = _calibrate_kernel_clock(run_dir, kernel_file)
    events: list[LogEvent] = []

    for rec in _iter_raw_lines(run_dir / kernel_file):
        if "marker" in rec:
            continue
        ts = rec["timestamp"] / 1e9 + clock_offset
        events.append(LogEvent(event_id=-1, source="kernel", timestamp=ts, pid=rec["pid"], raw=rec))

    for rec in _iter_raw_lines(run_dir / "postgres_events.json"):
        if "marker" in rec:
            continue
        ts = float(rec["timestamp"])
        events.append(LogEvent(event_id=-1, source="postgres", timestamp=ts, pid=rec["backend_pid"], raw=rec))

    events.sort(key=lambda e: e.timestamp)
    for i, e in enumerate(events):
        e.event_id = i

    return events


# --------------------------------------------------------------------------
# Algorithm 1 proper
# --------------------------------------------------------------------------

def _trace_to_parent_session(
    pid: int,
    active_sessions: Dict[int, float],
    parent_map: Dict[int, int],
    d_max: int = D_MAX,
) -> Optional[int]:
    """function TraceToParentSession(pid) -- paper Algorithm 1, lines 16-27."""
    current_pid = pid
    depth = 0
    while current_pid and current_pid != 0 and depth < d_max:
        if current_pid in active_sessions:
            return current_pid
        current_pid = parent_map.get(current_pid)
        depth += 1
    return None


def process_event(
    event: LogEvent,
    active_sessions: Dict[int, float],
    parent_map: Dict[int, int],
) -> Optional[int]:
    """
    procedure LinkEventToSession(e) -- paper Algorithm 1, lines 4-15,
    fused with the ActiveSessions bookkeeping (TrackNewSession /
    observe_process) a live tailer needs to do per-event anyway.

    Returns the session_key, or None if unresolved *right now* -- for a
    kernel event this does not necessarily mean noise; see
    process_event_with_retry, which is what main.py should actually call.
    """
    if event.is_postgres:
        session_id = event.raw.get("session_id", event.pid)
        if session_id not in active_sessions:
            active_sessions[session_id] = event.raw.get("session_start_time", event.timestamp)
        return session_id  # DB events come directly from the session -- no tracing needed
    else:
        ppid = event.raw.get("ppid", 0)
        if event.pid and ppid:
            parent_map[event.pid] = ppid
        return _trace_to_parent_session(event.pid, active_sessions, parent_map)


def process_event_with_retry(
    event: LogEvent,
    active_sessions: Dict[int, float],
    parent_map: Dict[int, int],
    pending: deque[LogEvent],
) -> list[tuple[int, int]]:
    """
    The function main.py should call per incoming event. Never silently
    drops a kernel event on first failure -- holds it in `pending` and
    retries whenever a new session registers, since a backend's own
    pre-query OS activity routinely arrives before its first Postgres
    event does (see PENDING_RETRY_WINDOW_SECONDS).

    Returns a list of (session_key, event_id) pairs resolved by this
    call -- usually 0 or 1, but can be more when registering a new
    session unlocks several previously-pending kernel events at once.
    main.py is responsible for putting these onto whatever queue/channel
    feeds Algorithm 2.
    """
    resolved: list[tuple[int, int]] = []

    session_key = process_event(event, active_sessions, parent_map)
    if session_key is not None:
        resolved.append((session_key, event.event_id))
    elif not event.is_postgres:
        pending.append(event)  # genuinely unresolved kernel event -- hold, don't drop yet

    if event.is_postgres:
        # A new session may have just registered -- sweep pending kernel
        # events and retry them now that active_sessions/parent_map have
        # more information.
        still_pending: deque[LogEvent] = deque()
        for pev in pending:
            if event.timestamp - pev.timestamp > PENDING_RETRY_WINDOW_SECONDS:
                continue  # expired -- genuinely unrelated OS background noise
            retry_key = _trace_to_parent_session(pev.pid, active_sessions, parent_map)
            if retry_key is not None:
                resolved.append((retry_key, pev.event_id))
            else:
                still_pending.append(pev)
        pending.clear()
        pending.extend(still_pending)

    return resolved


# --------------------------------------------------------------------------
# Standalone runner -- for developing/inspecting Algorithm 1 on its own.
# main.py should NOT import anything below this point; it owns its own
# event loop and queue, as discussed. This is just so you can run
#     python3 algorithm_1.py
# and see what Algorithm 1 produces for each run, saved to disk.
# --------------------------------------------------------------------------

def run_one(run_dir: Path) -> tuple[list[LogEvent], list[tuple[int, int]]]:
    """Replay one run directory through Algorithm 1 top to bottom.
    Returns (master_log, correlated) -- correlated is every
    (session_key, event_id) pair Algorithm 1 resolved, in the order
    resolved (not necessarily the same order as master_log, since a
    kernel event can resolve late via the retry buffer)."""
    active_sessions: Dict[int, float] = {}
    parent_map: Dict[int, int] = {}
    pending: deque[LogEvent] = deque()

    master_log = load_master_log(run_dir)
    correlated: list[tuple[int, int]] = []
    for event in master_log:
        correlated.extend(process_event_with_retry(event, active_sessions, parent_map, pending))

    return master_log, correlated


def save_run_output(run_name: str, master_log: list[LogEvent], correlated: list[tuple[int, int]], output_dir: Path) -> None:
    """Writes two files per run:
      {run_name}_event_table.json         -- lookup table for the event_ids
                                              referenced in the correlation
                                              CSV below. Only includes events
                                              Algorithm 1 actually attributed
                                              to a session -- background OS
                                              noise that never resolved is
                                              excluded, since nothing will
                                              ever look it up by event_id.
      {run_name}_session_correlation.csv  -- (session_key, event_id) pairs Algorithm 1 resolved
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    referenced_ids = {eid for _sk, eid in correlated}
    lookup_events = sorted((e for e in master_log if e.event_id in referenced_ids), key=lambda e: e.event_id)

    event_table_path = output_dir / f"{run_name}_event_table.json"
    with event_table_path.open("w") as f:
        json.dump(
            [
                {"event_id": e.event_id, "source": e.source, "timestamp": e.timestamp, "pid": e.pid, "raw": e.raw}
                for e in lookup_events
            ],
            f,
            indent=2,
        )

    correlation_path = output_dir / f"{run_name}_session_correlation.csv"
    with correlation_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["session_key", "event_id"])
        writer.writerows(correlated)

    print(f"  wrote {event_table_path.name}  ({len(lookup_events)} events, {len(master_log)} read total)")
    print(f"  wrote {correlation_path.name}  ({len(correlated)} correlated pairs)")


if __name__ == "__main__":
    run_dirs = sorted(DATASET_DEV.glob("run_*")) + sorted(DATASET_TEST.glob("run_*"))

    if not run_dirs:
        print(f"No run_* directories found under {DATASET_DEV} or {DATASET_TEST}")
    else:
        for run_dir in run_dirs:
            run_name = f"{run_dir.parent.name}_{run_dir.name}"  # e.g. dataset_dev_run_1
            print(f"\n{run_name}")

            master_log, correlated = run_one(run_dir)

            kernel_total = sum(1 for e in master_log if not e.is_postgres)
            pg_total = sum(1 for e in master_log if e.is_postgres)
            kernel_linked = sum(1 for sk, eid in correlated if not master_log[eid].is_postgres)
            pg_linked = sum(1 for sk, eid in correlated if master_log[eid].is_postgres)
            sessions_found = len({sk for sk, _ in correlated})

            print(f"  postgres events linked : {pg_linked}/{pg_total}")
            print(f"  kernel events linked   : {kernel_linked}/{kernel_total}")
            print(f"  distinct sessions found: {sessions_found}")

            save_run_output(run_name, master_log, correlated, OUTPUT_DIR)