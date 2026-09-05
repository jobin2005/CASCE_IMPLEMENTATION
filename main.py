"""
main.py
=======

Usage:
    python3 main.py                  # run every dataset_dev/dataset_test run_*
    python3 main.py path/to/run_dir  # run a single run directory
"""

from __future__ import annotations

import sys
from collections import deque
from pathlib import Path
from typing import Dict, List, Tuple

from algorithm_1 import LogEvent, load_master_log, process_event_with_retry

PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_DEV = PROJECT_ROOT / "dataset_dev"
DATASET_TEST = PROJECT_ROOT / "dataset_test"


def run_algorithm_1(run_dir: Path) -> Tuple[List[LogEvent], List[Tuple[int, int]]]:
    """
    Feed one run directory's merged log through Algorithm 1, event by
    event, exactly the way a live tailer would in production.

    Returns:
        master_log : every LogEvent (kernel + postgres), sorted by time
        alg2_queue : the (session_key, event_id) pairs Algorithm 1
                     resolved, in the order resolved -- this is what
                     would be handed off to Algorithm 2.
    """
    active_sessions: Dict[int, float] = {}
    parent_map: Dict[int, int] = {}
    pending: deque[LogEvent] = deque()

    master_log = load_master_log(run_dir)
    alg2_queue: List[Tuple[int, int]] = []

    for event in master_log:
        for session_key, event_id in process_event_with_retry(
            event, active_sessions, parent_map, pending
        ):
            alg2_queue.append((session_key, event_id))

    return master_log, alg2_queue


def summarize(run_name: str, master_log: List[LogEvent], alg2_queue: List[Tuple[int, int]]) -> None:
    kernel_total = sum(1 for e in master_log if not e.is_postgres)
    pg_total = sum(1 for e in master_log if e.is_postgres)
    kernel_linked = sum(1 for sk, eid in alg2_queue if not master_log[eid].is_postgres)
    pg_linked = sum(1 for sk, eid in alg2_queue if master_log[eid].is_postgres)
    sessions_found = len({sk for sk, _ in alg2_queue})

    print(f"\n{run_name}")
    print(f"  total events           : {len(master_log)} (kernel={kernel_total}, postgres={pg_total})")
    print(f"  postgres events linked : {pg_linked}/{pg_total}")
    print(f"  kernel events linked   : {kernel_linked}/{kernel_total}")
    print(f"  distinct sessions found: {sessions_found}")


def main() -> None:
    if len(sys.argv) > 1:
        run_dirs = [Path(sys.argv[1]).resolve()]
    else:
        run_dirs = sorted(DATASET_DEV.glob("run_*")) + sorted(DATASET_TEST.glob("run_*"))

    if not run_dirs:
        print(f"No run_* directories found under {DATASET_DEV} or {DATASET_TEST}")
        return

    for run_dir in run_dirs:
        run_name = run_dir.name if run_dir.parent in (DATASET_DEV, DATASET_TEST) else run_dir.name
        if run_dir.parent.name in ("dataset_dev", "dataset_test"):
            run_name = f"{run_dir.parent.name}_{run_dir.name}"

        master_log, alg2_queue = run_algorithm_1(run_dir)
        summarize(run_name, master_log, alg2_queue)

        # This is the point where main.py would normally forward
        # `alg2_queue` on to Algorithm 2. Since Algorithm 2 isn't
        # incorporated here, we just report what Algorithm 1 produced.


if __name__ == "__main__":
    main()