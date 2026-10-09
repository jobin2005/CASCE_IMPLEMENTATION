#!/usr/bin/env python3
"""
CASCE real-time detection daemon.

Follows the live postgres_events.json / kernel_events.json written by
workload_simulation/logger.sh and scores every database session with the SAME
code path the offline pipeline uses (main.py -> algorithm_4_hybrid.py):

  Algorithm 1  algorithm_1.process_event_with_retry   (events in timestamp order)
  Algorithm 2  algorithm2.process_event                (session events in timestamp order)
  Algorithm 3  algorithm_3_abstract.abstract_session_graph + main.sanitize_for_graphml
  GraphML      write + read back, exactly the representation the GAT was trained on
  Algorithm 4  algorithm_4_hybrid.detect with the trained casce_gat.pt

When a session is scored
  - every --rescore-every seconds while it is running, if it received new events
    since its last score (early alerting; 0 disables), and
  - once it has ended (final score): when the collector's SESSION_END marker for
    its backend arrives, or -- fallback -- after --idle-timeout seconds without
    events. After a SESSION_END the session is evicted, so a reused pid starts
    a new session.

Outputs (in --out-dir)
  alerts.jsonl          first time each session's risk reaches theta_A, with latency
  session_scores.jsonl  final score per session (last line per session wins)
  timings.jsonl         per-scoring stage timings in ms (for the overhead experiments)

Ground-truth labels are never read here; evaluation is a separate step.

Usage
  live:    python3 realtime_daemon.py --log-dir ~/Desktop/Database/CASCE_DATASET
  replay:  python3 realtime_daemon.py --replay --log-dir live_runs/smoke_002 --out-dir /tmp/x
"""
from __future__ import annotations

import argparse
import copy
import io
import json
import os
import signal
import sys
import time
from collections import deque
from pathlib import Path

import networkx as nx

import algorithm_1
import algorithm2
import algorithm_3_abstract
import algorithm_4_hybrid
from main import sanitize_for_graphml


# --------------------------------------------------------------------------
# Log following
# --------------------------------------------------------------------------

class JsonlFollower:
    """Yields complete JSON lines appended to a file; tolerates the file not
    existing yet, partial trailing lines, and the file being recreated."""

    def __init__(self, path: Path):
        self.path = path
        self.f = None
        self.inode = None
        self.partial = ""

    def _open(self):
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        if self.f is None or st.st_ino != self.inode or st.st_size < self.f.tell():
            if self.f:
                self.f.close()
            self.f = open(self.path, "r")
            self.inode = st.st_ino
            self.partial = ""
        return True

    def read_new(self):
        if not self._open():
            return []
        out = []
        chunk = self.f.read()
        if not chunk:
            return out
        data = self.partial + chunk
        lines = data.split("\n")
        self.partial = lines.pop()  # "" if data ended with a newline
        for line in lines:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"[daemon] skipping malformed line in {self.path.name}: {line[:80]}",
                          file=sys.stderr)
        return out


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class Session:
    __slots__ = ("events", "last_event_wall", "last_event_ts", "dirty", "alerted", "final", "above")

    def __init__(self):
        self.events = []            # attributed events, as loader.load_attributed_events builds them
        self.last_event_wall = 0.0  # wall clock when the daemon last received an event for it
        self.last_event_ts = 0.0    # event time of its newest event
        self.dirty = False          # new events since last scoring
        self.alerted = False
        self.final = False
        self.above = 0              # consecutive scorings with risk >= theta_A


class Engine:
    def __init__(self, model, theta_a, theta_r, out_dir: Path, templates, confirm=1):
        self.confirm = max(1, confirm)  # alert after this many consecutive scorings >= theta_A
        self.model = model
        self.theta_a = theta_a
        self.theta_r = theta_r
        self.templates = templates
        # Algorithm 1 state (exactly what algorithm_1.run_one keeps)
        self.active_sessions = {}
        self.parent_map = {}
        self.pending = deque()
        self.next_event_id = 0
        self.kernel_clock_offset = None
        self.awaiting_anchor = False
        self.by_id = {}              # event_id -> LogEvent, while pending in Algorithm 1
        self.ended = {}              # backend pid -> wall time of its SESSION_END marker
        self.evicted = {}            # backend pid -> SESSION_END time, after its final score
        self.sessions: dict[int, Session] = {}
        out_dir.mkdir(parents=True, exist_ok=True)
        self.alerts_f = open(out_dir / "alerts.jsonl", "a", buffering=1)
        self.scores_f = open(out_dir / "session_scores.jsonl", "a", buffering=1)
        self.timings_f = open(out_dir / "timings.jsonl", "a", buffering=1)

    # -- ingestion: raw records -> LogEvents (same as algorithm_1.load_master_log) --
    def to_log_events(self, records, source):
        out = []
        for rec in records:
            if "marker" in rec:
                if source == "kernel" and rec["marker"] == "LOGGING_START":
                    self.awaiting_anchor = True
                    self._start_marker = float(rec["timestamp"])
                elif source == "kernel" and rec["marker"] == "SESSION_END":
                    self.ended[rec["backend_pid"]] = float(rec["timestamp"])
                continue
            if source == "kernel":
                if self.awaiting_anchor and "pid" in rec:
                    # algorithm_1._calibrate_kernel_clock: marker wall time - first event's monotonic ns
                    self.kernel_clock_offset = self._start_marker - rec["timestamp"] / 1e9
                    self.awaiting_anchor = False
                if self.kernel_clock_offset is None:
                    continue  # cannot place it in time; logger always writes the anchor first
                ts = rec["timestamp"] / 1e9 + self.kernel_clock_offset
                out.append(algorithm_1.LogEvent(-1, "kernel", ts, rec["pid"], rec))
            else:
                out.append(algorithm_1.LogEvent(-1, "postgres", float(rec["timestamp"]),
                                                rec["backend_pid"], rec))
        return out

    # -- Algorithm 1 --------------------------------------------------------
    def correlate(self, events, wall_now):
        """events must be in timestamp order (the reorder buffer guarantees it)."""
        for ev in events:
            ev.event_id = self.next_event_id
            self.next_event_id += 1
            self.by_id[ev.event_id] = ev
            for session_key, eid in algorithm_1.process_event_with_retry(
                    ev, self.active_sessions, self.parent_map, self.pending):
                self._attach(session_key, self.by_id[eid], wall_now)
        # keep only events still waiting in Algorithm 1's retry buffer
        live_pending = {p.event_id for p in self.pending}
        for eid in [e for e in self.by_id if e not in live_pending]:
            del self.by_id[eid]

    def _attach(self, session_key, ev, wall_now):
        # identical to loader.load_attributed_events
        merged = {**ev.raw, "session_key": session_key, "event_id": ev.event_id,
                  "source": ev.source, "timestamp_unix": ev.timestamp}
        if session_key in self.evicted and ev.timestamp <= self.evicted[session_key] + 5:
            # an event of a session that was already finalised: its SESSION_END
            # came too early relative to this event (clock problem) -- say so
            print(f"[daemon] WARNING: event at {ev.timestamp:.3f} for session {session_key}, "
                  f"which already ended at {self.evicted[session_key]:.3f}; its final score "
                  f"missed this event", file=sys.stderr, flush=True)
        s = self.sessions.setdefault(session_key, Session())
        s.events.append(merged)
        s.last_event_wall = wall_now
        s.last_event_ts = max(s.last_event_ts, ev.timestamp)
        s.dirty = True
        s.final = False

    # -- Algorithms 2-4 -------------------------------------------------------
    def score(self, session_key, final):
        s = self.sessions[session_key]
        t0 = time.perf_counter()
        # Algorithm 2 over this session's events in timestamp order (loader sorts globally;
        # per session that is the same order). Copies: process_event mutates its input.
        algorithm2.ORPHAN_LOG.clear()
        algorithm2.PARSE_ERROR_LOG.clear()
        graphs = {}
        for e in sorted(s.events, key=lambda e: e["timestamp_unix"]):
            algorithm2.process_event(session_key, copy.deepcopy(e), graphs)
        G_s = graphs[session_key]
        t1 = time.perf_counter()
        G_enriched, behaviors = algorithm_3_abstract.abstract_session_graph(G_s, self.templates)
        G_enriched = sanitize_for_graphml(G_enriched)
        t2 = time.perf_counter()
        buf = io.BytesIO()
        nx.write_graphml(G_enriched, buf)
        buf.seek(0)
        G_model = nx.read_graphml(buf)
        t3 = time.perf_counter()
        a = algorithm_4_hybrid.detect(G_model, self.model, session_id=session_key,
                                      theta_a=self.theta_a, theta_r=self.theta_r)
        t4 = time.perf_counter()
        wall = time.time()
        s.dirty = False

        timing = {"session_id": session_key, "final": final, "n_events": len(s.events),
                  "n_nodes": G_model.number_of_nodes(), "alg2_ms": (t1 - t0) * 1e3,
                  "alg3_ms": (t2 - t1) * 1e3, "graphml_ms": (t3 - t2) * 1e3,
                  "alg4_ms": (t4 - t3) * 1e3, "total_ms": (t4 - t0) * 1e3}
        self.timings_f.write(json.dumps(timing) + "\n")

        result = {"session_id": session_key, "risk": a["risk"], "rule_score": a["rule_score"],
                  "gat_score": a["gat_score"], "scenario": a["scenario"], "status": a["status"],
                  "theta_a": self.theta_a, "n_events": len(s.events),
                  "behaviors": [b["label"] for b in behaviors],
                  "last_event_ts": s.last_event_ts, "scored_at": wall}
        s.above = s.above + 1 if a["status"] != "benign" else 0
        # partial (running) sessions must stay above theta_A for --confirm consecutive
        # scorings before alerting; a final score above theta_A always alerts
        if a["status"] != "benign" and not s.alerted and (final or s.above >= self.confirm):
            s.alerted = True
            alert = {**result, "message": a.get("message", ""),
                     "detection_latency_s": wall - s.last_event_ts}
            self.alerts_f.write(json.dumps(alert, default=str) + "\n")
            print(f"[ALERT] session {session_key}: risk {a['risk']:.3f} "
                  f"(rule {a['rule_score']:.2f}, gat {a['gat_score']:.2f}) {a['scenario'] or ''}",
                  flush=True)
        if final:
            s.final = True
            self.scores_f.write(json.dumps(result, default=str) + "\n")
            print(f"[score] session {session_key}: risk {a['risk']:.3f} -> {a['status']} "
                  f"({len(s.events)} events, {timing['total_ms']:.1f} ms)", flush=True)
        return result

    def scoring_pass(self, wall_now, idle_timeout, rescore_every, last_rescore, settle):
        # sessions whose backend exited: final score once their last events have
        # passed the reorder window, then evict
        for pid, end_ts in list(self.ended.items()):
            if wall_now < end_ts + settle:
                continue
            del self.ended[pid]
            s = self.sessions.get(pid)
            if s is not None and not s.final:
                self.score(pid, final=True)
            self.sessions.pop(pid, None)
            self.active_sessions.pop(pid, None)
            self.evicted[pid] = end_ts
        # evicted only serves the late-event warning (events up to 5 s after
        # SESSION_END); without trimming it grows by one entry per session forever
        if len(self.evicted) > 10000:
            horizon = max(self.evicted.values()) - 600
            self.evicted = {p: t for p, t in self.evicted.items() if t >= horizon}
        for sk, s in list(self.sessions.items()):
            if s.final:
                continue
            if wall_now - s.last_event_wall >= idle_timeout:
                self.score(sk, final=True)
            elif rescore_every > 0 and s.dirty and wall_now - last_rescore >= rescore_every:
                self.score(sk, final=False)

    def finish(self):
        for sk, s in self.sessions.items():
            if not s.final:
                self.score(sk, final=True)
        for f in (self.alerts_f, self.scores_f, self.timings_f):
            f.close()


# --------------------------------------------------------------------------
# Main loops
# --------------------------------------------------------------------------

def run_replay(engine, log_dir, rescore_every=0.0):
    """Offline replay of a finished capture: same as algorithm_1.run_one + main.py.
    With rescore_every > 0, running sessions are also rescored every that many
    seconds of event time, like the live daemon does -- so alerts.jsonl gives
    the real-time view for a capture (e.g. to evaluate a new model on old runs)."""
    master_log = algorithm_1.load_master_log(log_dir)
    if rescore_every <= 0:
        engine.correlate(master_log, wall_now=0.0)
    else:
        next_tick = master_log[0].timestamp + rescore_every if master_log else 0.0
        for ev in master_log:
            while ev.timestamp >= next_tick:
                for sk, s in list(engine.sessions.items()):
                    if s.dirty and not s.final:
                        engine.score(sk, final=False)
                next_tick += rescore_every
            engine.correlate([ev], wall_now=ev.timestamp)
    engine.finish()


def run_follow(engine, log_dir, args):
    pg = JsonlFollower(log_dir / "postgres_events.json")
    kern = JsonlFollower(log_dir / "kernel_events.json")
    buffer = []                      # LogEvents waiting for the reorder window
    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    last_rescore = 0.0
    print(f"[daemon] following {log_dir} (theta_A={args.theta_a}, rescore every {args.rescore_every}s, "
          f"idle fallback {args.idle_timeout}s, reorder {args.reorder_delay}s). Ctrl+C to stop.", flush=True)

    while not stop:
        buffer += engine.to_log_events(kern.read_new(), "kernel")
        buffer += engine.to_log_events(pg.read_new(), "postgres")
        now = time.time()
        # Release events older than the reorder window, in timestamp order, so
        # Algorithm 1 sees one time-ordered stream like load_master_log produces.
        cutoff = now - args.reorder_delay
        ready = sorted((e for e in buffer if e.timestamp <= cutoff), key=lambda e: e.timestamp)
        if ready:
            buffer = [e for e in buffer if e.timestamp > cutoff]
            engine.correlate(ready, wall_now=now)
        engine.scoring_pass(now, args.idle_timeout, args.rescore_every, last_rescore,
                            settle=args.reorder_delay + 0.5)
        if now - last_rescore >= args.rescore_every:
            last_rescore = now
        time.sleep(args.poll_interval)

    # drain whatever is left, then final scores for everything
    buffer += engine.to_log_events(kern.read_new(), "kernel")
    buffer += engine.to_log_events(pg.read_new(), "postgres")
    engine.correlate(sorted(buffer, key=lambda e: e.timestamp), wall_now=time.time())
    engine.finish()
    print("[daemon] stopped.", flush=True)


def main():
    ap = argparse.ArgumentParser(description="CASCE real-time detection daemon")
    ap.add_argument("--log-dir", type=Path, default=Path.home() / "Desktop/Database/CASCE_DATASET",
                    help="folder with postgres_events.json and kernel_events.json")
    ap.add_argument("--out-dir", type=Path, default=Path("realtime_out"))
    ap.add_argument("--model-path", default="casce_gat.pt")
    ap.add_argument("--theta-a", type=float, default=None,
                    help="alert threshold (default: the θ_A tuned on validation for --model-path)")
    ap.add_argument("--theta-r", type=float, default=algorithm_4_hybrid.THETA_R)
    ap.add_argument("--idle-timeout", type=float, default=60.0,
                    help="fallback: final score after this many seconds without events "
                         "(normally the SESSION_END marker finalises a session)")
    ap.add_argument("--rescore-every", type=float, default=2.0,
                    help="rescore running sessions with new events this often (early alerts; 0 = off)")
    ap.add_argument("--reorder-delay", type=float, default=1.0,
                    help="hold events this long so both logs merge in timestamp order")
    ap.add_argument("--poll-interval", type=float, default=0.05)
    ap.add_argument("--confirm", type=int, default=1,
                    help="alert on a running session only after this many consecutive scorings "
                         "at or above theta_A (1 = first one, the original behaviour); a session's "
                         "final score at or above theta_A always alerts")
    ap.add_argument("--threads", type=int, default=1,
                    help="torch CPU threads for scoring (graphs are tiny; the torch default of one "
                         "thread per core only competes with the database for CPU)")
    ap.add_argument("--replay", action="store_true", help="process a finished capture and exit")
    ap.add_argument("--replay-realtime", action="store_true",
                    help="with --replay: also rescore running sessions every --rescore-every "
                         "seconds of event time (fills alerts.jsonl like a live run)")
    args = ap.parse_args()

    args.theta_a = algorithm_4_hybrid.resolve_theta(args.theta_a, args.model_path)
    if algorithm_4_hybrid.TORCH_AVAILABLE and args.threads > 0:
        algorithm_4_hybrid.torch.set_num_threads(args.threads)
    model = algorithm_4_hybrid.load_model(args.model_path)
    if model is None:
        sys.exit("torch/torch_geometric not available -- run with the project .venv")
    engine = Engine(model, args.theta_a, args.theta_r, args.out_dir,
                    algorithm_3_abstract.initialize_templates(), confirm=args.confirm)
    if args.replay:
        run_replay(engine, args.log_dir, args.rescore_every if args.replay_realtime else 0.0)
    else:
        run_follow(engine, args.log_dir, args)


if __name__ == "__main__":
    main()
