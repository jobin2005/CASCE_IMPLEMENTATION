#!/usr/bin/env python3
"""
Execute synthetic scenario specs (datagen) for real against the live database.

Each spec session becomes one real Postgres session in casce_environment:
  - connects as the spec's role over TCP (like the corpus' network clients),
  - sends exactly the statements codegen would have emitted for it
    (codegen.event_list_for_session: role padding + events), with the same
    per-event timing (codegen.resolve_scenario_times: step gaps,
    delay_after_previous_seconds, concurrent_with),
  - COPY ... TO PROGRAM therefore spawns the real processes it describes.
Statements are sent with psql's \\g, so the query text is byte-identical to
the spec (no trailing semicolon). Waiting happens in this script, outside the
database, so it leaves no trace in the logs -- as in the synthetic corpus.

Ground truth: every session runs with
  PGAPPNAME=casce_label=<Benign|Malicious>:<key>
which the pg_telemetry hook records in session_labels.jsonl only. <key> maps
to (run, scenario, session, synthetic backend_pid) in live_manifest.jsonl.

Network: curl targets in the specs are made-up hostnames. Each is mapped in
the container's /etc/hosts to the spec's connects_to IP, and those IPs are
added to the container's loopback, so the connect() really happens and is
refused at once instead of hanging. (The port is the URL's real port; the
corpus sometimes recorded the spec's connects_to port instead.)

Optional background load: pgbench against casce_tpcb, one connection per
transaction (-C), labelled Benign:pgbench.

Usage (host, project .venv):
  python3 workload_simulation/run_live_scenarios.py --class benign --out-dir live_runs/4b
  python3 workload_simulation/run_live_scenarios.py --pgbench-only 600 --out-dir live_runs/4a
  python3 workload_simulation/run_live_scenarios.py --class benign --pgbench --out-dir live_runs/4c
  python3 workload_simulation/run_live_scenarios.py --check-sql      # validate schema/permissions only
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "datagen"))
import codegen  # noqa: E402  (same padding + timing code that built the corpus)

CONTAINER = "casce_environment"
DB = "casce_banking"
HOSTS_BEGIN, HOSTS_END = "# CASCE-BEGIN", "# CASCE-END"
STRIP_BLOCK = (f"awk '/{HOSTS_BEGIN}/{{skip=1}} !skip{{print}} /{HOSTS_END}/{{skip=0}}' /etc/hosts "
               f"> /tmp/casce_hosts && cat /tmp/casce_hosts > /etc/hosts")


def dexec(*args, input_text=None, env=None, check=True, capture=True):
    cmd = ["docker", "exec", "-i", "-u", "root"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [CONTAINER, *args]
    return subprocess.run(cmd, input=input_text, text=True, check=check,
                          capture_output=capture)


# --------------------------------------------------------------------------
# Specs -> planned sessions
# --------------------------------------------------------------------------

def load_plan(spec_globs, wanted_class, limit):
    plan = []
    for spec_path in sorted(p for g in spec_globs for p in glob.glob(g)):
        spec_path = Path(spec_path)
        run_dir = spec_path.parent.parent
        data = yaml.safe_load(spec_path.read_text())
        manifest = json.loads((run_dir / "expectation_manifest.json").read_text())
        man_sessions = manifest["scenarios"][data["scenario_id"]]["sessions"]
        sf = codegen.SpecFile(path=spec_path, filename=spec_path.name, data=data)
        times = codegen.resolve_scenario_times(sf, dt.date(2026, 1, 1))
        t0 = min(t[0] for t in times if t)
        sessions = []
        for sess, ev_times in zip(data["sessions"], times):
            cls = sess.get("class", data.get("default_class"))
            events = codegen.event_list_for_session(sess)
            sqls = [e.get("sql") or e.get(codegen.ANCHOR_KEY) for e in events]
            hosts = {}
            for e in sess.get("events") or []:
                if "sql" in e and e.get("connects_to"):
                    for h in re.findall(r"https?://([^/:'\s]+)", e["sql"]):
                        hosts[h] = e["connects_to"]["ip"]
            sessions.append({
                "session_label": sess["session_label"], "class": cls, "role": sess["role"],
                "sqls": sqls, "offsets": [t - t0 for t in ev_times], "hosts": hosts,
                "synthetic_backend_pid": man_sessions[sess["session_label"]]["backend_pid"],
            })
        if wanted_class != "all" and not any(s["class"] == wanted_class for s in sessions):
            continue
        if wanted_class != "all":
            sessions = [s for s in sessions if s["class"] == wanted_class]
            base = min(s["offsets"][0] for s in sessions)
            for s in sessions:
                s["offsets"] = [o - base for o in s["offsets"]]
        plan.append({"run": run_dir.name, "dataset": run_dir.parent.name,
                     "scenario_id": data["scenario_id"], "sessions": sessions})
    return plan[:limit] if limit else plan


# --------------------------------------------------------------------------
# Container network setup
# --------------------------------------------------------------------------

class HostsFile:
    """Keeps the CASCE block of the container's /etc/hosts in sync with the
    hostname -> IP mappings of the scenarios currently running."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}   # hostname -> (ip, refcount)

    def _write(self):
        # /etc/hosts is bind-mounted by Docker: rewrite it in place, never replace it
        block = "".join(f"{ip} {h}\n" for h, (ip, _n) in sorted(self.active.items()))
        dexec("bash", "-c", STRIP_BLOCK + f" && printf '%s\\n%s%s\\n' '{HOSTS_BEGIN}' "
              f"'{block}' '{HOSTS_END}' >> /etc/hosts")

    def try_acquire(self, hosts):
        with self.lock:
            if any(h in self.active and self.active[h][0] != ip for h, ip in hosts.items()):
                return False
            for h, ip in hosts.items():
                n = self.active.get(h, (ip, 0))[1]
                self.active[h] = (ip, n + 1)
            if hosts:
                self._write()
            return True

    def release(self, hosts):
        with self.lock:
            for h in hosts:
                ip, n = self.active[h]
                if n <= 1:
                    del self.active[h]
                else:
                    self.active[h] = (ip, n - 1)
            if hosts:
                self._write()

    def clear(self):
        with self.lock:
            self.active.clear()
            dexec("bash", "-c", STRIP_BLOCK)


def add_loopback_ips(ips):
    for ip in sorted(ips):
        dexec("bash", "-c", f"ip addr show dev lo | grep -q ' {ip}/32' || ip addr add {ip}/32 dev lo")


def remove_loopback_ips(ips):
    for ip in sorted(ips):
        dexec("bash", "-c", f"ip addr del {ip}/32 dev lo 2>/dev/null || true", check=False)


# --------------------------------------------------------------------------
# Running sessions
# --------------------------------------------------------------------------

def run_session(sess, key, scenario_start, log_rows, lock):
    label = "Benign" if sess["class"] == "benign" else "Malicious"
    proc = subprocess.Popen(
        ["docker", "exec", "-i", "-u", "root", "-e", f"PGAPPNAME=casce_label={label}:{key}",
         CONTAINER, "psql", "-X", "-q", "-h", "127.0.0.1", "-U", sess["role"], "-d", DB,
         "-o", "/dev/null"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    started = time.time()
    for sql, off in zip(sess["sqls"], sess["offsets"]):
        wait = scenario_start + off - time.time()
        if wait > 0:
            time.sleep(wait)
        proc.stdin.write(sql + "\n\\g\n")
        proc.stdin.flush()
    proc.stdin.close()
    err = proc.stderr.read()
    proc.wait()
    with lock:
        log_rows.append({"key": key, "label": label, "role": sess["role"],
                         "session_label": sess["session_label"],
                         "synthetic_backend_pid": sess["synthetic_backend_pid"],
                         "n_statements": len(sess["sqls"]), "started": started,
                         "ended": time.time(), "psql_exit": proc.returncode,
                         "errors": [l for l in err.splitlines() if l.strip()][:10]})


def run_scenario(sc, idx, hosts_file, log_rows, lock):
    hosts = {}
    for s in sc["sessions"]:
        hosts.update(s["hosts"])
    while not hosts_file.try_acquire(hosts):
        time.sleep(0.5)
    try:
        start = time.time() + 0.5
        threads = []
        for j, sess in enumerate(sc["sessions"]):
            key = f"s{idx:04d}_{j}"
            with lock:
                log_rows.append({"key": key, "planned": True, "dataset": sc["dataset"],
                                 "run": sc["run"], "scenario_id": sc["scenario_id"],
                                 "session_label": sess["session_label"], "class": sess["class"],
                                 "synthetic_backend_pid": sess["synthetic_backend_pid"]})
            t = threading.Thread(target=run_session, args=(sess, key, start, log_rows, lock))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    finally:
        hosts_file.release(hosts)


def start_pgbench(seconds, clients, rate):
    return subprocess.Popen(
        ["docker", "exec", "-u", "root", "-e", "PGAPPNAME=casce_label=Benign:pgbench", CONTAINER,
         "pgbench", "-h", "127.0.0.1", "-U", "postgres", "-n", "-C", "-c", str(clients),
         "-j", str(max(1, clients // 2)), "-R", str(rate), "-T", str(int(seconds)), "casce_tpcb"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def check_sql(plan):
    """EXPLAIN every distinct statement as its role (COPY: its inner query) --
    catches missing tables/columns/permissions without side effects.
    Run with logging stopped: EXPLAIN statements would otherwise be captured."""
    seen, bad = set(), 0
    for sc in plan:
        for s in sc["sessions"]:
            for sql in s["sqls"]:
                if (s["role"], sql) in seen:
                    continue
                seen.add((s["role"], sql))
                m = re.match(r"(?is)^\s*COPY\s*\((.*)\)\s*TO\s+PROGRAM", sql)
                target = m.group(1) if m else sql
                if not re.match(r"(?i)^\s*(SELECT|INSERT|UPDATE|DELETE)", target):
                    continue  # utility statement: cannot be EXPLAINed safely
                r = dexec("psql", "-X", "-q", "-h", "127.0.0.1", "-U", s["role"], "-d", DB,
                          "-c", "EXPLAIN " + target, check=False)
                if r.returncode != 0:
                    bad += 1
                    print(f"[FAIL] {s['role']}: {sql[:100]}\n       {r.stderr.strip()[:200]}")
    print(f"checked {len(seen)} statements, {bad} failed")
    return bad == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--specs", nargs="+", default=["dataset_test/run_*/specs/*.yaml"])
    ap.add_argument("--class", dest="wanted_class", default="benign",
                    choices=["benign", "malicious", "all"])
    ap.add_argument("--out-dir", type=Path, default=Path("live_runs/latest"))
    ap.add_argument("--parallel", type=int, default=4, help="scenarios running at the same time")
    ap.add_argument("--limit", type=int, default=0, help="only the first N scenarios (testing)")
    ap.add_argument("--pgbench", action="store_true", help="pgbench background load during the run")
    ap.add_argument("--pgbench-only", type=float, default=0, metavar="SECONDS",
                    help="run only pgbench for this many seconds (experiment 4a)")
    ap.add_argument("--pgbench-clients", type=int, default=2)
    ap.add_argument("--pgbench-rate", type=float, default=1.0, help="transactions (= sessions) per second")
    ap.add_argument("--check-sql", action="store_true")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.pgbench_only:
        print(f"[runner] pgbench only for {args.pgbench_only:.0f}s "
              f"({args.pgbench_rate}/s sessions, -C)", flush=True)
        pb = start_pgbench(args.pgbench_only, args.pgbench_clients, args.pgbench_rate)
        out = pb.communicate()[0]
        (args.out_dir / "pgbench.log").write_text(out)
        print(out.strip().splitlines()[-3:] if out.strip() else "", flush=True)
        return

    plan = load_plan([str(PROJECT_ROOT / g) if not Path(g).is_absolute() else g for g in args.specs],
                     args.wanted_class, args.limit)
    n_sess = sum(len(sc["sessions"]) for sc in plan)
    serial = sum(max(s["offsets"][-1] for s in sc["sessions"]) for sc in plan)
    print(f"[runner] {len(plan)} scenarios, {n_sess} {args.wanted_class} sessions, "
          f"~{serial / 60:.1f} min if run one at a time; running {args.parallel} at a time", flush=True)

    if args.check_sql:
        sys.exit(0 if check_sql(plan) else 1)

    ips = {ip for sc in plan for s in sc["sessions"] for ip in s["hosts"].values()}
    add_loopback_ips(ips)
    hosts_file = HostsFile()
    hosts_file.clear()
    log_rows, lock = [], threading.Lock()
    pb = None
    if args.pgbench:
        pb = start_pgbench(serial + 3600, args.pgbench_clients, args.pgbench_rate)
    t_start = time.time()
    try:
        pending = list(enumerate(plan))
        running = []
        while pending or running:
            running = [t for t in running if t.is_alive()]
            while pending and len(running) < args.parallel:
                idx, sc = pending.pop(0)
                t = threading.Thread(target=run_scenario, args=(sc, idx, hosts_file, log_rows, lock))
                t.start()
                running.append(t)
                done = len(plan) - len(pending) - len(running)
                print(f"[runner] {time.time() - t_start:6.0f}s  started {sc['run']}/{sc['scenario_id']}"
                      f"  ({done} done, {len(running)} running, {len(pending)} left)", flush=True)
            time.sleep(0.2)
    finally:
        if pb:
            pb.terminate()
            try:
                (args.out_dir / "pgbench.log").write_text(pb.communicate(timeout=10)[0] or "")
            except subprocess.TimeoutExpired:
                pb.kill()
            dexec("pkill", "-INT", "pgbench", check=False)
        hosts_file.clear()
        remove_loopback_ips(ips)
        planned = {r["key"]: r for r in log_rows if r.get("planned")}
        for r in log_rows:
            if not r.get("planned") and r["key"] in planned:
                planned[r["key"]].update(r)
        with open(args.out_dir / "live_manifest.jsonl", "w") as f:
            for r in planned.values():
                r.pop("planned", None)
                f.write(json.dumps(r) + "\n")
        errs = [r for r in planned.values() if r.get("errors")]
        print(f"[runner] finished in {(time.time() - t_start) / 60:.1f} min; "
              f"{len(planned)} sessions, {len(errs)} with SQL errors "
              f"(see {args.out_dir / 'live_manifest.jsonl'})", flush=True)


if __name__ == "__main__":
    main()
