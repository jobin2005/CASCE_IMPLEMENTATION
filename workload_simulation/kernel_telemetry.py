#!/usr/bin/env python3
"""
CASCE kernel-plane collector (eBPF / BCC).

Writes kernel_events.json in exactly the shape datagen/codegen.py produces
for the synthetic corpus (see _kernel_record / _build_sql_event there), so
live runs go through Algorithms 1-4 unchanged.

What is traced
--------------
Only processes DESCENDED FROM A POSTGRES BACKEND (postmaster -> backend ->
child ...). Ancestry is tracked in-kernel (sched_process_fork), so the
rest of the host (desktop apps, the container's other processes) and
Postgres' own processes (backends, autovacuum, checkpointer, walwriter,
...) never reach user space. That is what the synthetic corpus contains:
kernel records only for commands a session spawned.

Syscalls: execve, openat, connect -- the three the corpus uses.

Normalisation to the codegen conventions (raw events are kept, see below)
--------------------------------------------------------------------------
1. Clock: a LOGGING_START marker (wall clock) and a clock_anchor record
   (monotonic ns, same instant) are written first, exactly like codegen,
   so Algorithm 1's _calibrate_kernel_clock gets an exact offset.
2. COPY ... TO PROGRAM runs `sh -c "<cmd>"`. codegen has no shell process:
   pipeline segment 0 is a child of the backend and segment k a child of
   segment k-1. The `sh -c` wrapper is therefore not emitted and its
   children are re-parented that way.
3. execve: comm = argv[0] as typed, arg = the full command line plus its
   redirections ("cat > /tmp/x"), as codegen writes it. Only successful
   execs are emitted (the shell's failed PATH probes are dropped).
4. Pipeline order: segments are ordered by fork order (= the order written
   in the command), not by which exec finishes first.
5. Redirection targets are opened by the shell BEFORE the command execs;
   they are emitted as openat records of the command process right after
   its execve (timestamp = execve + k us), as codegen does -- otherwise
   Algorithm 2 cannot attach the File to its Process.
6. Loader / runtime noise is dropped: failed opens, shared libraries,
   ld.so.cache, locale, /proc, /sys, TLS config and certificate stores,
   resolver config, libc's /etc/passwd|group lookups (unless the command
   names the file), DNS (port 53) and non-IPv4 connects.
7. When a backend exits, a {"marker": "SESSION_END", "backend_pid": ...} line is
   written. Markers are skipped by Algorithms 1-4 (like LOGGING_START).

Every traced event is also written unmodified to kernel_events.raw.json,
so the normalisation can be audited.
"""
import argparse
import json
import os
import signal
import socket
import struct
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>

#define ARGSIZE 128
#define MAXARG  20

enum ev_type { EV_EXEC_ARG = 1, EV_EXEC_ENTER = 2, EV_EXEC_RET = 3, EV_OPENAT = 4, EV_CONNECT = 5, EV_FORK = 6, EV_EXIT = 7 };

struct data_t {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 depth;
    s32 retval;
    u32 flags;
    u32 dest_ip;
    u32 child;
    u16 dest_port;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char arg[ARGSIZE];
};

BPF_PERF_OUTPUT(events);
/* tgid -> depth below the postmaster (postmaster = 0, backend = 1, spawned = 2+) */
BPF_HASH(tracked, u32, u32, 65536);
/* tid -> openat in flight (reported on exit, with its result) */
BPF_HASH(open_infly, u32, struct data_t, 4096);

static __always_inline u32 *tracked_depth(void) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return tracked.lookup(&tgid);
}

static __always_inline void fill(struct data_t *d, u32 type, u32 depth) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    d->type = type;
    d->pid = bpf_get_current_pid_tgid() >> 32;
    d->ppid = task->real_parent->tgid;
    d->uid = bpf_get_current_uid_gid();
    d->depth = depth;
    d->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&d->comm, sizeof(d->comm));
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = bpf_get_current_pid_tgid() >> 32;
    u32 child = args->child_pid;
    u32 *d = tracked.lookup(&parent);
    if (d) {
        u32 nd = *d + 1;
        tracked.update(&child, &nd);
        if (*d >= 2) {  /* fork order = pipeline order for `sh -c "a | b"` */
            struct data_t data = {};
            fill(&data, EV_FORK, *d);
            data.child = child;
            events.perf_submit(args, &data, sizeof(data));
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    /* per task: a thread's own entry (from fork) or, for the main thread, the process */
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u32 *d = tracked.lookup(&tid);
    if (d && *d > 0) {
        if (*d == 1 && tid == (u32)(id >> 32)) {  /* a backend (session) ends */
            struct data_t data = {};
            fill(&data, EV_EXIT, 1);
            events.perf_submit(args, &data, sizeof(data));
        }
        tracked.delete(&tid);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 *d = tracked_depth();
    if (!d || *d < 2)
        return 0;
    struct data_t data = {};
    fill(&data, EV_EXEC_ARG, *d);
    const char *const *argv = (const char *const *)args->argv;
    #pragma unroll
    for (int i = 0; i < MAXARG; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        data.flags = i;
        bpf_probe_read_user_str(&data.arg, sizeof(data.arg), argp);
        events.perf_submit(args, &data, sizeof(data));
    }
    data.type = EV_EXEC_ENTER;
    bpf_probe_read_user_str(&data.arg, sizeof(data.arg), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u32 *d = tracked_depth();
    if (!d || *d < 2)
        return 0;
    struct data_t data = {};
    fill(&data, EV_EXEC_RET, *d);
    data.retval = args->ret;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 *d = tracked_depth();
    if (!d || *d < 2)
        return 0;
    struct data_t data = {};
    fill(&data, EV_OPENAT, *d);
    data.flags = args->flags;
    bpf_probe_read_user_str(&data.arg, sizeof(data.arg), args->filename);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    open_infly.update(&tid, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct data_t *data = open_infly.lookup(&tid);
    if (!data)
        return 0;
    data->retval = args->ret;
    events.perf_submit(args, data, sizeof(*data));
    open_infly.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 *d = tracked_depth();
    if (!d || *d < 2)
        return 0;
    struct data_t data = {};
    fill(&data, EV_CONNECT, *d);
    struct sockaddr *sa = (struct sockaddr *)args->uservaddr;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &sa->sa_family);
    if (family == 2) { /* AF_INET */
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        bpf_probe_read_user(&data.dest_ip, sizeof(data.dest_ip), &sin->sin_addr.s_addr);
        bpf_probe_read_user(&data.dest_port, sizeof(data.dest_port), &sin->sin_port);
    }
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

EV_EXEC_ARG, EV_EXEC_ENTER, EV_EXEC_RET, EV_OPENAT, EV_CONNECT, EV_FORK, EV_EXIT = 1, 2, 3, 4, 5, 6, 7
EV_NAMES = {1: "exec_arg", 2: "exec_enter", 3: "exec_ret", 4: "openat", 5: "connect", 6: "fork", 7: "exit"}

SHELLS = {"sh", "dash", "bash"}

# Opened by the dynamic loader / libc / TLS / resolver for any command --
# never part of the command's own behaviour, and absent from the corpus.
NOISE_PREFIXES = (
    "/etc/ld.so.", "/lib/", "/lib64/", "/lib32/", "/usr/lib/", "/usr/lib64/",
    "/usr/lib32/", "/usr/libx32/", "/usr/local/lib/", "/usr/share/locale",
    "/usr/share/zoneinfo", "/usr/share/ca-certificates/", "/usr/lib/ssl/",
    "/etc/ssl/", "/etc/gnutls/", "/proc/", "/sys/", "/dev/tty", "/dev/urandom",
    "/dev/random",
)
NOISE_FILES = {
    "/etc/nsswitch.conf", "/etc/localtime", "/etc/gai.conf", "/etc/host.conf",
    "/etc/resolv.conf", "/etc/hosts", "/etc/locale.alias", "/etc/os-release",
    "/etc/ld.so.cache", "/etc/ld.so.preload", "/etc/inputrc",
}

# Read by libc for user/group lookups (getpwuid etc.) by almost any command;
# kept only when the command itself names the file (e.g. `cat /etc/passwd`).
NSS_FILES = {"/etc/passwd", "/etc/group"}

O_ACCMODE, O_WRONLY, O_RDWR, O_APPEND = 0o3, 0o1, 0o2, 0o2000


def is_noise_path(path, cmdline=""):
    if not path or path in NOISE_FILES or path.startswith(NOISE_PREFIXES):
        return True
    return path in NSS_FILES and path not in cmdline


def redirect_op(flags):
    if flags & O_APPEND:
        return ">>"
    if (flags & O_ACCMODE) in (O_WRONLY, O_RDWR):
        return ">"
    return "<"


def read_postmaster_pid(pgdata):
    with open(os.path.join(pgdata, "postmaster.pid")) as f:
        return int(f.readline().strip())


def proc_ppid_map():
    """pid -> ppid for every process currently visible in /proc."""
    out = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat") as f:
                stat = f.read()
            # comm may contain spaces/parens: ppid is the 2nd field after the last ')'
            out[int(name)] = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
    return out


class Normaliser:
    """Turns raw per-syscall events into codegen-shaped kernel records."""

    def __init__(self, out, raw_out, wall0, mono0):
        self.out = out
        self.raw_out = raw_out
        self.wall0, self.mono0 = wall0, mono0   # clock anchor, for SESSION_END wall times
        self.argv = {}          # pid -> [argv...] collected for the in-flight execve
        self.exec_enter = {}    # pid -> (ts, filename)
        self.execd = {}         # pid -> {"comm", "ppid"} once a (normalised) exec has been emitted
        self.pre_exec_opens = {}  # pid -> [(ts, path, flags)] redirects opened before exec
        self.wrappers = {}      # sh -c wrapper pid -> {"backend", "last_seg", "pending"}

    def write(self, rec):
        self.out.write(json.dumps(rec) + "\n")

    def handle(self, e):
        comm = e.comm.decode("utf-8", "replace")
        arg = e.arg.decode("utf-8", "replace")
        raw = {"type": EV_NAMES.get(e.type, e.type), "pid": e.pid, "ppid": e.ppid, "uid": e.uid,
               "depth": e.depth, "timestamp": e.ts, "comm": comm, "arg": arg,
               "flags": e.flags, "retval": e.retval}
        if e.type == EV_FORK:
            raw["child"] = e.child
        if e.type == EV_CONNECT and e.dest_ip:
            raw["dest_ip"] = socket.inet_ntoa(struct.pack("<I", e.dest_ip))
            raw["dest_port"] = socket.ntohs(e.dest_port)
        self.raw_out.write(json.dumps(raw) + "\n")

        if e.type == EV_EXEC_ARG:
            if e.flags == 0:
                self.argv[e.pid] = []
            self.argv.setdefault(e.pid, []).append(arg)
        elif e.type == EV_EXEC_ENTER:
            self.exec_enter[e.pid] = (e.ts, arg)
        elif e.type == EV_EXEC_RET:
            self._on_exec_ret(e)
        elif e.type == EV_OPENAT:
            self._on_openat(e, arg)
        elif e.type == EV_CONNECT:
            self._on_connect(e, raw)
        elif e.type == EV_EXIT:
            # A marker, like LOGGING_START: Algorithms 1-4 skip marker lines, so the
            # record stream stays identical to the corpus. The daemon uses it to
            # finalise a session the moment it disconnects.
            self.write({"marker": "SESSION_END", "backend_pid": e.pid,
                        "timestamp": self.wall0 + (e.ts - self.mono0) / 1e9})
        elif e.type == EV_FORK and e.pid in self.wrappers:
            self.wrappers[e.pid]["children"].append(e.child)

    # -- execve ---------------------------------------------------------
    def _on_exec_ret(self, e):
        argv = self.argv.pop(e.pid, [])
        enter_ts, _filename = self.exec_enter.pop(e.pid, (e.ts, ""))
        if e.retval != 0 or not argv:
            return  # failed PATH probe -- the shell will try the next one
        prog = os.path.basename(argv[0])

        # COPY ... TO PROGRAM: backend -> `sh -c "<cmd>"`; codegen has no shell.
        if e.depth == 2 and prog in SHELLS and len(argv) >= 3 and argv[1] == "-c":
            self.wrappers[e.pid] = {"backend": e.ppid, "children": [],
                                    "pending": self.pre_exec_opens.pop(e.pid, [])}
            return

        if e.pid in self.wrappers:
            # the shell exec'd the (last) command in place instead of forking it
            w = self.wrappers.pop(e.pid)
            out_ppid = w["children"][-1] if w["children"] else w["backend"]
            redirects = w["pending"] + self.pre_exec_opens.pop(e.pid, [])
        elif e.ppid in self.wrappers:
            # segment k (in fork order == order in the command) is a child of
            # segment k-1, segment 0 a child of the backend -- as in codegen
            w = self.wrappers[e.ppid]
            kids = w["children"]
            k = kids.index(e.pid) if e.pid in kids else len(kids)
            out_ppid = kids[k - 1] if k > 0 else w["backend"]
            redirects = w["pending"] + self.pre_exec_opens.pop(e.pid, [])
            w["pending"] = []
        else:
            out_ppid = e.ppid
            redirects = self.pre_exec_opens.pop(e.pid, [])

        comm = argv[0]
        cmdline = " ".join(argv)
        cmdline += "".join(f" {redirect_op(flags)} {path}" for _, path, flags in redirects)
        self.execd[e.pid] = {"comm": comm, "ppid": out_ppid, "cmdline": cmdline}
        self.write({"pid": e.pid, "ppid": out_ppid, "uid": e.uid, "timestamp": enter_ts,
                    "comm": comm, "syscall": "execve", "arg": cmdline})
        for k, (_, path, _flags) in enumerate(redirects, start=1):
            self.write({"pid": e.pid, "ppid": out_ppid, "uid": e.uid,
                        "timestamp": enter_ts + k * 1000,
                        "comm": comm, "syscall": "openat", "arg": path})

    # -- openat ---------------------------------------------------------
    def _on_openat(self, e, path):
        if e.retval < 0:
            return  # failed lookups (config files that don't exist, PATH probes)
        info = self.execd.get(e.pid)
        if is_noise_path(path, info["cmdline"] if info else ""):
            return
        if info is None:
            # not exec'd yet: a redirection the shell opens for the command
            if e.pid in self.wrappers:
                self.wrappers[e.pid]["pending"].append((e.ts, path, e.flags))
            else:
                self.pre_exec_opens.setdefault(e.pid, []).append((e.ts, path, e.flags))
            return
        self.write({"pid": e.pid, "ppid": info["ppid"], "uid": e.uid, "timestamp": e.ts,
                    "comm": info["comm"], "syscall": "openat", "arg": path})

    # -- connect --------------------------------------------------------
    def _on_connect(self, e, raw):
        info = self.execd.get(e.pid)
        if info is None or "dest_ip" not in raw or raw["dest_port"] == 53:
            return
        self.write({"pid": e.pid, "ppid": info["ppid"], "uid": e.uid, "timestamp": e.ts,
                    "comm": info["comm"], "syscall": "connect", "arg": "",
                    "dest_ip": raw["dest_ip"], "dest_port": raw["dest_port"]})


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", default="/dataset_workspace/kernel_events.json")
    ap.add_argument("--raw-out", default="/dataset_workspace/kernel_events.raw.json")
    ap.add_argument("--pg-log", default="/dataset_workspace/postgres_events.json")
    ap.add_argument("--pgdata", default="/var/lib/postgresql/data")
    ap.add_argument("--ready-file", default="/dataset_workspace/.casce_kernel_tracer.ready")
    args = ap.parse_args()

    postmaster = read_postmaster_pid(args.pgdata)
    b = BPF(text=BPF_TEXT)
    tracked = b["tracked"]

    # Seed ancestry with what already exists: postmaster (0), backends (1), their children (2+).
    tracked[tracked.Key(postmaster)] = tracked.Leaf(0)
    ppids = proc_ppid_map()
    depth = {postmaster: 0}
    frontier = [postmaster]
    while frontier:
        nxt = []
        for pid, ppid in ppids.items():
            if ppid in frontier and pid not in depth:
                depth[pid] = depth[ppid] + 1
                tracked[tracked.Key(pid)] = tracked.Leaf(depth[pid])
                nxt.append(pid)
        frontier = nxt

    out = open(args.out, "a", buffering=1)
    raw_out = open(args.raw_out, "a", buffering=1)

    # Clock anchor, exactly as codegen writes it: wall-clock marker + monotonic
    # anchor record taken at the same instant (bpf_ktime_get_ns == CLOCK_MONOTONIC).
    w0 = time.time()
    mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    w1 = time.time()
    wall = (w0 + w1) / 2
    marker = json.dumps({"marker": "LOGGING_START", "timestamp": wall})
    out.write(marker + "\n")
    out.write(json.dumps({"pid": 0, "ppid": 0, "uid": 0, "timestamp": mono,
                          "comm": "clock_anchor", "syscall": "clock_nanosleep", "arg": ""}) + "\n")
    with open(args.pg_log, "a") as pg:
        pg.write(marker + "\n")

    norm = Normaliser(out, raw_out, wall, mono)
    b["events"].open_perf_buffer(lambda cpu, data, size: norm.handle(b["events"].event(data)),
                                 page_cnt=256,
                                 lost_cb=lambda n: print(f"[kernel_telemetry] LOST {n} events",
                                                         file=sys.stderr, flush=True))

    with open(args.ready_file, "w") as f:
        f.write(str(os.getpid()))
    print(f"[kernel_telemetry] postmaster={postmaster}, seeded {len(depth) - 1} processes, "
          f"writing {args.out}", flush=True)

    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    while not stop:
        b.perf_buffer_poll(timeout=200)
    b.perf_buffer_poll(timeout=0)  # drain what is left
    out.close()
    raw_out.close()
    try:
        os.remove(args.ready_file)
    except OSError:
        pass
    print("[kernel_telemetry] stopped.", flush=True)


if __name__ == "__main__":
    main()
