#!/usr/bin/env python3
from bcc import BPF
import json
import time
import os

# eBPF C program mapping to required syscall tracepoints
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 ts;
    u32 syscall_id;
    char comm[TASK_COMM_LEN];
    char arg[128]; 
    u32 dest_ip;
    u16 dest_port;
};

static inline void submit_event(void *ctx, u32 syscall_id, const char *arg) {
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    data.syscall_id = syscall_id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (arg) {
        bpf_probe_read_user_str(&data.arg, sizeof(data.arg), arg);
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) { submit_event(args, 1, (const char *)args->filename); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_clone) { submit_event(args, 2, ""); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_openat) { submit_event(args, 3, (const char *)args->filename); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_rename) { submit_event(args, 4, (const char *)args->oldname); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) { submit_event(args, 5, (const char *)args->pathname); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    data.syscall_id = 6;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    struct sockaddr *uservaddr = (struct sockaddr *)args->uservaddr;
    short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
    
    if (family == 2) { /* AF_INET */
        struct sockaddr_in *sock = (struct sockaddr_in *)uservaddr;
        bpf_probe_read_user(&data.dest_ip, sizeof(data.dest_ip), &sock->sin_addr.s_addr);
        bpf_probe_read_user(&data.dest_port, sizeof(data.dest_port), &sock->sin_port);
    }
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_accept) { submit_event(args, 7, ""); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) { submit_event(args, 8, ""); return 0; }
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) { submit_event(args, 9, ""); return 0; }
"""

SYSCALL_MAP = {
    1: "execve", 2: "clone", 3: "openat", 4: "rename", 5: "unlink",
    6: "connect", 7: "accept", 8: "send", 9: "recv"
}

if __name__ == '__main__':
    b = BPF(text=bpf_text)
    output_file = "kernel_events.json"
    print(f"Tracing kernel events... Writing to {output_file}")

    with open(output_file, "a") as f:
        import socket
        import struct
        
        def print_event(cpu, data, size):
            event = b["events"].event(data)
            
            dest_ip_str = ""
            dest_port_int = 0
            if event.syscall_id == 6 and event.dest_ip != 0:
                try:
                    dest_ip_str = socket.inet_ntoa(struct.pack("<I", event.dest_ip))
                    dest_port_int = socket.ntohs(event.dest_port)
                except Exception:
                    pass

            try:
                comm = event.comm.decode('utf-8', 'ignore')
            except:
                comm = "unknown"
                
            try:
                arg = event.arg.decode('utf-8', 'ignore')
            except:
                arg = ""
                
            out = {
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "timestamp": event.ts,
                "comm": comm,
                "syscall": SYSCALL_MAP.get(event.syscall_id, "unknown"),
                "arg": arg
            }
            if dest_ip_str:
                out["dest_ip"] = dest_ip_str
                out["dest_port"] = dest_port_int
            f.write(json.dumps(out) + "\n")
            f.flush()

        b["events"].open_perf_buffer(print_event)
        
        try:
            while True:
                b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Stopped tracing.")
            exit()
