#!/usr/bin/env python3
"""
CASCE Real-Time Streaming Daemon
======================================================
Owner: Member 4 (Asiya - System Performance & Explainability)

This daemon simulates the exact flow of a real-time production SIEM deployment.
It actively tails `postgres_events.json` and `kernel_events.clean.json` as they are
written by `logger.sh` and the background simulation workloads. 

Algorithm Core:
- Continuously maintains a RAM mapping of PID -> PostgreSQL Session.
- Incrementally updates per-session `nx.MultiDiGraph` arrays natively in RAM.
- Periodically triggers Algorithm 3 and Algorithm 4 (Rule Heuristics) on active sessions.
- Precisely records processing latency (Event Time -> Alert Extraction) to generate profiling statistics.

Usage:
  python3 realtime_daemon.py --pg-log /dataset_workspace/postgres_events.json --kernel-log /dataset_workspace/kernel_events.normalized.json
"""

import time
import json
import argparse
import asyncio
import os
import networkx as nx
from collections import defaultdict
import numpy as np

import algorithm_3_abstract
import algorithm_4_hybrid

class CASCEStreamingEngine:
    def __init__(self):
        # Master Dictionary of all active Database session traces
        self.active_graphs = defaultdict(nx.MultiDiGraph)
        
        # eBPF Kernel Pid -> Database Session ID mapper
        self.pid_tracker = {}
        
        # Performance analytics registry
        self.latency_metrics = {
            "ingestion_overhead_ms": [],
            "algorithmic_overhead_ms": [],
            "total_e2e_latency_ms": []
        }
        
        self.templates = algorithm_3_abstract.initialize_templates()
        print("[+] CASCE Real-Time Streaming Engine Intialized.")

    def update_topology(self, event, layer="db"):
        """ Incrementally graphs an event (O(1) complexity per event) """
        start_ns = time.perf_counter_ns()
        
        session_id = None
        if layer == "db":
            session_id = event.get("session_id")
            self.pid_tracker[event.get("backend_pid")] = session_id
            node_id = f"Q_{event.get('timestamp')}_{event.get('backend_pid')}"
            
            G = self.active_graphs[session_id]
            G.add_node(node_id, 
                       type="Query", 
                       query=event.get("query", ""),
                       username=event.get("username", ""),
                       timestamp_unix=event.get("timestamp_unix", time.time()))
                       
        elif layer == "kernel":
            pid = event.get("pid")
            # Trace up lineage if it's a child spawn (e.g. bash spawned by postgres)
            session_id = self.pid_tracker.get(pid, self.pid_tracker.get(event.get("ppid")))
            
            if session_id:
                node_id = f"P_{pid}_{event.get('timestamp')}"
                G = self.active_graphs[session_id]
                G.add_node(node_id, 
                           type="Process", 
                           comm=event.get("comm", ""),
                           syscall=event.get("syscall", ""),
                           arg=event.get("arg", ""),
                           timestamp_unix=event.get("timestamp_unix", time.time()))
                
                if event.get("dest_ip"):
                    dest_id = f"E_{event.get('dest_ip')}"
                    G.add_node(dest_id, type="Endpoint", ip=event.get("dest_ip"))
                    G.add_edge(node_id, dest_id, relation="connects_to")
            
        overhead_ms = (time.perf_counter_ns() - start_ns) / 1e6
        self.latency_metrics["ingestion_overhead_ms"].append(overhead_ms)
        return session_id

    def run_detection_pipeline(self, session_id):
        """ Pulls active session graph, runs abstractions + classification, returns alert. """
        start_ns = time.perf_counter_ns()
        
        G_s = self.active_graphs.get(session_id)
        if not G_s or len(G_s.nodes) < 3:
            return None # Insufficient topology to analyze
            
        # Run Algorithm 3 
        try:
            G_enriched = algorithm_3_abstract.abstract_session_graph(G_s, self.templates)
        except Exception:
            G_enriched = G_s
            
        # Run Algorithm 4 (Using Heuristic fast-path because PyG is not instantiated here)
        assessment = algorithm_4_hybrid.detect(G_enriched, None, session_id=session_id)
        
        overhead_ms = (time.perf_counter_ns() - start_ns) / 1e6
        self.latency_metrics["algorithmic_overhead_ms"].append(overhead_ms)
        return assessment

async def tail_log_file(file_path, engine, layer="db"):
    """ Asynchronous Non-Blocking tailer """
    if not os.path.exists(file_path):
        print(f"[!] Target {file_path} doesn't exist yet, waiting...")
        while not os.path.exists(file_path):
            await asyncio.sleep(1)
            
    print(f"[*] Attached live stream onto {file_path}")
    with open(file_path, 'r') as f:
        # Go to end of file if you want to skip historical noise, but here we parse it all.
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.001) # Yield thread
                continue
                
            try:
                event = json.loads(line)
                
                # Markers dictate attack bounds, but we ignore them for topology
                if "marker" in event:
                    continue
                    
                e2e_start = time.perf_counter_ns()
                
                # INGESTION
                session_id = engine.update_topology(event, layer)
                
                if session_id:
                    # Every N events, check risk scale (for simplicity here, run every 10 events)
                    if len(engine.active_graphs[session_id].nodes) % 10 == 0:
                        assessment = engine.run_detection_pipeline(session_id)
                        if assessment and assessment['status'] == 'alert':
                            msg = f"[ALARM TRIGGERED | Session: {session_id}] {assessment['message']}"
                            print(f"\n{msg}")
                            with open("casce_realtime_alerts.log", "a") as af:
                                af.write(msg + "\n")
                            
                engine.latency_metrics["total_e2e_latency_ms"].append((time.perf_counter_ns() - e2e_start)/1e6)
            except json.JSONDecodeError:
                pass


async def main():
    parser = argparse.ArgumentParser(description="Live Streaming Threat Detection Daemon")
    parser.add_argument('--pg-log', type=str, default="postgres_events.json", help="Path to continuous PG JSON")
    parser.add_argument('--kernel-log', type=str, default="kernel_events.json", help="Path to continuous Kernel JSON")
    args = parser.parse_args()

    engine = CASCEStreamingEngine()
    
    # Fire up concurrent tailers
    db_tailer = asyncio.create_task(tail_log_file(args.pg_log, engine, layer="db"))
    kernel_tailer = asyncio.create_task(tail_log_file(args.kernel_log, engine, layer="kernel"))
    
    # Reporter daemon thread
    async def reporter():
        while True:
            await asyncio.sleep(10)
            ing_lat = np.mean(engine.latency_metrics["ingestion_overhead_ms"][-100:]) if engine.latency_metrics["ingestion_overhead_ms"] else 0
            alg_lat = np.mean(engine.latency_metrics["algorithmic_overhead_ms"][-100:]) if engine.latency_metrics["algorithmic_overhead_ms"] else 0
            print(f"-- [System Metrics] Topology Engine: {ing_lat:.4f} ms/event | Algorithmic Inference: {alg_lat:.4f} ms/execution --")
            
    metrics_reporter = asyncio.create_task(reporter())
    
    await asyncio.gather(db_tailer, kernel_tailer, metrics_reporter)

if __name__ == "__main__":
    asyncio.run(main())
