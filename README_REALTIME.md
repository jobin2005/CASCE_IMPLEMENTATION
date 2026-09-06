# CASCE Real-Time Streaming Evaluation (Member 4 Guide)

This completely unified pipeline allows you to run concurrent `pgbench` traffic layered maliciously with APT attacks, while the `realtime_daemon.py` detects, graphs, and scores the workloads in milliseconds.

## Step 1: Initialize the Target Environment
Open a terminal in this `CASCE_IMPLEMENTATION` directory and run the daemon. Note the Python script runs effortlessly on your native host Ubuntu memory (No Docker Required!):
```bash
# This starts the daemon. It will wait silently for the logger hooks to begin writing JSON streams.
python3 -u realtime_daemon.py --pg-log /dataset_workspace/postgres_events.json --kernel-log /dataset_workspace/kernel_events.json
```

## Step 2: Trigger the EBPF Telemetry
In a separate terminal inside your Docker cluster (`casce_environment`):
```bash
cd /dataset_workspace
./workload_simulation/logger.sh start
```
This safely anchors the Postgres hooking arrays and activates eBPF memory pipes.

## Step 3: Unleash the Concurrent Workload Simulation
Still inside your Docker context, start blasting the application with your scripts concurrently:
```bash
# Fire thousands of benign noise queries 
./workload_simulation/normal_workload.sh &

# Fire hard-edge DB anomalies
./workload_simulation/benign_edge_cases.sh &

# Fire your 40+ APT/Data Extraction loads 
for attack in workload_simulation/attack_workload/*.sh; do 
    bash $attack & 
done
```

## Step 4: Extract Output and Statistics
As the shell scripts fire (Step 3), flip back to the terminal running `realtime_daemon.py` (Step 1). 
You will see the background threads printing real-time correlations!

1. Every detected attack is printed natively to the console:
   `[ALARM TRIGGERED | Session: XXX] EXTERNAL_TRANSFER Behavior Matched!`
2. The daemon automatically writes all permanent alerts safely to **`casce_realtime_alerts.log`** located right here in the repository!
3. Evaluate the precise End-to-End latency mathematically:
   `-- [System Metrics] Topology Engine Ingestion: 0.121 ms/event | Algorithmic Inference: 1.025 ms/execution --`

You can use the resulting `casce_realtime_alerts.log` array to perfectly triangulate Algorithm 4's streaming True Positives against your `labels.csv` ground truth!
