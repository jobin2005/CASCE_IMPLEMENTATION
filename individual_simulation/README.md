# Real-Time Live Attack Simulation Suite (4D Workload)

This directory contains the real-time evaluation suite of CASCE executed against a live PostgreSQL 17 testbed and Linux kernel eBPF tracepoints, using the 4D attack workload suite (`4d-live-attack-workload`).

All experiments are performed on **live telemetry** captured in real time via:
- PostgreSQL executor hook (`pg_telemetry.so`)
- Linux eBPF kprobes/tracepoints (`logger.sh` / `kernel_telemetry.py`)
- Live clock synchronization anchor (`LOGGING_START` monotonic ns to wall-clock epoch)
- NetworkX GraphML heterogeneous graph synthesis and PyG HeteroGAT (`casce_gat_v3p_ens2`) risk inference.

---

## 1. 24-Case Individual Simulation Suite (`individual_cases/`)

The individual simulation suite contains 24 isolated real-time scenarios (16 attack variants + 8 seen/unseen benign banking workloads). Each scenario directory contains:
- `postgres_events.json`: Exact SQL statements, query hashes, and user roles from the C executor hook.
- `kernel_events.json`: Exact eBPF syscalls (`sys_enter_execve`, `sys_enter_connect`, file I/O).
- `<case_name>.graphml`: Heterogeneous provenance graph with behavioral node abstractions (MITRE ATT&CK style).
- `graph.png`: High-resolution visual render showing database queries, kernel processes, file descriptors, and behavioral nodes.
- `summary.json`: Detailed detection metrics, risk scores, rule scores, GAT scores, and confusion verdicts.

### Individual Confusion Matrix Summary

| Metric | Value |
|---|---|
| **True Positives (TP)** | 7 |
| **True Negatives (TN)** | 8 |
| **False Positives (FP)** | **0** (0.0% False Positive Rate) |
| **False Negatives (FN)** | 9 |
| **Precision** | **100.0%** |
| **Specificity** | **100.0%** |
| **Recall (TPR)** | 43.8% |
| **F1 Score** | 0.6087 |

---

## 2. Category-Wise Real-Time Attack Experiments (`category_experiments/`)

The 4 core threat categories were executed independently in real time against the PostgreSQL database testbed:

| Attack Category | Total Sessions | Attacks (Pos) | Benign (Neg) | TP | FN | FP | TN | Recall (TPR) | Precision | F1 Score | FPR | Latency (p50) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Class 1: Privilege Abuse & Escalation** | 11 | 5 | 6 | 5 | 0 | **0** | 6 | **100.0%** | **100.0%** | **1.0000** | **0.0%** | 81.4 ms |
| **Class 2: Data Exfiltration** | 21 | 15 | 6 | 5 | 10 | **0** | 6 | 33.3% | **100.0%** | 0.5000 | **0.0%** | 82.4 ms |
| **Class 3: SQL Injection & Sabotage** | 9 | 3 | 6 | 0 | 3 | **0** | 6 | 0.0% | **100.0%** | 0.0000 | **0.0%** | 79.7 ms |
| **Class 4: Multi-Stage APT Scenarios** | 12 | 6 | 6 | 5 | 1 | **0** | 6 | **83.3%** | **100.0%** | **0.9091** | **0.0%** | 79.8 ms |

---

## 3. Intermixed Real-Time Benchmark with Background `pgbench` (`intermixed_pgbench_experiment/`)

To validate real-time detection in noisy, concurrent production environments, all 4 threat categories and benign activities were executed concurrently while a continuous high-volume `pgbench` transaction load ran in the background (`-C` connection-per-transaction, ~3.1 TPS):

| Metric | Value |
|---|---|
| **Total Live Sessions Evaluated** | **155** |
| - Background `pgbench` Sessions | 139 |
| - Foreground Benign Banking Sessions | 7 |
| - Foreground Attack Sessions | 9 |
| **True Positives (TP)** | 4 |
| **True Negatives (TN)** | **146** (139 `pgbench` + 7 banking) |
| **False Positives (FP)** | **0** (**0.0% False Positive Rate**) |
| **False Negatives (FN)** | 5 |
| **Precision** | **100.0%** |
| **Specificity (TNR)** | **100.0%** |
| **Recall (TPR)** | 44.4% |
| **F1 Score** | 0.6154 |
| **Latency p50** | **28.6 ms** |
| **Latency p90** | **40.5 ms** |
| **Latency p99** | **133.2 ms** |

### Per-Category Breakdown Under Concurrent `pgbench` Load:

| Workload Category | Total Sessions | TP | FN | FP | TN | Recall | Precision | FPR |
|---|---|---|---|---|---|---|---|---|
| **Class 1: Privilege Abuse & Escalation** | 3 | 3 | 0 | 0 | 0 | **100.0%** | **100.0%** | 0.0% |
| **Class 2: Data Exfiltration** | 3 | 0 | 3 | 0 | 0 | 0.0% | 100.0% | 0.0% |
| **Class 3: SQL Injection & Sabotage** | 1 | 0 | 1 | 0 | 0 | 0.0% | 100.0% | 0.0% |
| **Class 4: Multi-Stage APT Scenarios** | 2 | 1 | 1 | 0 | 0 | **50.0%** | **100.0%** | 0.0% |
| **Benign Banking (Seen + Unseen)** | 7 | 0 | 0 | **0** | **7** | N/A | N/A | **0.0%** |
| **Benign `pgbench` Background Noise** | 139 | 0 | 0 | **0** | **139** | N/A | N/A | **0.0%** |

---

## 4. Reproducibility Commands

To re-run the experiments:

```bash
cd /home/adithyan/Desktop/backup/CASCE_IMPLEMENTATION

# Experiment 1 & 2: Individual Cases (24) and Category-Wise Runs (4 classes)
python3 individual_simulation/run_full_live_experiments.py

# Experiment 3: Full Intermixed Benchmark with Background pgbench
python3 individual_simulation/run_intermixed_experiment.py
```

Generated manifests:
- `individual_simulation/individual_cases/individual_suite_manifest.json`
- `individual_simulation/category_experiments/category_summary.json`
- `individual_simulation/intermixed_pgbench_experiment/intermixed_experiment_summary.json`
