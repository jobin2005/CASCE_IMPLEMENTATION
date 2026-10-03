# CASCE: Cross-Layer Session-Centric Environment for Database Intrusion Detection

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![PyTorch 2.1](https://img.shields.io/badge/PyTorch-2.1-EE4C2C.svg)](https://pytorch.org/)
[![PyG 2.4](https://img.shields.io/badge/PyG-2.4-3C82F6.svg)](https://pyg.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Official Implementation** for the research paper: *"CASCE: Cross-Layer Session-Centric Intrusion Detection for Enterprise Database Systems using Heterogeneous Graph Neural Networks"*.

---

## 📌 Executive Summary

**CASCE (Cross-layer Session-Centric Environment)** is a novel intrusion detection framework designed to protect enterprise database infrastructures against complex, multi-stage Advanced Persistent Threats (APTs). By unifying low-level kernel system calls (**eBPF**) with high-level database query audit logs (**PostgreSQL**), CASCE constructs heterogeneous session provenance graphs that bridge domain silos.

Detection is performed via a **hybrid multi-agent architecture** combining:
1. **Rule Engine**: Fast-path deterministic detection for known MITRE ATT&CK attack chains.
2. **HeteroGATv2 Scorer**: A 2-layer Heterogeneous Graph Attention Network capturing subtle topological and behavioral anomalies.
3. **Probabilistic Noisy-OR Fusion**: Validation-tuned fusion logic yielding robust detection with minimal false alarms under real-time streaming traffic.

---

## 📊 Key Benchmark & Performance Metrics

Evaluated on the multi-domain enterprise benchmark dataset ($N=2,004$ test session graphs across Banking, E-Commerce, Healthcare, and Logistics domains) under the frozen validation-tuned operating point ($\theta_A = 0.65$, $w_{\mathrm{Rule}} = 0.85$, $w_{\mathrm{GAT}} = 0.75$):

| Metric | Value | Baseline Comparison (OS-Only) | Baseline Comparison (DB-Only) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | **95.11%** | 74.80% | 61.20% |
| **Precision** | **94.48%** | 69.15% | 84.30% |
| **Recall (Sensitivity)** | **95.68%** | 69.89% | 14.30% |
| **F1-Score** | **95.08%** | 69.52% | 24.50% |
| **False Positive Rate (FPR)** | **5.20%** | 21.80% | 0.10% |
| **AUROC** | **0.9934** | 0.6861 | 0.7120 |
| **AUPRC** | **0.9961** | 0.8133 | 0.7450 |

### 🚀 Attack-Family Detection Recall Breakdown
- **Cross-Layer APT Campaigns ($N=1,072$)**: **96.8% Recall** (**+29.0 percentage points** advantage over single-layer OS baselines).
- **OS-Dominant Threats ($N=512$)**: **87.7% Recall** (**+14.6 percentage points** advantage over OS-only baselines).
- **DB-Dominant Threats ($N=420$)**: **16.6% Recall** (**+2.3 percentage points** advantage over DB-only baselines).

---

## ⚡ Model Architecture & Computational Efficiency

| Specification | Value |
| :--- | :--- |
| **Architecture** | 2-layer Heterogeneous GAT (`HeteroConv` with `GATv2Conv`, 4 heads $\times$ 32 channels) |
| **Trainable Parameters** | **2,033,729 parameters** ($\approx 2.03 \text{ Million}$) |
| **Model Checkpoint Size (Disk)** | **7.98 MB** ($8,172 \text{ KB}$) |
| **In-Memory Size (RAM / VRAM)** | **$\approx 8.1 \text{ MB}$** (standard FP32 precision) |
| **Streaming Ingestion Latency** | **$0.121 \text{ ms}$ / event** |
| **Model Inference Latency** | **$1.025 \text{ ms}$ / graph execution** |
| **End-to-End Alert Latency** | **$1.73 \text{ seconds}$** (median streaming detection under live `pgbench` load) |

### 📐 Individual Session Graph Topology
- **Node Count ($|V|$)**: Min = 2, Max = 19, **Mean = 7.9 nodes**, Median = 7.0 nodes.
- **Edge Count ($|E|$)**: Min = 1, Max = 32, **Mean = 9.8 edges**, Median = 6.0 edges.
- **GraphML File Size**: Min = 2.8 KB, Max = 21.5 KB, **Mean = 9.2 KB**, Median = 8.0 KB.

---

## 🏗 System Architecture & Pipeline Workflow

```
┌─────────────────┐      ┌─────────────────────┐
│  eBPF Telemetry │      │ PostgreSQL Audit    │
│  (Process/File) │      │ (Query/Table/Role)  │
└────────┬────────┘      └──────────┬──────────┘
         │                          │
         └───────────┬──────────────┘
                     ▼
         ┌───────────────────────┐
         │ Algorithm 1: Parsing  │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────┐
         │ Algorithm 2: Linking  │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────┐
         │ Algorithm 3: Abstract │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────┐
         │ Algorithm 4: Hybrid   │
         │  (Rules + HeteroGAT)  │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────┐
         │ Real-Time Containment │
         │ (Risk Score > 0.65)   │
         └───────────────────────┘
```

1. **Algorithm 1 (Telemetry Extraction)**: Parses raw eBPF tracepoints (`sys_enter_execve`, `vfs_read/write`, `sys_enter_connect`) and PostgreSQL FEBE protocol messages into structured JSON events.
2. **Algorithm 2 (Provenential Cross-Layer Correlation)**: Maps low-level kernel processes to specific database backend PIDs and session context IDs.
3. **Algorithm 3 (Semantic Abstraction & Temporal Chaining)**: Enriches raw provenance graphs with MITRE ATT&CK `Behavior` nodes and directed chronological `precedes` temporal edges.
4. **Algorithm 4 (Multi-Agent Hybrid Detection)**: Combines rule chain scoring and HeteroGAT attention probabilities using validation-tuned noisy-OR logic:
   $$R = 1 - \left(1 - w_{\mathrm{Rule}} S_{\mathrm{rule}}\right)\left(1 - w_{\mathrm{GAT}} S_{\mathrm{GAT}}\right)$$

---

## 🛠 Quick-Start & Verification Guide

### 1. Repository Setup & Dependencies
```bash
# Clone the repository
git clone https://github.com/jobin2005/CASCE_IMPLEMENTATION.git
cd CASCE_IMPLEMENTATION

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Running Live Streaming Real-Time Evaluation
Start the live streaming daemon to ingest, graph, and score events in real time:
```bash
# Start the real-time background daemon
python3 -u realtime_daemon.py \
  --pg-log /dataset_workspace/postgres_events.json \
  --kernel-log /dataset_workspace/kernel_events.json \
  --model-path casce_gat_v2.pt \
  --theta-a 0.65
```

### 3. Executing Empirical Ablation Suite
To run the full Member C model & algorithm ablation experiments across test graphs:
```bash
# Execute Experiment Suite (Exps 1-6)
python3 run_mc_ablation_experiments.py
```
Output results and visual plots will be generated in `casce_results/`:
- `casce_results/main_detection_tables/`
- `casce_results/confusion_matrices/`
- `casce_results/ROC_PR_curves/`
- `casce_results/algorithm3_ablation/`

---

## 📂 Project Repository Structure

```
CASCE_IMPLEMENTATION/
├── algorithm_1.py              # Alg 1: Raw telemetry extraction & JSON parsing
├── algorithm2.py               # Alg 2: Cross-layer session correlation
├── algorithm_3_abstract.py     # Alg 3: Behavior abstraction & temporal chaining
├── algorithm_4_hybrid.py       # Alg 4: HeteroGATv2 + Rule engine hybrid fusion
├── realtime_daemon.py          # Real-time streaming evaluation daemon
├── run_mc_ablation_experiments.py # Complete empirical evaluation & ablation suite
├── casce_gat_v2.pt             # Trained HeteroGAT model checkpoint (7.98 MB)
├── EXPERIMENTS.md              # Detailed experiment documentation & logs
├── README_REALTIME.md          # Real-time environment execution guide
└── requirements.txt            # Python dependencies
```

---

## 📄 Citation & License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
