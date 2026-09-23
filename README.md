# CASCE: Cross-layer Session-Centric Environment for PostgreSQL Threat Detection

![CASCE Status](https://img.shields.io/badge/Status-Active_Development-blue)
![Architecture](https://img.shields.io/badge/Architecture-eBPF_%7C_PostgreSQL_%7C_PyTorch-success)
![Pipeline](https://img.shields.io/badge/Dataset-Spec--Driven_Datagen-green)

## Overview
**CASCE** is a state-of-the-art cybersecurity provenance framework specifically architected to detect Advanced Persistent Threats (APTs) targeting PostgreSQL database environments. 

Traditional provenance IDS systems rely solely on OS-level hooks or static database logs, suffering heavily from "dependency explosion" (yielding massive False Positives) or structural brittleness (yielding massive False Negatives). CASCE fundamentally resolves this by dynamically fusing Linux Kernel telemetry mapped through eBPF with native PostgreSQL Abstract Syntax Tree (AST) logic. By processing this unified cross-layer data through a Heterogeneous Graph Attention Network (**HeteroGATv2**), CASCE mathematically eliminates baseline limitations and achieves a theoretically proven minimum Bayes classification error.

---

## Dataset Generation Pipeline (`datagen/`)

Real database captures suffer from privacy restrictions and near-duplicate leakage across train/val/test splits. CASCE resolves this with a **declarative, spec-driven synthetic dataset generation engine** that enforces strict cross-layer invariants, matched pairs (counterfactual controls), and automated graph verification.

### Core Components
1. **Scenario Specs (`specs/*.yaml`)**: Declarative YAML files defining scenario identity, family grouping, matched-pair constraints, PostgreSQL sessions, SQL queries, and OS process/file/network side-effects.
2. **Domain Models (`datagen/domains/*.yaml`)**: Ground-truth schema contracts (tables, sensitive PII columns, roles, normal role privileges).
3. **Deterministic Generator (`datagen/codegen.py`)**: Converts YAML specs into deterministic `postgres_events.json`, `kernel_events.json`, `labels.csv`, and `expectation_manifest.json` with isolated PID namespaces and clock calibration offsets.
4. **Pipeline Validator (`datagen/validate_run.py`)**: Executes generated logs through `algorithm_1` (Session-Anchored Correlation) and `algorithm2` (NetworkX graph construction) to verify structural and edge correctness.
5. **Agentic Batch Orchestration (`.agents/skills/casce-datagen/`)**: Agent skill enabling Antigravity to plan batch generation (`plan_<batch_id>.json`), manage worker isolation, evaluate pilot statistical shortcut gates, and maintain idempotency (`manifest.jsonl`).

### CLI Usage

```bash
# 1. Generate run artifacts from specs
python datagen/codegen.py datagen/smoke_run

# 2. Validate run artifacts through the detection pipeline
python datagen/validate_run.py datagen/smoke_run
```

---

## Detection Pipeline Architecture

The detection pipeline consists of four sequential algorithms:

```
datagen Logs (postgres_events.json & kernel_events.json)
                         │
                         ▼
        Algorithm 1: Session-Anchored Correlation (SAC)
                         │
                         ▼
        Algorithm 2: Heterogeneous Base Graph Construction
        (Nodes: Session, Query, Table, Role, Process, File, Endpoint)
                         │
                         ▼
        Algorithm 3: Behavioral Abstraction & MITRE ATT&CK Enrichment
        (Adds high-level Behavior nodes: DATA_ACCESS, EXTERNAL_TRANSFER, etc.)
                         │
                         ▼
        Algorithm 4 / GAT Engine: HeteroGAT Threat Classification
```

1. **Algorithm 1 (`algorithm_1.py`)**: Correlates PostgreSQL audit logs and eBPF kernel event streams into distinct session keys via PID ancestry tracing (`ppid` chain up to `D_MAX=8`).
2. **Algorithm 2 (`algorithm2.py`)**: Constructs multi-directed NetworkX graphs with heterogeneous node types (`Session`, `Query`, `Table`, `Role`, `Process`, `File`, `Endpoint`) and directed relation edges (`executes`, `queries`, `targets`, `spawns`, `opens`, `connects_to`).
3. **Algorithm 3 (`algorithm_3_abstract.py`)**: Evaluates MITRE ATT&CK behavioral templates via structural isomorphism, semantic TF-IDF matching, and temporal decay ($S_{\text{struct}}, S_{\text{sem}}, S_{\text{temp}}$), enriching the graph with `Behavior` nodes.
4. **Algorithm 4 & PyTorch GAT (`algorithm_4_hybrid.py`, `casce_gat.pt`)**: Encodes heterogeneous graph structures via PyTorch Geometric to compute threat probabilities and classify malicious activity.

---

## Repository Structure

```
.
├── .agents/skills/casce-datagen/  # Agentic batch generation skill
├── datagen/                       # Synthetic dataset generator & validator
│   ├── codegen.py                 # Spec-to-log deterministic generator
│   ├── validate_run.py            # Pipeline validator
│   ├── scenario_spec.md           # Spec format v1 documentation
│   ├── scenario_spec.schema.json  # JSON schema for scenario specs
│   ├── domains/                   # Domain models (banking.yaml)
│   └── smoke_run/                 # Smoke test run directory
├── algorithm_1.py                 # Session-Anchored Correlation (SAC)
├── algorithm2.py                  # Base heterogeneous graph builder
├── algorithm_3_abstract.py        # MITRE ATT&CK behavioral abstractor
├── algorithm_4_hybrid.py          # Hybrid GAT threat classifier
├── main.py                        # Pipeline entry point & queue manager
├── loader.py                      # Attributed event loader
├── schema.py                      # Schema & node/edge definitions
├── sqlfacts.py                    # SQL AST fact extractor (pglast)
├── graphsops.py                   # Graph modification helpers
├── undersample.py                 # Dataset balancing utility
└── evaluate.py                    # Model evaluation script
```

---

## Agentic Skill Usage

To generate synthetic dataset batches using Antigravity, request a batch with target count, domain, and mode:

```text
Generate 100 banking scenarios with the casce-datagen skill.
Balanced benign and malicious, pilot mode.
```

