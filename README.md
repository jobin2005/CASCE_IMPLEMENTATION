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

### CLI Usage: End-to-End Workflow

#### 1. Generate Massive Multi-Domain Dataset
Generates synthetic scenarios across all domains (`banking`, `healthcare`, `ecommerce`, `logistics`) with dynamic endpoints and semantic families:
```bash
python3 datagen/generate_batch_v2.py \
  --out datagen/generated/multi_domain_huge \
  --runs 50 \
  --scenarios-per-run 35 \
  --domain all \
  --seed 42
```

#### 2. Correlate and Build Heterogeneous Graphs (Algorithms 1, 2, and 3)
Runs Session-Anchored Correlation (Alg 1), NetworkX Graph Construction (Alg 2), and MITRE ATT&CK Behavior Abstraction (Alg 3) across all runs:
```bash
python3 main.py datagen/generated/multi_domain_huge
```
*Output: Materializes enriched GraphML files into `datagen/generated/multi_domain_huge/enriched_graphs/graphml/`.*

#### 3. Create Stratified Family-Aware Splits
Partitions scenarios into Train (60%), Validation (20%), and Test (20%) sets with zero family-level data leakage:
```bash
python3 prepare_algo4_dataset.py datagen/generated/multi_domain_huge
```

#### 4. Train the HeteroGAT Model (Algorithm 4)
Trains the heterogeneous graph attention network on the generated dataset:
```bash
python3 algorithm_4_hybrid.py --mode train \
  --train-dir datagen/generated/multi_domain_huge/enriched_graphs/graphml \
  --val-dir datagen/generated/multi_domain_huge/enriched_graphs/graphml \
  --train-labels datagen/generated/multi_domain_huge/algo4_splits/train_labels.json \
  --val-labels datagen/generated/multi_domain_huge/algo4_splits/val_labels.json \
  --model-path casce_gat_huge.pt \
  --epochs 50 \
  --lr 0.001
```

#### 5. Evaluate on Held-Out Test Set
Evaluates detection accuracy, precision, recall, and F1 on unseen attack family variations:
```bash
python3 algorithm_4_hybrid.py --mode evaluate \
  --input-dir datagen/generated/multi_domain_huge/enriched_graphs/graphml \
  --labels datagen/generated/multi_domain_huge/algo4_splits/test_labels.json \
  --model-path casce_gat_huge.pt \
  --theta-a 0.65
```

#### 6. Run Adversarial IP Shortcut Ablation Testing
Strips all network connection nodes (`Endpoint`), connection edges (`connects_to`), and IP/port attributes to prove the model learns genuine query/process semantics:
```bash
python3 test_ip_shortcut_ablation.py \
  --input-dir datagen/generated/multi_domain_huge/enriched_graphs/graphml \
  --labels datagen/generated/multi_domain_huge/algo4_splits/test_labels.json \
  --model-path casce_gat_huge.pt \
  --theta-a 0.65
```

#### 7. Evaluate Generalization to Unseen Zero-Day Attack Families
Partitions and tests generalization against completely withheld attack families (e.g. `exfil`, `tamper`, `lateral`):
```bash
python3 test_zeroday_holdout.py datagen/generated/multi_domain_huge \
  --scenario exfil \
  --model-path casce_gat_huge.pt \
  --theta-a 0.65
```

#### 8. Run Real-Time Threat Detection on Session Graphs
Evaluates new or live session graphs and outputs detailed risk assessments:
```bash
python3 algorithm_4_hybrid.py --mode detect \
  --input-dir datagen/generated/multi_domain_huge/enriched_graphs/graphml \
  --model-path casce_gat_huge.pt \
  --outdir ./detect_output \
  --theta-a 0.65
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
│   ├── generator_diversity.py     # Diversity engine (IPs, URIs, endpoints)
│   ├── domain_knowledge.py        # Dynamic scenario & family generator
│   ├── generate_batch_v2.py       # Batch generator engine
│   ├── gate_pilot.py              # Statistical shortcut gating
│   ├── scenario_spec.md           # Spec format documentation
│   ├── scenario_spec.schema.json  # JSON schema for scenario specs
│   └── domains/                   # Ground-truth domain models
├── algorithm_1.py                 # Session-Anchored Correlation (SAC)
├── algorithm2.py                  # Base heterogeneous graph builder
├── algorithm_3_abstract.py        # MITRE ATT&CK behavioral abstractor
├── algorithm_4_hybrid.py          # HeteroGAT train / evaluate / detect engine
├── main.py                        # Batch pipeline orchestrator (Algs 1-3)
├── prepare_algo4_dataset.py       # Stratified family-aware dataset splitter
├── test_zeroday_holdout.py        # Unseen zero-day attack family evaluation
├── test_ip_shortcut_ablation.py   # Adversarial IP shortcut ablation testing
├── loader.py                      # Attributed event loader
├── schema.py                      # Schema & node/edge definitions
├── sqlfacts.py                    # SQL AST fact extractor (pglast)
└── graphsops.py                   # Graph serialization & helper ops
```

---

## Agentic Skill Usage

To generate synthetic dataset batches using Antigravity, request a batch with target count, domain, and mode:

```text
Generate 100 banking scenarios with the casce-datagen skill.
Balanced benign and malicious, pilot mode.
```

