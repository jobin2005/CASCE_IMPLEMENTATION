# CASCE: Context-Aware Session Correlation and Enrichment

CASCE is an end-to-end framework for detecting cyberattacks in enterprise environments using provenance graphs, behavioral abstraction, and Graph Attention Networks (GAT).

---

## Architecture Overview

The pipeline consists of four core algorithms:

1. **Algorithm 1: Session-Anchored Correlation (SAC)** (`algorithm_1.py`)
   - Ingests raw host telemetry, authentication logs, and network events.
   - Correlates multi-source events by user session identifiers, process GUIDs, and temporal proximity into structured event tables.

2. **Algorithm 2: Provenance Graph Construction** (`algorithm2.py`)
   - Transforms correlated session events into directed provenance multigraphs (`nx.MultiDiGraph`) capturing causal interactions between processes, files, sockets, and registry keys.

3. **Algorithm 3: Behavioral Graph Abstraction & Feature Enrichment** (`algorithm_3_abstract.py`)
   - Abstracts raw system artifacts into high-level behavioral motifs using predefined pattern templates.
   - Enriches nodes and edges with behavioral features and exports enriched `.graphml` files per session.

4. **Algorithm 4: Hybrid Detection System** (`algorithm_4_hybrid.py`)
   - Uses a Graph Attention Network (PyTorch Geometric GAT) combined with structural heuristics for session classification and anomaly scoring ($\theta_a, \theta_r$).

---

## Setup & Installation

### Prerequisites
- Python 3.9+
- CUDA-compatible GPU (recommended for training)

### Environment Setup

```bash
# Clone the repository
git clone https://github.com/jobin2005/CASCE_IMPLEMENTATION.git
cd CASCE_IMPLEMENTATION

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt  # or install torch, torch-geometric, networkx, scikit-learn
```

---

## End-to-End Workflow

### Step 1: Preprocessing & Graph Generation

Run the master pipeline to process raw telemetry in `dataset_dev` and `dataset_test` into enriched `.graphml` graphs under `output/`:

```bash
# Process all runs across dataset_dev and dataset_test
python3 main.py

# Or process a single run directory
python3 main.py dataset_dev/run_1
```

---

### Step 2: Zero-Day Holdout Split Generation

> [!IMPORTANT]
> **Why this step is necessary:**
> `dataset_dev` and `dataset_test` may contain identical attack payloads. A standard train/test split evaluates *re-recognition* rather than *generalization* to unseen attacks.
> `build_holdout_split.py` holds out one or more entire attack families completely from training and validation to measure true zero-day detection capability.
>
> Because `output/` is ignored in Git, this command must be run whenever you set up a fresh environment or change holdout families.

1. **Inspect attack family inventory:**
   ```bash
   python3 build_holdout_split.py --inventory
   ```

2. **Generate the zero-day split (e.g., holding out `Data_Exfiltration`):**
   ```bash
   python3 build_holdout_split.py --holdout-types Data_Exfiltration
   ```

   This writes four label split files per run directory:
   - `labels_train_noheldout.json`: Training set (dev runs 1–42), completely excluding held-out families.
   - `labels_val_noheldout.json`: Validation set (dev runs 43–56), completely excluding held-out families.
   - `labels_test_indist.json`: In-distribution test set (test runs 1–24), excluding held-out families.
   - `labels_heldout_eval.json`: Unseen zero-day evaluation set containing all held-out family sessions across both dev and test sets plus Normal sessions.

---

### Step 3: Model Training

Train the GAT model on the held-out split (`casce_gat_noheldout.pt`):

#### Option A: Quick Bash One-Liner (Recommended)
```bash
python3 algorithm_4_hybrid.py --mode train \
  --train-dir $(eval echo output/dataset_dev/run_{1..42} | tr ' ' ',') \
  --train-labels $(eval echo output/dataset_dev/run_{1..42}/labels_train_noheldout.json | tr ' ' ',') \
  --val-dir $(eval echo output/dataset_dev/run_{43..56} | tr ' ' ',') \
  --val-labels $(eval echo output/dataset_dev/run_{43..56}/labels_val_noheldout.json | tr ' ' ',') \
  --model-path casce_gat_noheldout.pt \
  --epochs 50
```

#### Option B: Full Explicit Command
```bash
python3 algorithm_4_hybrid.py --mode train \
  --train-dir output/dataset_dev/run_1,output/dataset_dev/run_2,output/dataset_dev/run_3,output/dataset_dev/run_4,output/dataset_dev/run_5,output/dataset_dev/run_6,output/dataset_dev/run_7,output/dataset_dev/run_8,output/dataset_dev/run_9,output/dataset_dev/run_10,output/dataset_dev/run_11,output/dataset_dev/run_12,output/dataset_dev/run_13,output/dataset_dev/run_14,output/dataset_dev/run_15,output/dataset_dev/run_16,output/dataset_dev/run_17,output/dataset_dev/run_18,output/dataset_dev/run_19,output/dataset_dev/run_20,output/dataset_dev/run_21,output/dataset_dev/run_22,output/dataset_dev/run_23,output/dataset_dev/run_24,output/dataset_dev/run_25,output/dataset_dev/run_26,output/dataset_dev/run_27,output/dataset_dev/run_28,output/dataset_dev/run_29,output/dataset_dev/run_30,output/dataset_dev/run_31,output/dataset_dev/run_32,output/dataset_dev/run_33,output/dataset_dev/run_34,output/dataset_dev/run_35,output/dataset_dev/run_36,output/dataset_dev/run_37,output/dataset_dev/run_38,output/dataset_dev/run_39,output/dataset_dev/run_40,output/dataset_dev/run_41,output/dataset_dev/run_42 \
  --train-labels output/dataset_dev/run_1/labels_train_noheldout.json,output/dataset_dev/run_2/labels_train_noheldout.json,output/dataset_dev/run_3/labels_train_noheldout.json,output/dataset_dev/run_4/labels_train_noheldout.json,output/dataset_dev/run_5/labels_train_noheldout.json,output/dataset_dev/run_6/labels_train_noheldout.json,output/dataset_dev/run_7/labels_train_noheldout.json,output/dataset_dev/run_8/labels_train_noheldout.json,output/dataset_dev/run_9/labels_train_noheldout.json,output/dataset_dev/run_10/labels_train_noheldout.json,output/dataset_dev/run_11/labels_train_noheldout.json,output/dataset_dev/run_12/labels_train_noheldout.json,output/dataset_dev/run_13/labels_train_noheldout.json,output/dataset_dev/run_14/labels_train_noheldout.json,output/dataset_dev/run_15/labels_train_noheldout.json,output/dataset_dev/run_16/labels_train_noheldout.json,output/dataset_dev/run_17/labels_train_noheldout.json,output/dataset_dev/run_18/labels_train_noheldout.json,output/dataset_dev/run_19/labels_train_noheldout.json,output/dataset_dev/run_20/labels_train_noheldout.json,output/dataset_dev/run_21/labels_train_noheldout.json,output/dataset_dev/run_22/labels_train_noheldout.json,output/dataset_dev/run_23/labels_train_noheldout.json,output/dataset_dev/run_24/labels_train_noheldout.json,output/dataset_dev/run_25/labels_train_noheldout.json,output/dataset_dev/run_26/labels_train_noheldout.json,output/dataset_dev/run_27/labels_train_noheldout.json,output/dataset_dev/run_28/labels_train_noheldout.json,output/dataset_dev/run_29/labels_train_noheldout.json,output/dataset_dev/run_30/labels_train_noheldout.json,output/dataset_dev/run_31/labels_train_noheldout.json,output/dataset_dev/run_32/labels_train_noheldout.json,output/dataset_dev/run_33/labels_train_noheldout.json,output/dataset_dev/run_34/labels_train_noheldout.json,output/dataset_dev/run_35/labels_train_noheldout.json,output/dataset_dev/run_36/labels_train_noheldout.json,output/dataset_dev/run_37/labels_train_noheldout.json,output/dataset_dev/run_38/labels_train_noheldout.json,output/dataset_dev/run_39/labels_train_noheldout.json,output/dataset_dev/run_40/labels_train_noheldout.json,output/dataset_dev/run_41/labels_train_noheldout.json,output/dataset_dev/run_42/labels_train_noheldout.json \
  --val-dir output/dataset_dev/run_43,output/dataset_dev/run_44,output/dataset_dev/run_45,output/dataset_dev/run_46,output/dataset_dev/run_47,output/dataset_dev/run_48,output/dataset_dev/run_49,output/dataset_dev/run_50,output/dataset_dev/run_51,output/dataset_dev/run_52,output/dataset_dev/run_53,output/dataset_dev/run_54,output/dataset_dev/run_55,output/dataset_dev/run_56 \
  --val-labels output/dataset_dev/run_43/labels_val_noheldout.json,output/dataset_dev/run_44/labels_val_noheldout.json,output/dataset_dev/run_45/labels_val_noheldout.json,output/dataset_dev/run_46/labels_val_noheldout.json,output/dataset_dev/run_47/labels_val_noheldout.json,output/dataset_dev/run_48/labels_val_noheldout.json,output/dataset_dev/run_49/labels_val_noheldout.json,output/dataset_dev/run_50/labels_val_noheldout.json,output/dataset_dev/run_51/labels_val_noheldout.json,output/dataset_dev/run_52/labels_val_noheldout.json,output/dataset_dev/run_53/labels_val_noheldout.json,output/dataset_dev/run_54/labels_val_noheldout.json,output/dataset_dev/run_55/labels_val_noheldout.json,output/dataset_dev/run_56/labels_val_noheldout.json \
  --model-path casce_gat_noheldout.pt \
  --epochs 50
```

---

### Step 4: Model Evaluation

Two separate evaluations should be executed and reported:

#### 1. In-Distribution Evaluation (Unseen test sessions of known families)

Using the provided shell script:
```bash
./eval_indist.sh
```

Or directly via CLI:
```bash
python3 algorithm_4_hybrid.py --mode evaluate \
  --input-dir $(eval echo output/dataset_test/run_{1..24} | tr ' ' ',') \
  --labels $(eval echo output/dataset_test/run_{1..24}/labels_test_indist.json | tr ' ' ',') \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_indist
```

#### 2. Held-Out Zero-Day Evaluation (Generalization to unseen attack families)

Using the provided shell script:
```bash
./eval_heldout.sh
```

Or directly via CLI:
```bash
python3 algorithm_4_hybrid.py --mode evaluate \
  --input-dir $(eval echo output/dataset_dev/run_{1..56} output/dataset_test/run_{1..24} | tr ' ' ',') \
  --labels $(eval echo output/dataset_dev/run_{1..56}/labels_heldout_eval.json output/dataset_test/run_{1..24}/labels_heldout_eval.json | tr ' ' ',') \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_heldout
```

#### 3. Detailed Per-Class Evaluation Script

To generate granular multi-class breakdown reports:
```bash
python3 evaluate.py \
  --input-dirs $(eval echo output/dataset_test/run_{1..24} | tr ' ' ',') \
  --label-files $(eval echo output/dataset_test/run_{1..24}/labels.json | tr ' ' ',') \
  --model-path casce_gat_noheldout.pt \
  --outdir eval_detailed
```

---

### Step 5: Model & Algorithm Ablation Suite (M C Role)

To run the complete ablation and validation experiment suite answering "Why does CASCE work?":

```bash
# Run via pipeline orchestrator:
python3 run_pipeline.py --stage ablation

# Or directly:
python3 run_ablation_experiments.py
```

This automates all five core experiments:
1. **Overall CASCE Evaluation**: Precision, Recall, F1, FPR, FNR, Specificity, AUROC, AUPRC, TP/TN/FP/FN, ROC/PR curves, and confusion matrices.
2. **Rules vs. GAT vs. Hybrid**: Validating the necessity of the dual-path hybrid architecture.
3. **Algorithm 3 Ablation**: Measuring detection impact across representation progression: Raw Graph $\rightarrow$ Behavior Abstraction $\rightarrow$ Behavior Abstraction + Chaining.
4. **Fusion Weight Evaluation**: Sweeping $(w_{Rule}, w_{GAT})$ on validation data, resolving the alert crossover issue ($w_{GAT} \ge \theta_A$), and evaluating on test.
5. **Threshold Sensitivity**: Sweeping and selecting alert threshold $\theta_A$ and response threshold $\theta_R$ on validation data, then freezing them for final test evaluation.

---

### Step 6: Detection / Inference Mode

To run streaming or batch anomaly detection on any directory of enriched graphs:

```bash
python3 algorithm_4_hybrid.py --mode detect \
  --input-dir output/dataset_test/run_1 \
  --model-path casce_gat_noheldout.pt \
  --outdir detections/run_1 \
  --theta-a 0.65 \
  --theta-r 0.80
```

---

## Deliverables & Repository Structure

```
├── run_ablation_experiments.py # Master ablation & evaluation experiment suite
├── run_pipeline.py             # End-to-end pipeline orchestrator (stages: graphs, labels, train, eval, ablation)
├── main.py                     # Graph generation pipeline (Algs 1 -> 2 -> 3)
├── algorithm_1.py              # SAC: Session-Anchored Correlation
├── algorithm2.py               # MultiGraph Construction
├── algorithm_3_abstract.py     # Graph Abstraction & Feature Enrichment
├── algorithm_4_hybrid.py       # Hybrid GAT Detector (train / eval / detect / tune)
├── build_holdout_split.py      # Zero-day holdout split generator
├── eval_indist.sh              # In-distribution evaluation script
├── eval_heldout.sh             # Zero-day held-out evaluation script
├── evaluate.py                 # Multi-class metrics & evaluation script
├── casce_gat_noheldout.pt      # Trained GAT model weights (with holdout split)
│
├── casce_results/              # Overall CASCE metrics, summaries, and comparative JSONs
├── main_detection_tables/      # Publication-ready CSV and Markdown performance tables
├── algorithm3_ablation/        # Algorithm 3 ablation CSVs, reports, and bar charts
├── fusion_results/             # Validation weight sweeps, crossover analysis, and heatmaps
├── threshold_results/          # Threshold sweeps, sensitivity plots, and freezing protocol
├── confusion_matrices/         # Confusion matrix plots and JSON data (CASCE, Rules, GAT, Hybrid)
├── ROC_PR_curves/              # High-resolution ROC and PR curve plots and raw curve points
└── seed_results/               # Random seed model weights and stability records
```
