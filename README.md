# CASCE: cross-layer threat detection for PostgreSQL

CASCE (Context-Aware Semantic Correlation Engine) detects attacks on a PostgreSQL database by combining two views of each database session:
- **what the session did in SQL**, captured by a Postgres executor hook;
- **what it caused in the operating system** (programs started, files opened, network connections), captured with eBPF.

Each session becomes a small heterogeneous graph. A rule engine and a heterogeneous graph attention network (GATv2) score that graph, and an alert is raised when the risk crosses a threshold θ. The system runs offline on recorded logs and in real time on a live database.

**Detailed results, exact commands and known limitations are in [EXPERIMENTS.md](EXPERIMENTS.md).** Instructions for coding agents generating data are in [.agents/skills/casce-datagen/SKILL.md](.agents/skills/casce-datagen/SKILL.md).

## Pipeline

```
postgres_events.json (SQL hook) + kernel_events.json (eBPF)
        │
        ▼  Algorithm 1  algorithm_1.py         session correlation: kernel events → session via the ppid chain; one clock
        ▼  Algorithm 2  algorithm2.py          one graph per session: Session, Query, Table, Role, Process, File, Endpoint
        ▼  Algorithm 3  algorithm_3_abstract.py   behaviour nodes (MITRE ATT&CK-style): data access, shell, external transfer, …
        ▼  Algorithm 4  algorithm_4_hybrid.py     rules + HeteroGATv2 → risk = 1 − (1 − 0.75·rule)(1 − 0.75·gat); alert if risk ≥ θ
```

- **Real-time daemon.** `realtime_daemon.py` follows the two log files live, re-scores running sessions every 2 s and writes `alerts.jsonl` / `session_scores.jsonl`. With `--replay` it re-scores a recorded capture.
- **Threshold.** θ is tuned on validation data and stored in each model's sidecar JSON. Evaluation and the daemon read it from there.

## Repository layout

| Path | Contents |
|---|---|
| `algorithm_1.py`, `algorithm2.py`, `algorithm_3_abstract.py`, `algorithm_4_hybrid.py` | The four algorithms. `algorithm_4_hybrid.py --mode train/tune/evaluate/detect` |
| `schema.py`, `sqlfacts.py`, `graphsops.py`, `loader.py`, `main.py` | Graph schema, SQL fact extraction, graph helpers; `main.py` builds the enriched graphs of `dataset_dev`/`dataset_test` |
| `build_training_graphs.py` | Full-session and prefix (partial-session) graphs for any runs, synthetic or live |
| `datagen/` | Spec-driven synthetic data generator (`generate_batch.py`, `codegen.py`, `validate_run.py`), banking domain model, spec docs |
| `dataset_dev/`, `dataset_test/` | Synthetic banking corpus: 900 / 226 sessions, 13 scenario templates (7 attack, 6 benign) |
| `dataset_benign_extra/` | 240 sessions of 6 extra benign templates, used for training only |
| `prepare_algo4_dataset.py` | Instance-level train/val/test split (E1) |
| `make_template_folds.py`, `run_loto.sh`, `fold_report.py`, `loto_summary.py`, `loto/` | **Template-disjoint evaluation**: 7 folds, each testing on attack and benign templates never seen in training |
| `make_holdout_labels.py`, `holdout_report.py`, `leakage_report.py`, `run_seed.sh`, `seed_summary.py` | priv_abuse holdout, train/test overlap diagnostics, seed variance |
| `realtime_daemon.py`, `workload_simulation/` | Real-time detection; live capture (`pg_telemetry.c`, `kernel_telemetry.py`, `logger.sh`), live scenario runner, live evaluation |
| `casce_gat_v2.pt` (+ `.json`) | Current model (feature v2, θ = 0.55). `casce_gat.pt` is the legacy v1 baseline |
| `loto*/`, `models_seeds/`, `eval_test_report_*/`, `tune_out_*/` | Result files referenced in EXPERIMENTS.md |

## Quick start

The tested setup is Python 3.14 with torch 2.11, torch_geometric 2.8, networkx, pglast, scikit-learn and pyyaml.

```bash
# evaluate the current model on the synthetic test set (θ read from casce_gat_v2.json)
python3 algorithm_4_hybrid.py --mode evaluate --model-path casce_gat_v2.pt \
    --input-dir dataset_test/enriched_graphs/graphml --labels dataset_test/algo4_splits/test_labels.json \
    --outdir eval_out

# one template-disjoint fold (train → tune θ on validation templates → test on unseen templates)
./run_loto.sh priv_abuse 1                 # v2 features
FV=3 OUT=loto_v3_f1 ./run_loto.sh priv_abuse 1   # v3 features

# score a recorded live capture with the real-time daemon, then evaluate it against its labels
python3 realtime_daemon.py --replay --log-dir live_runs/<run> --model-path casce_gat_v2.pt --out-dir live_runs/<run>/daemon
python3 workload_simulation/evaluate_live.py --run-dir live_runs/<run> \
    --scores live_runs/<run>/daemon/session_scores.jsonl --model-path casce_gat_v2.pt
```

The live setup (Docker container, Postgres hook, eBPF tracer, banking database) is described in `workload_simulation/` and in EXPERIMENTS.md → "4D environment".

## Results so far

All data is synthetic banking traffic. Full tables, per-template results and caveats are in EXPERIMENTS.md.

| Evaluation | What is tested | Result |
|---|---|---|
| **Seen templates** (E1) | New instances of the 13 training templates | F1 **0.985 ± 0.017** (3 seeds), precision 1.0, FPR 0 |
| **Live, mixed traffic** (5b) | 1,251 live sessions: 1,025 pgbench + 133 benign + 93 attacks, same templates | TP 93, FP 0, FN 0, TN 1,158; alerts after a median 1.7 s; live verdicts identical to synthetic for 226/226 sessions |
| **Unseen templates**, v2 (T) | 7 folds × 3 seeds; test templates never seen in training | Recall 0.82, FPR 0.40, F1 **0.67 ± 0.13**, ROC-AUC 0.61 |
| **Unseen templates**, v3 features (provisional) | Same folds, 1 seed | Recall 0.91, FPR 0.29, F1 **0.83**. 4 of 7 unseen attack templates are perfect. **Still to be confirmed** on more seeds and the live 4D test |

**What these numbers mean.** On attack types it was trained on, CASCE is near-perfect, offline and live, with no false alarms. On attack types it has never seen, it generalises only partly. The main failure is mistaking unseen *legitimate* data movement (ETL replication, audits) for attacks. Feature v3, which describes behaviour instead of exact SQL strings, paths and names, is the most promising fix so far.

## Open work

- **Confirm v3:** seeds 2–3 for the template-disjoint folds.
- **Live 4D:** run unseen attacks and benign workload on the live database. The environment is ready and verified.
- **Unsolved case:** distinguishing malicious from benign ETL replication when neither was seen in training.
- **Known limitations** (see EXPERIMENTS.md): three rule types can never fire; single banking domain only.
