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

- **Real-time daemon.** `realtime_daemon.py` follows the two log files live, re-scores running sessions every 2 s and writes `alerts.jsonl` / `session_scores.jsonl`. With `--replay` it re-scores a recorded capture; replay reproduces live verdicts exactly. Scoring is single-threaded (`--threads 1`, the default), which matters: torch's default of one thread per core made scoring about 5× slower. One daemon handles about 8 new sessions/s; alert latency is a median 1.6 s.
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
| `casce_gat_v3p_ens2.json` | **Recommended deployment model**: ensemble of two v3P models (`casce_gat_v3p.pt`, `casce_gat_v3p_s7.pt`; average of their GAT probabilities). Use it as `--model-path casce_gat_v3p_ens2.pt` (θ = 0.55, in the json) |
| `casce_gat_v3p.pt`, `casce_gat_v3p_s7.pt` (+ `.json`) | v3P: feature v3, trained with the extra benign templates and live-captured benign traffic (two seeds) |
| `casce_gat_v2.pt`, `casce_gat_v3.pt` (+ `.json`) | Models trained on the E1 split only, feature v2 and v3. v3 is the model evaluated for generalization. `casce_gat.pt` is the legacy v1 baseline |
| `workload_simulation/run_full_live.sh`, `workload_simulation/live_compare.py` | One complete live experiment (capture + workload + one or more daemons scoring in real time) and a side-by-side comparison of the daemons |
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

# a complete live experiment: capture on, daemons for several models scoring in real time, workload, capture off
bash workload_simulation/run_full_live.sh my_run casce_gat_v3p.pt,casce_gat_v3.pt --class all --pgbench \
    --specs 'dataset_test/run_*/specs/*.yaml'
python3 workload_simulation/live_compare.py live_runs/my_run daemon_v3p_live daemon_v3_live

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
| **Unseen templates**, v3 features (T) | Same folds, 3 seeds | Recall 0.79, FPR 0.33, F1 **0.73 ± 0.12**, ROC-AUC 0.66. A modest gain over v2 (the 1-seed 0.83 was optimistic); 4 of 7 unseen attack templates perfect in most seeds; unseen benign ETL/audit jobs remain the main error |
| **v3, seen templates + live** | Single v3 model trained like v2; E1 test and replays of live runs 4a–5b | Identical to v2: F1 1.0 offline; 5b TP 93, FP 0, FN 0, TN 1,158; live = synthetic for 226/226 |
| **Live, unseen benign workloads** (6_full) | 2,801 live sessions incl. 240 of 6 benign templates no model had seen; v3 scoring live | False alarms on the unseen templates: v2 **94/240**, v3 **17/240** (all 17 = benign data sent to non-approved external hosts); attacks 93/93 for both |
| **Final live run, real time** (8_final) | 1,999 live sessions; v2, v3, v3P all scoring live, same traffic | Attacks 93/93 (56/56 executed) for all; FPR v2 2.4%, v3 0.42%, **v3P 0.16%**; F1 0.80 / 0.96 / **0.98**; alert latency median **1.6 s**, max 3.1 s |
| **Load test** (9_load) | 4,868 pgbench sessions at 8/s for 10 min, v3P live | All scored, 0 false alarms, final-score lag p99 6.9 s, stable memory (~800 MB) |
| **Fresh live confirmation** (10_confirm) | 1,115 live sessions of fresh, never-used scenario instances; v3, v3P, ensemble scoring live | Ensemble and v3P: attacks **57/57**, false alarms **0/1,058**, F1 **1.0**, latency median 1.66 s (ensemble), max 3.2 s; v3: 2 false alarms |

**What these numbers mean.** On attack types it was trained on, CASCE is near-perfect, offline and live, with no false alarms. On attack types it has never seen, it generalises only partly. The main failure is mistaking unseen *legitimate* data movement (ETL replication, audits) for attacks. Feature v3, which describes behaviour instead of exact SQL strings, paths and names, helps: modestly on unseen *templates* offline (F1 0.67 → 0.73), and strongly on unseen *benign workloads* live (false alarms 94 → 17 of 240). Adding the bank's normal workloads to training (v3P), and averaging two v3P models, gives every attack detected with no false alarms on fresh live traffic.

## Open work

- **3-model ensemble:** a third v3P seed (13) is evaluated automatically when its training finishes (`live_eval_ensemble/casce_gat_v3p_ens3/`).
- **Live 4D:** run unseen attacks and benign workload on the live database. The environment is ready and verified.
- **Unsolved case:** distinguishing malicious from benign ETL replication when neither was seen in training.
- **Known limitations** (see EXPERIMENTS.md): three rule types can never fire; single banking domain only.
