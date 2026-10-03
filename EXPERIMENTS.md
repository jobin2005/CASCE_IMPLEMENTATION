# CASCE experiments: E1 and the priv_abuse holdout

This file records which experiments were run, how to reproduce them and what they showed. It also covers how far the results can be trusted. The run date and status are given for each experiment.

All commands use the system `python3` (torch 2.11, torch_geometric 2.8, scikit-learn 1.9) and run from the repo root.

## Status

| # | Experiment | Status | Output |
|---|---|---|---|
| E1 | `casce_gat_v2`: train, tune θ on validation, test on `dataset_test` | Run on Sep 30–Oct 1. **Reproduced exactly** on Oct 2 (sweep and test JSON identical) | `casce_gat_v2.{pt,json}`, `tune_out_v2/`, `eval_test_report_v2/` |
| E1-live | v2 on live captures 4a, 4b, 4c, 5a (replays) and 5b_mixed (live) | Run on Oct 1. The 5b evaluation was **written to disk on Oct 2** | `live_runs/*/daemon_v2/`, `live_runs/5b_mixed/eval_v2.txt` |
| H1 | Leave-one-template-out: `banking_priv_abuse` removed from train, val and prefixes | Trained Oct 1. **Evaluated Oct 2**, after the earlier session ended before evaluation | `casce_gat_holdout_priv_abuse.{pt,json}`, `tune_out_holdout_priv_abuse/`, `eval_test_report_holdout_priv_abuse/` |
| H1-live | Holdout model on the 5b_mixed live capture (replay) | Run Oct 2 | `live_runs/5b_mixed/daemon_holdout_priv_abuse/`, `live_runs/5b_mixed/eval_holdout_priv_abuse.txt` |
| S | Seed variance for v2 and H1 (original seed 42 + retrained seeds 1, 2) | Run Oct 2 | `models_seeds/*.report.json`, `models_seeds/seed_summary.json` |
| L | Train/test overlap diagnostics | Run Oct 2 | `eval_test_report_v2/leakage_report.json` |
| **T** | **Template-disjoint evaluation (LOTO)**: 7 folds × 3 seeds, each testing on a malicious and a benign template never seen in training or validation | Run Oct 2–3, all 21 runs complete | `loto/folds.json`, `loto/*_s*.report.json`, `loto/loto_summary.json`, `loto/INTERIM_RESULTS.md` |
| 4D | Live test on attacks/benign traffic that are not datagen templates | **Environment ready and verified (Oct 3, `live_runs/4d_smoke`); the out-of-distribution workload itself has not been run yet** | `live_runs/4d_smoke/` |

## Data and splits

- **Synthetic corpus.** It comes from `datagen/generate_batch.py`: 13 banking templates, 7 malicious and 6 benign.
  - `dataset_dev`: 40 runs, 900 sessions, generator seed 42.
  - `dataset_test`: 10 runs, 226 sessions, 93 of them malicious, generator seed 123.
  - Neither seed is stored with the data. Both were recovered by regenerating the run-001 scenario ids.
- **Split** (`prepare_algo4_dataset.py`, seed 42, `dataset_dev/algo4_splits/split_metadata.json`).
  - "family_aware" groups by scenario **instance** (`<template>_<NNNN>`), not by template.
  - Dev instances whose id also appears in test are dropped.
  - Result: train has 308 graphs (180 malicious), val has 67 (26 malicious), test has 226 (93 malicious).
  - No session or instance is shared between splits. **Every template appears in train, val and test.**
- **Training extras** in `training_v2/`, git-ignored:
  - Prefix graphs of the train and val sessions (`dev_train_prefixes`: 924; `dev_val_prefixes`: 201).
  - 60 pgbench sessions each from the live captures `train_pgbench_1` (train) and `train_pgbench_2` (val), 240 graphs each, all benign.
- **Holdout labels.** Produced by `make_holdout_labels.py`, which drops every graph of the family: full sessions, prefixes and benign padding prefixes.
  - Train: 1364 graphs (306 malicious). Val: 500 graphs (48 malicious).
  - `leakage_report.py` re-checks this and asserts that no priv_abuse graph remains.

### Regenerating `training_v2/`
These commands were reconstructed from `index.jsonl`; the original command lines were not recorded. Verify the counts match after running them.
```
python3 build_training_graphs.py --runs dataset_dev/run_* --only dataset_dev/algo4_splits/train_labels.json --out-dir training_v2/dev_train_prefixes --no-full
python3 build_training_graphs.py --runs dataset_dev/run_* --only dataset_dev/algo4_splits/val_labels.json   --out-dir training_v2/dev_val_prefixes --no-full
python3 build_training_graphs.py --runs live_runs/train_pgbench_1 --max-sessions 60 --out-dir training_v2/pgbench_train
python3 build_training_graphs.py --runs live_runs/train_pgbench_2 --max-sessions 60 --out-dir training_v2/pgbench_val
python3 make_holdout_labels.py --family banking_priv_abuse --dataset-root dataset_dev \
    --in dataset_dev/algo4_splits/train_labels.json dataset_dev/algo4_splits/val_labels.json \
         training_v2/dev_train_prefixes/labels.json training_v2/dev_val_prefixes/labels.json \
    --out-dir training_v2/holdout_priv_abuse
```

## Model and scoring
- **Feature version 2** (pid-free) GAT: 2× HeteroConv(GATv2, 4 heads × 32), per-node-type mean pool, MLP.
- **Training:** seed 42, Adam 1e-3, batch 1, up to 50 epochs, early stopping on validation BCE with patience 5.
- **Score:** Algorithm 4 risk is a noisy-OR of the rule score and the GAT probability: `1-(1-0.75·rule)(1-0.75·gat)`.
- **Threshold:** θ_A is tuned on **validation** only, as the middle of the tied-best-F1 range.

## E1: `casce_gat_v2` (all 13 templates seen in training)
```
python3 algorithm_4_hybrid.py --mode train --feature-version 2 --seed 42 --epochs 50 \
  --train-dir dataset_dev/enriched_graphs/graphml,training_v2/dev_train_prefixes/graphml,training_v2/pgbench_train/graphml \
  --train-labels dataset_dev/algo4_splits/train_labels.json,training_v2/dev_train_prefixes/labels.json,training_v2/pgbench_train/labels.json \
  --val-dir dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml \
  --val-labels dataset_dev/algo4_splits/val_labels.json,training_v2/dev_val_prefixes/labels.json,training_v2/pgbench_val/labels.json \
  --model-path casce_gat_v2.pt
python3 algorithm_4_hybrid.py --mode tune --model-path casce_gat_v2.pt --input-dir <val dirs above> --labels <val labels above> --outdir tune_out_v2
python3 algorithm_4_hybrid.py --mode evaluate --model-path casce_gat_v2.pt --input-dir dataset_test/enriched_graphs/graphml \
  --labels dataset_test/algo4_splits/test_labels.json --theta-a 0.55 --outdir eval_test_report_v2
```

| Set | n (malicious) | θ | P | R | F1 | Acc | FPR |
|---|---|---|---|---|---|---|---|
| Validation sweep | 508 (52) | F1 = 1.0 for every θ in 0.30–0.75; 0.55 chosen | | | | | |
| Test (synthetic) | 226 (93) | 0.55 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |
| Live 5b_mixed, final verdict | 1251 (93): 1025 pgbench, 133 benign scenarios | 0.55 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |

On 5b_mixed, live and synthetic agree on all 226/226 scenario sessions (mean |Δrisk| 0.002). Real-time alerts reached recall 1.0 with a median latency of 1.73 s. For comparison, v1 (`casce_gat.pt`, θ 0.40) replayed on 5b gave FPR 0.905.

## H1: priv_abuse held out (leave-one-template-out)
Training used the same command as E1 with the label files from `training_v2/holdout_priv_abuse/*` (pgbench labels unchanged) and `--model-path casce_gat_holdout_priv_abuse.pt`. The evaluation commands were:
```
python3 algorithm_4_hybrid.py --mode tune --model-path casce_gat_holdout_priv_abuse.pt \
  --input-dir dataset_dev/enriched_graphs/graphml,training_v2/dev_val_prefixes/graphml,training_v2/pgbench_val/graphml \
  --labels training_v2/holdout_priv_abuse/algo4_splits__val_labels.json,training_v2/holdout_priv_abuse/dev_val_prefixes__labels.json,training_v2/pgbench_val/labels.json \
  --outdir tune_out_holdout_priv_abuse                          # -> θ = 0.55 (F1 = 1.0 for θ 0.30–0.75)
python3 algorithm_4_hybrid.py --mode evaluate --model-path casce_gat_holdout_priv_abuse.pt \
  --input-dir dataset_test/enriched_graphs/graphml --labels dataset_test/algo4_splits/test_labels.json \
  --theta-a 0.55 --outdir eval_test_report_holdout_priv_abuse
python3 holdout_report.py --family banking_priv_abuse --theta 0.55 \
  --model holdout=casce_gat_holdout_priv_abuse.pt --model v2=casce_gat_v2.pt \
  --out eval_test_report_holdout_priv_abuse/holdout_report.json
python3 realtime_daemon.py --replay --replay-realtime --log-dir live_runs/5b_mixed --model-path casce_gat_holdout_priv_abuse.pt \
  --theta-a 0.55 --out-dir live_runs/5b_mixed/daemon_holdout_priv_abuse
python3 workload_simulation/evaluate_live.py --run-dir live_runs/5b_mixed --theta 0.55 --compare-synthetic \
  --scores live_runs/5b_mixed/daemon_holdout_priv_abuse/session_scores.jsonl \
  --alerts live_runs/5b_mixed/daemon_holdout_priv_abuse/alerts.jsonl --model-path casce_gat_holdout_priv_abuse.pt
```

Test results at θ = 0.55, single seed (42):

| Subset | Model | n (malicious) | P | R | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| All test | holdout | 226 (93) | 1.000 | 0.925 | 0.961 | 0.000 | 0.993 | 0.992 |
| **Unseen priv_abuse vs all benign** | holdout | 149 (16) | 1.000 | **0.562** | 0.720 | 0.000 | 0.959 | 0.876 |
| Seen templates only | holdout | 210 (77) | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| priv_abuse vs benign (reference: template seen) | v2 | 149 (16) | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |

- **Detection rate.** 9 of 16 unseen priv_abuse sessions are flagged. Their risk ranges from 0.26 to 0.73 (median 0.56). When the template was seen in training, every session scores exactly 0.75.
- **The GAT ranks the unseen family perfectly; the fused risk does not.** On the GAT probability alone, priv_abuse vs benign has ROC-AUC 1.0, with a margin of 0.33 over the highest benign GAT score. The rule score is 0 for every priv_abuse graph. Benign ETL sessions, however, carry a rule score (`Ingress tool transfer`), which puts their fused risk at 0.29–0.30. That sits above the 5 lowest-scoring priv_abuse sessions, so the AUC on fused risk drops to 0.959. All 7 misses are priv_abuse sessions with risk between 0.26 and 0.47.
- **Live 5b_mixed (replay).** Final-verdict results are identical to synthetic: priv_abuse 9 of 16, all other families 100%, and 0 false positives on 1158 benign sessions (1025 pgbench). In the real-time view, 14 of 16 priv_abuse sessions alert at some point. 5 of those reach risk 0.75 partway through the session, around the `CREATE ROLE` step, then fall below θ once the session completes. The final verdict is the primary metric.
- **Seed variance (see S):** the 9/16 above comes from one seed. Retrained with seeds 1 and 2, the holdout model detects **16/16** priv_abuse sessions. However, it then misses 7/14 and 14/14 sessions of the *seen* template `etl_exfil_mal`. Retraining with seed 42 is **not bit-reproducible**: at epoch 4 the original logged val_loss 0.0030 and the rerun 0.0005.

### What the holdout does and does not show (see `leakage_report.json` → `holdout`)
- No priv_abuse graph is in the holdout train or val data. No test priv_abuse graph has the same normalized SQL sequence as any holdout-train graph.
- 5 of priv_abuse's 8 normalized statements never occur in holdout training: `CREATE ROLE svc_shadow|dba_maint|admin_backup SUPERUSER …`, the `pg_authid` rolpassword dump, and the `national_id` select.
- The **patterns** are still covered by kept templates:
  - `CREATE ROLE … SUPERUSER` and a `pg_authid` dump in `multi_apt` (19 train graphs).
  - `ALTER ROLE … SUPERUSER` in `alter_role_esc` (19).
  - `pg_authid` reads in the benign `dba_shadow_audit` (15).
- H1 therefore measures generalization to an unseen **template** whose individual steps resemble seen malicious ones. It does not show detection of an entirely new privilege-escalation technique. Removing every escalation template was considered and not done, per the project decision for this round.
- In the live captures, every priv_abuse `CREATE ROLE` was denied by Postgres, because the session runs as `teller`. Only the attempt is visible.

## Why the E1 1.0 is in-distribution (from `leakage_report.json`)
- There is no direct leakage: no shared graph or session, and θ was tuned on validation.
- The test set still re-instantiates the training templates:
  - The test set contains no template that is absent from train.
  - 108/226 test graphs (71/93 malicious) have a train graph with an **identical SQL sequence**.
  - With quoted literals and numbers masked, that rises to 153/226, including **all 93 malicious graphs**.
- Feature v2 hashes template-specific strings into node features: SQL text, file paths, curl command lines, role names and IPs.
  - Role nodes occur **only** in malicious graphs (96 of them).
  - All role names and the malicious file paths are class-exclusive.
  - Validation loss reaches ~0 within 5–8 epochs.
- The live sessions replay the same `dataset_test` specs. pgbench was added to training after v1 flagged every pgbench session. Live 1.0 therefore also tests seen distributions; the new information it adds is that live capture reproduces synthetic scores (Δ 0.002).
- Rules alone never reach θ. Decisions come from the GAT, which caps risk at 0.75 when rules are silent.

**Reportable claim:** detection of re-instantiated known templates, including live capture under heavy benign pgbench load, with no false positives. The single-seed 1.0 is not stable across retraining; see **S** for the multi-seed figures.

## Known issues (reported, not changed: changing them would alter the method)
- **Dropped edges.** `('Query','spawns','Process')` and `('Query','accesses','Role')` are missing from `FORWARD_EDGE_TYPES` and are dropped at load (`algorithm_4_hybrid.py` ~466). As a result, Process and Role nodes receive no messages from queries.
- **Recency feature.** It mixes kernel nanosecond timestamps with Postgres epoch seconds.
- **Rules that never fire.** ACCOUNT_MANIPULATION, OS_CREDENTIAL_DUMPING and INDICATOR_REMOVAL never fire, because Algorithm 2 never emits `modifies` edges or Configuration nodes.
- **Threshold defaults (fixed Oct 2).** `--mode tune` now writes θ_A into the model's sidecar JSON. `--mode evaluate`, `realtime_daemon.py` and `evaluate_live.py` read it and refuse to run without one, so v1's 0.40 can no longer be applied to v2 by accident. `--feature-version` still defaults to 1 for training; pass 2.
- **4D environment (set up Oct 3).** The local `casce_environment` container now runs the repo's current telemetry. All earlier files were archived, not deleted:
  - `pg_telemetry.c` is built and installed. It needed `libkrb5-dev` for the GSSAPI headers. The old August build is kept at `/root/pg_telemetry.so.aug28.bak`.
  - The current `logger.sh` and `ebpf_telemetry/kernel_telemetry.py` are installed in `~/Desktop/Projects/CASCE_DATASET`. The old August capture and logger are in its `archive/aug28_old_capture/`.
  - `pgbench_history` was recreated, and `iproute2` was installed.
  - **Verified end to end** (`live_runs/4d_smoke`): one labelled benign `COPY … TO PROGRAM gzip` session plus 22 pgbench sessions. The kernel trace linked `gzip` to its backend through the ppid. All 23 sessions were scored by the v2 replay, giving FPR 0. θ was read from the model sidecar.
- **Stale scripts.** These target an old data layout and naming scheme. Do not use them for results:
  - `evaluate_holdout_experiment.py`: v1 features, a nonexistent `datagen/generated/banking_1000`, and early stopping on the held-out family.
  - `test_zeroday_holdout.py`.
  - `run_pipeline.py`.
  - `undersample.py`.
  - The per-class filename parsing in `evaluate.py`.
- **Legacy material.** `workload_simulation/attack_workload/*.sh` and `README_REALTIME.md` are legacy and were not used in any recorded run.

## S: seed variance
`./run_seed.sh <v2|holdout_priv_abuse> <seed>` runs train → tune θ on val → `holdout_report.py`, writing to `models_seeds/`. `python3 seed_summary.py --out models_seeds/seed_summary.json` then collects the results.

Training is not deterministic, even with a fixed seed: CPU scatter ops are nondeterministic, and the torch build differs from the original machine. The "42 (original)" rows are the committed checkpoints. Seeds 1 and 2 were retrained on Oct 2 with `OMP_NUM_THREADS=3`. In every run θ came out as 0.55, with F1 = 1.0 on validation for every θ from 0.30 to 0.75.

| Config | Seed | All-test R | All-test F1 | All-test ROC-AUC | FPR | priv_abuse detected | etl_exfil_mal detected |
|---|---|---|---|---|---|---|---|
| v2 (all templates seen) | 42 (original) | 1.000 | 1.000 | 1.000 | 0.000 | 16/16 | 14/14 |
| | 1 | 0.935 | 0.967 | 1.000 | 0.000 | 16/16 | 8/14 |
| | 2 | 0.979 | 0.989 | 1.000 | 0.000 | 16/16 | 12/14 |
| | **mean ± std** | **0.971 ± 0.033** | **0.985 ± 0.017** | 1.000 | 0.000 | 1.000 | 0.81 ± 0.21 |
| holdout (priv_abuse unseen) | 42 (original) | 0.925 | 0.961 | 0.993 | 0.000 | 9/16 | 14/14 |
| | 1 | 0.925 | 0.961 | 1.000 | 0.000 | 16/16 | 7/14 |
| | 2 | 0.850 | 0.919 | 1.000 | 0.000 | 16/16 | 0/14 |
| | **mean ± std** | **0.900 ± 0.043** | **0.947 ± 0.024** | 0.998 | 0.000 | **0.85 ± 0.25** | 0.50 ± 0.50 |

What the seed runs show:
1. **E1's perfect test score holds for one seed only.** Across 3 seeds, v2 reaches test F1 0.985 ± 0.017. ROC-AUC is 1.0 and precision is 1.0 in every run.
2. **The errors come from calibration, not ranking.** Every miss in every run is a malicious session scored between 0.26 and 0.55. The model ranks it above every benign session (AUC ≈ 1), but the validation-tuned θ = 0.55 sits above it. The affected sessions are always `etl_exfil_mal`, plus priv_abuse for the original holdout checkpoint. Benign `etl_repl_ben` scores about 0.30, so the margin is narrow.
3. **Why `etl_exfil_mal` is affected.** It is a *seen* template, but it has only 2 graphs in train and **none in validation**: the split dropped the instances whose ids collide with test. Validation therefore cannot place θ for it, and test has 14 of them. This is a split artefact. Detecting it is effectively close to unseen-template generalization.
4. **Unseen priv_abuse.** Recall is 0.85 ± 0.25 (9/16, 16/16, 16/16), with FPR 0 and ROC-AUC ≥ 0.959 in every run. That is strong ranking but unstable detection at the tuned θ. Report the mean ± std and the per-seed values, not a single number.
5. Three seeds is the minimum. Running seeds 3 and 4 for both configs (about 1 h per pair on 16 cores) would tighten the estimates.

**Reportable claims, revised.**
- Known templates: test F1 0.985 ± 0.017, precision 1.0, FPR 0, ROC-AUC 1.0 (3 seeds). Live capture reproduces synthetic scores. The single-seed 1.0 should not be quoted on its own.
- Unseen priv_abuse template: recall 0.85 ± 0.25 at the validation-tuned θ, with zero false positives and ROC-AUC ≥ 0.96. The kept templates cover the same SQL patterns (see above).

## T: template-disjoint evaluation (leave-one-template-out)
This is the test of whether the model detects **behaviour it has never seen**, rather than new seeds of templates it was trained on.
- **Fold design.** `make_template_folds.py` builds 7 folds (`loto/folds.json`), one per malicious template. Each fold has:
  - **Test:** that malicious template plus one benign template, neither seen in training or validation. All of their sessions from `dataset_dev` and `dataset_test` are used.
  - **Validation:** a *different* malicious template plus a different benign template. It drives early stopping and θ.
  - **Training:** the remaining 5 malicious and 4 benign templates, with prefix graphs and pgbench, using the same method and settings as v2.
- **Runs:** each fold was run with 3 seeds. `./run_loto.sh <fold> <seed>` does one run; `loto/run_all.sh` resumes whatever is missing; `python3 loto_summary.py` produces the table.

| Unseen attack template | Recall | FPR (unseen benign) | F1 | ROC-AUC | F1 on seen templates |
|---|---|---|---|---|---|
| alter_role_esc | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 | 0.725 ± 0.072 |
| priv_abuse | 1.000 ± 0.000 | 0.157 ± 0.176 | 0.892 ± 0.110 | 0.964 ± 0.063 | 1.000 |
| compliance_exfil | 0.667 ± 0.577 | 0.000 ± 0.000 | 0.667 ± 0.577 | 1.000 | 0.946 ± 0.093 |
| teller_pii_dump | 0.951 ± 0.049 | 0.667 ± 0.577 | 0.664 ± 0.270 | 0.667 ± 0.577 | 0.939 ± 0.094 |
| etl_exfil_mal | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.667 ± 0.000 | 0.000 (degenerate) | 0.878 ± 0.022 |
| defense_impair | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.654 ± 0.000 | 0.000 (degenerate) | 1.000 |
| multi_apt | 0.111 ± 0.192 | 0.000 ± 0.000 | 0.167 ± 0.289 | 0.667 | 0.845 ± 0.036 |
| **Macro (3 seeds)** | **0.818 ± 0.104** | **0.403 ± 0.058** | **0.673 ± 0.128** | **0.614 ± 0.078** | |

Pooled confusion matrices (unseen test, all folds):

| Seed | TN | FP | FN | TP |
|---|---|---|---|---|
| 1 | 475 | 288 | 182 | 326 |
| 2 | 574 | 189 | 68 | 440 |
| 3 | 469 | 294 | 96 | 412 |

### What T shows
1. **Generalization to unseen behaviour is weak.** F1 falls from 0.985 on seen templates (E1, 3 seeds) to **0.673 ± 0.128**. ROC-AUC falls to **0.61**.
2. **The false-positive rate on unseen benign behaviour is 0.40.** This is the largest problem. Benign templates that move data out or read sensitive data in bulk are flagged when they were absent from training: ETL replication, internal ETL and compliance audit.
   - In the ETL and defense_impair folds the GAT saturates (0 or 1) for both classes. The rule score alone then orders the sessions, which gives the degenerate ROC-AUC of 0.0.
   - In one teller_pii_dump run the benign audit scored *above* the attack (GAT ROC-AUC 0.0). That is a true inversion.
3. **Unseen attacks that share key steps with training attacks are detected.** These are `alter_role_esc` and `priv_abuse` (`CREATE/ALTER ROLE … SUPERUSER`, `pg_authid`). The unseen multi-stage APT is mostly missed (recall 0.11).
4. **θ does not transfer between unseen templates.** `compliance_exfil` is ranked perfectly in every seed, yet one seed missed all 78 attacks because θ, tuned on another unseen template, sat above them. Calibrating on validation cannot fix a scale shift that differs by template.
5. **Validation loss rises from epoch 1–2** in most folds. Fitting the training templates harder makes unseen templates worse: shortcut learning.
6. **Results vary strongly across seeds** (std up to 0.58). Single-seed unseen-template numbers are not reliable.

## Final reportable claims (as of Oct 3)
- **Seen templates:** F1 0.985 ± 0.017, precision 1.0, FPR 0, ROC-AUC 1.0 (3 seeds). These are new instances of the 13 training templates.
- **Live capture:** reproduces the synthetic scores (226/226 identical verdicts) with 0 false alarms over 1158 benign live sessions, including pgbench load. These sessions also use the same templates.
- **Unseen templates (T):** recall 0.82 ± 0.10, FPR 0.40 ± 0.06, F1 0.67 ± 0.13, ROC-AUC 0.61 ± 0.08 (7 folds × 3 seeds).
  - **This is the honest generalization result.** The detector recognises known attack patterns well but does not reliably generalize to unseen behaviour. In particular it mistakes unseen benign data-movement for attacks.
- **Priv_abuse held out:** recall 1.0, FPR 0.16 ± 0.18 on unseen benign `teller_routine` (T fold). The template is unseen, but its key SQL steps occur in other training attacks.
- **Next step (P3, a method change; decide before implementing):** run a feature ablation that masks SQL literals, paths and role names, fixes the recency units and adds the dropped edge types. Evaluate it on these same folds, so any change in the T numbers can be attributed to the features.

