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
| **T** | **Template-disjoint evaluation (LOTO)**: 7 folds × 3 seeds, each testing on a malicious and a benign template never seen in training or validation | Run Oct 2–3, all 21 runs complete | `loto/folds.json`, `loto/*_s*.report.json`, `loto/loto_summary.json` |
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
- **Stale scripts (removed Oct 3).** `evaluate.py`, `evaluate_holdout_experiment.py`, `test_zeroday_holdout.py`, `run_pipeline.py` and `undersample.py` targeted an old data layout and file-naming scheme (e.g. v1 features, the nonexistent `datagen/generated/banking_1000`, early stopping on the held-out family). Their replacements are `algorithm_4_hybrid.py --mode evaluate`, `holdout_report.py` and `fold_report.py`. The old v1 result folders (`eval_test_report*`, `tune_out`, `tune_out_recovered`) were removed too. Everything is in git history (e.g. commit 9593f8fc).
- **Legacy material.** `workload_simulation/attack_workload/*.sh` (hand-written attacks, not datagen templates) were not used in any recorded run; they are the candidate workload for the live 4D test.

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


## v3: fixes 1–3 (implemented Oct 3; NOT yet evaluated)
`--feature-version 3` in `algorithm_4_hybrid.py`. v1 and v2 behaviour is unchanged: re-evaluating `casce_gat_v2.pt` and the holdout model gives byte-identical `evaluation_results.json`.

1. **Dropped edges (bug).**
   - v3 adds `Query —spawns→ Process`, the SQL statement that started an OS program and the core cross-layer link, and `Query —accesses→ Role`.
   - The **recency** feature now uses one clock (`timestamp_unix`) and measures position within the session (0 = first event, 1 = last). In v1/v2 it mixed kernel nanoseconds with Postgres seconds.
2. **Behaviour instead of identifiers (shortcut features).** Node text in v3:

   | Node | v3 text |
   |---|---|
   | Query | SQL with quoted literals → `s`, numbers → `n`, and the role name in CREATE/ALTER/DROP ROLE → `r`; statement type, clauses and table/column names are kept |
   | Process | program name only (`curl`, `cat`, …), not the full command line |
   | Endpoint | `approved` (the bank's allow-listed integration endpoints) / `internal` (other private address) / `external` / `loopback`, instead of the IP |
   | File | top-level directory + hidden-directory flag + extension, instead of the full path |
   | Role | constant `role`, without its name |

   Session, Table and Behavior are as in v2.
3. **Threshold from benign traffic.** `--mode tune --theta-mode fpr --target-fpr 0.01` picks the lowest θ whose false-positive rate on the *benign* validation sessions is ≤ 1%. It needs no attack examples, so it does not depend on which unseen attack validation holds. The default `--theta-mode f1` is unchanged, and the chosen mode is recorded in the model sidecar.

**Approved destinations (changed Oct 3, before any v3 run).** The first draft split endpoints only by private vs public address. That put the bank's documented warehouse `198.51.100.20` in the same "external" class as the attacker's look-alike `198.51.100.77`. v3 now takes an explicit allow-list, as a bank configures for its firewall: `APPROVED_DESTINATIONS`, which defaults to the domain's approved endpoints `198.51.100.20`, `10.0.1.50` and `10.0.1.100` (datagen `INTERNAL_IPS`) and can be overridden with `CASCE_APPROVED_DESTINATIONS`. This is not a label: the generator deliberately sends about 30% of each class to the other pool.

**Planned evaluation** uses the same 7 template-disjoint folds:
```
FV=3 THETA_MODE=fpr OUT=loto_v3 SEEDS="1 2 3" setsid nohup bash loto/run_all.sh > loto_v3.queue.log 2>&1 &
python3 loto_summary.py --dir loto_v3 --out loto_v3/loto_summary.json
```

## Fix 4: extra benign templates (implemented Oct 3; NOT yet evaluated)
**Why.** On unseen templates, most false alarms came from legitimate behaviour the model had never seen as benign: data leaving the database via `COPY … TO PROGRAM`, bulk sensitive reads and role or log administration. The original corpus has only 6 benign templates.

**What.** `datagen/generate_batch.py --template-set benign_extra` adds 6 benign templates. Each is the legitimate counterpart of a behaviour that attacks use:

| Template | Role | Legitimate counterpart of |
|---|---|---|
| `nightly_backup` | batch_etl_service | `COPY … TO PROGRAM 'gzip/bzip2/xz > /var/backups/…'`: local compressed backup (exfil-like, no network) |
| `bi_export` | branch_manager | aggregated KPIs `curl`-ed to an internal BI service (exfil-like, no PII) |
| `kyc_review` | compliance_officer | a few named customers' `national_id`/`address`, written to a case file (pii_dump-like, targeted) |
| `user_provisioning` | **dba** (new role) | `CREATE ROLE … LOGIN PASSWORD … VALID UNTIL` (no SUPERUSER) + `GRANT` (priv_abuse / alter_role-like) |
| `audit_archive` | **dba** | compress old `audit_logs` rows, `DELETE` them, `rm` temp report files (defense_impair-like) |
| `replica_health` | batch_etl_service | replication-lag check `curl`-ed to internal monitoring (exfil-like, no customer data) |

- **New `dba` role:** added to `datagen/domains/banking.yaml` (role description and padding) and to `codegen.DEFAULT_PADDING_PROFILE`. No existing template uses it.
- **Default set unchanged:** with `--template-set default` (the default), regenerating seed 42 reproduces the `dataset_dev` specs exactly. Verified on all 40 runs.

**Corpus.** `dataset_benign_extra/`: 12 runs, seed 777, 240 benign sessions (35–44 per template). All runs pass `validate_run.py`. Runs are renumbered `run_101…run_112` so graph file names never collide with `dataset_dev`.
- Graphs (`enriched_graphs/`) come from `build_training_graphs.py` (full sessions + prefixes, 960 graphs). That builder produces graphs identical to `main.py`'s (checked on dev run_001).
- These sessions carry Behavior nodes that previously occurred **only in malicious graphs**: DESTRUCTIVE_DB_OPERATION 86 and DEFENSE_IMPAIRMENT 86 from `audit_archive`, plus EXTERNAL_TRANSFER 156.

Regenerate with:
```
python3 datagen/generate_batch.py --out dataset_benign_extra --runs 12 --seed 777 --template-set benign_extra
for i in $(seq -w 1 12); do mv dataset_benign_extra/run_0$i dataset_benign_extra/run_1$i; done
python3 build_training_graphs.py --runs dataset_benign_extra/run_1* --out-dir dataset_benign_extra/enriched_graphs
```

**How it is used.** The corpus goes into **training only**. The 7 template-disjoint folds (validation and test graphs) are unchanged, so any difference from the v2 results in "T" comes from the extra benign data alone:
```
EXTRA=1 OUT=loto_v2_extra SEEDS="1 2 3" setsid nohup bash loto/run_all.sh > loto_v2_extra.queue.log 2>&1 &
```
Training sets grow by 960 graphs (~+33%), so runs take about a third longer.

**Live 4D.** `workload_simulation/setup_banking_db.sh` now creates the `dba` role (CREATEROLE, DELETE on audit_logs, pg_execute_server_program) and the folders the new templates write into.

## Comparison runs A0/A/B/C (started Oct 3)
`loto/run_abc.sh` runs one seed per configuration on the same 7 folds, then commits and pushes each stage's results:

| Stage | Config | Isolates |
|---|---|---|
| A0 | v2 models from `loto/`, θ re-tuned with `--theta-mode fpr` (no retraining) | fix 3 |
| A | v2 + `dataset_benign_extra` in training, θ mode f1 | fix 4 |
| B | v3, θ mode fpr | fixes 1–3 |
| C | v3 + `dataset_benign_extra`, θ mode fpr | fixes 1–4 |

Each stage's results are in `loto_<config>/loto_summary.txt`.

### Results: A0/A/B/C plus re-scoring with the original θ rule (seed 1, Oct 3)
`loto/rescore_f1.sh <src> <dst>` re-tunes θ with `--theta-mode f1` on already-trained models (no retraining). This separates the v3 features from the benign-FPR θ rule.

| Config | Features | Extra benign | θ rule | Recall | FPR | F1 | ROC-AUC | Pooled TN/FP/FN/TP |
|---|---|---|---|---|---|---|---|---|
| v2 (3 seeds, mean) | v2 | – | f1 | 0.818 | 0.403 | 0.673 | 0.614 | (seed 1: 475/288/182/326) |
| A0 | v2 | – | fpr | 0.571 | 0.300 | 0.445 | 0.524 | 542/221/246/262 |
| A | v2 | yes | f1 | 0.847 | 0.502 | 0.696 | 0.729 | 407/356/97/411 |
| B | v3 | – | fpr | 0.619 | **0.143** | 0.595 | 0.667 | 701/62/214/294 |
| **B′ (`loto_v3_f1`)** | **v3** | – | **f1** | **0.905** | 0.286 | **0.832** | 0.667 | 625/138/64/444 |
| C | v3 | yes | fpr | 0.619 | 0.242 | 0.540 | 0.667 | 600/163/214/294 |
| C′ (`loto_v3_extra_f1`) | v3 | yes | f1 | 0.619 | 0.334 | 0.562 | 0.667 | 576/187/214/294 |

**Reading (one seed, so provisional):**
- **v3 features with the original θ rule (B′) are the best configuration.** Macro F1 is 0.832, against v2's 0.673 ± 0.128 over 3 seeds.
  - 4 of 7 unseen attack templates are perfect, with recall 1 and FPR 0: alter_role_esc, compliance_exfil, priv_abuse and teller_pii_dump.
  - multi_apt is 0.33 recall with 0 FPR.
- **Two folds still fail: etl_exfil_mal and defense_impair.** In both, the unseen benign template is ETL replication (`etl_repl_ben` / `etl_internal`). It is flagged 100%, and the ranking is inverted or degenerate (AUC 0).
  - The ETL pair differs mainly in destination and query breadth. With the ETL templates absent from training, no configuration separates them.
- **The benign-FPR θ rule (fix 3) hurts in every configuration.** It often picks θ ≥ 0.75, above the 0.75 risk cap that applies when no rule fires, so attacks the model ranks correctly are missed. Recommendation: drop it and keep the original f1 rule.
- **Extra benign corpus (fix 4):** it helps v2 (F1 0.54 → 0.70 on seed 1, AUC 0.52 → 0.73), but it does **not** help v3 (0.832 → 0.562). Its six templates may resemble the unseen ETL/compliance traffic in ways that shift the scale. This needs more seeds before drawing a conclusion.
- **Caveat on selection.** B′ was chosen *after* seeing these test folds: the v3 design was fixed beforehand, but the choice of θ rule was not. Its numbers must be confirmed on seeds 2–3 and on data not used for this choice, ideally the live 4D run, before being reported as the final result.

## 4D: plan (decided Oct 3; not run yet)
- **Database: `casce_banking`**, the same schema as all training data and the earlier live runs (4a–5b), so only the attack techniques are unseen. It was set up in this machine's container on Oct 3 with `setup_banking_db.sh`: 10,000 customers, 100,000 accounts, 300,000 transactions, the 5 banking roles incl. `dba`, and the CASCE hook enabled. `run_live_scenarios.py --check-sql --class all` passes, apart from 2 attack statements the database correctly denies.
- **Attacks.** The legacy `workload_simulation/attack_workload/*.sh` scripts (added Sep 7, from the project's early phase) target the old pgbench database `casce_tpcb` as superuser. They must be **adapted to the banking tables and roles** before use. That adaptation is done by the team (see below).
  - Each group is flagged *new technique* or *similar to training*. Backdoor `CREATE ROLE` and `curl` exfiltration count as similar to training.
  - OS-only scripts are excluded and their exclusion reported.
- **Benign workload:** backup, maintenance, a temporary reporting role, everyday teller/manager traffic, plus pgbench background load.
- **Labels:** every `psql` call is one session with `PGAPPNAME=casce_label=<Benign|Malicious>:<group>_<name>_r<repeat>`.
  - The runner also writes a manifest (`key, class, group, new_technique, source, role, repeat`, one JSON line per session).
  - Destructive attacks run last, after pgbench stops. The database is reset between repeats.
- **3 repeats.** Models: v2 and a single v3 model, each at its validation-tuned θ, with nothing tuned on 4D.
- **Reporting:** per attack group (main table), overall, and per script (appendix), as mean ± spread over repeats. Results go into the 4D column of `results_per_attack.md`.

## Results per attack type
`python3 per_attack_table.py` → `results_per_attack.md`. It gives one row per scenario template: detection rate for attacks and false-alarm rate for benign workloads. Columns: seen offline (E1, v2, 3 seeds); seen live (5b, v2, with alert latency); unseen offline (template-disjoint, v2 with 3 seeds and v3 with 1 seed); and 4D (pending). It is built from existing result files only.

## v3 single model on E1 and the live captures (Oct 3)
`run_v3_full.sh` trains `casce_gat_v3.pt` exactly like `casce_gat_v2` (same train/val data, seed 42, settings; only `--feature-version 3`). It then tunes θ on the E1 validation set with the original f1 rule: θ = 0.55, recorded in the sidecar. Early stopping fired at epoch 33. It then repeats v2's evaluations: the E1 test set, plus replays of the live captures through the real-time daemon (`--replay --replay-realtime`). Outputs are in `live_eval_v3/` and `eval_test_report_v3/`.

| Evaluation | v2 | **v3** |
|---|---|---|
| E1 synthetic test (226; 93 attacks) | P = R = F1 = 1.0, FPR 0 | P = R = F1 = 1.0, FPR 0, ROC-AUC 1.0 |
| 4a live, pgbench only (331) | FPR 0 | **FPR 0** |
| 4b live, benign scenarios (133) | FPR 0 | **FPR 0** |
| 4c live, benign + pgbench (312) | FPR 0 | **FPR 0** |
| 5a live, attacks (93) | 93/93 | **93/93** |
| 5b live mixed (1,251) | TP 93, FP 0, FN 0, TN 1,158 | **TP 93, FP 0, FN 0, TN 1,158**; real-time view identical; no partial-session false alerts |
| Live vs synthetic verdicts | 226/226 | **226/226** (mean \|Δrisk\| 0.001) |

**Reading.** On seen templates v3 matches v2 exactly, offline and live, so masking identifiers costs nothing on known attacks. v3's advantage is on unseen templates (section T, F1 0.83 vs 0.67, provisional, 1 seed). The v2 live rows for 4a–5a are replays of the same captures, like v3's. 5b was scored live by v2 and replayed for v3; replay reproduces live verdicts.

## Overnight run, Oct 8–9: live real-time evaluation and production hardening
Local branch `overnight-realtime`, not pushed. Everything below was run on this machine's `casce_environment` container.

### 6_full: fresh live capture, v3 scoring in real time (follow mode)
`workload_simulation/run_full_live.sh 6_full casce_gat_v3.pt --class all --pgbench --specs 'dataset_test/run_*/specs/*.yaml' 'dataset_benign_extra/run_*/specs/*.yaml'`
- Capture: 2,801 labelled live sessions over 39 min.
  - All 226 `dataset_test` scenario sessions (133 benign, 93 attacks; seen templates).
  - 240 sessions of the 6 `benign_extra` templates, **never seen by v2 or v3**.
  - 2,335 pgbench sessions.
- Daemon: v3, θ = 0.55 (from its sidecar), running live during the capture. v2 and v3 were also replayed on the same capture (`--replay --replay-realtime`).

| Final verdict | v2 (replay) | **v3 (live)** | v3 (replay) |
|---|---|---|---|
| Attacks (93) | 93/93 | **93/93** | 93/93 |
| pgbench (2,335) | 0 FP | **0 FP** | 0 FP |
| Seen benign scenarios (133) | 0 FP | **0 FP** | 0 FP |
| **Unseen benign templates (240)** | **94 FP (39%)**: audit_archive 43/43, bi_export 35/35, replica_health 16/43 | **17 FP (7%)**: replica_health 17/43 only | 17 FP |
| Overall precision / recall / F1 | 0.497 / 1.0 / 0.664 | **0.845 / 1.0 / 0.916** | 0.845 / 1.0 / 0.916 |
| Real-time view: alerts on sessions whose final verdict is benign | 0 | 35 (user_provisioning) | 35 |

- **v3 replay reproduces v3 live exactly**, the same 17 FP and 35 transient alerts, so replay is a valid stand-in for live scoring.
- **The live result on unseen benign workloads confirms the offline template-disjoint result:** v3 generalizes much better than v2.
- **Remaining v3 errors:**
  - `replica_health`, the benign `curl` of a row count to internal monitoring, at 40%.
  - Transient mid-session alerts on `user_provisioning`: right after its `CREATE ROLE … LOGIN PASSWORD`, the partial session resembles priv_abuse. Its final verdict is benign.

### Real-time latency: torch threads
- Live 6_full latency was poor: attacks alerted after a median 5.5 s (p90 8.5 s, max 12.8 s), and one scoring pass took a median 424 ms.
- **Breakdown:** Algorithm 2 1.4 ms, Algorithm 3 16.5 ms, GraphML round trip 4.4 ms, **Algorithm 4 393 ms**.
- **Cause:** PyTorch's default of one thread per core (12 here) on graphs of about 20 nodes, under CPU contention (two fold trainings ran at the same time).
- **Benchmark** (120 test graphs, same load): `detect()` median **103.5 ms at the default, 22.4 ms with 1 thread**, 23.5 ms with 2, 79.1 ms with 4.
- **Fix:** `realtime_daemon.py --threads` (default 1) sets `torch.set_num_threads`. Also, the daemon's `evicted` table is now trimmed, so it no longer grows by one entry per session forever.
- **Why `replica_health` is flagged.** The destination of each session's `curl` comes from the live kernel `connect` events, classed with v3's endpoint rule. All **17** flagged sessions sent to an **external, non-approved** address; all **26** sent to an approved destination scored benign. The generator deliberately sends 30% of benign transfers to the external pool (`_DEST_CROSS_PROB`) and still labels them benign. v3 alerts on "data sent to a non-approved external host", which is arguably the intended security policy. These 17 are label convention, not detector confusion.

### Alert confirmation (`--confirm N`): no benefit, default kept at 1
Re-scoring 6_full with v3 at `--confirm 1` reproduces the earlier replay exactly: 93/93 attacks, 52 benign alerts, 35 of them transient. At `--confirm 2` (alert a running session only after two consecutive scorings ≥ θ) the result is still **35 transient alerts**. The user_provisioning partial sessions stay above θ for several 2-s rescorings, because the GRANT that makes them benign arrives 2–6 s after the CREATE ROLE. A longer hold-off would only delay real alerts. The option remains available, but the remedy for transient alerts is the model knowing the benign workload (v3P below), not an alert delay.

### Sandbox hygiene
`user_provisioning` scenarios create logins (`teller_NNN`, `analyst_NNN`, `auditor_NNN`) that persist. Replaying the same specs again then fails with "role already exists" (12 sessions in 7_train_benign; harmless for training). The 35 such logins were dropped from `casce_banking` before the final live run. Drop them between live runs that replay the same specs.

### v3P: production candidate (more benign coverage, live-captured benign traffic)
`run_v3p.sh` produces `casce_gat_v3p.pt`. The model, features (v3), settings, seed and θ rule are the same as `casce_gat_v3`. The training data adds what v3 lacked:
1. **The 6 extra benign templates:** `dataset_benign_extra` runs 101–105 for training and run 106 for validation. **Runs 107–112 are held out for testing.**
2. **Live-captured benign traffic with real eBPF kernel events**, captured for training only (`live_runs/7_train_benign`, 21 min). It covers the benign scenarios of `dataset_dev` runs 1–10 plus `benign_extra` runs 101–105: 228 scenario sessions, plus pgbench (100 of 1,349 sessions sampled). That gives 1,312 graphs including prefixes. Until now the model had seen real kernel events only at test time.

Training set: 3,184 graphs (2,824 benign, 360 malicious). Validation: 588. Early stopping fired at epoch 35. θ = 0.55 (the validation F1 = 1.0 range was 0.30–0.75, middle chosen).

| Test (offline) | n (malicious) | P | R | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| E1 test + held-out benign_extra runs 107–112 | 706 (93) | 0.969 | 1.000 | 0.984 | 0.0049 | 0.9995 |

**Caveat.** For v3P the extra benign templates are *seen* (new instances only). v3P therefore measures **coverage of the bank's known workloads**, not generalization. Generalization evidence remains the template-disjoint folds (T) and v3's live result on the unseen templates (6_full).

### 8_final: final live run, v2 / v3 / v3P all scoring in real time (Oct 9, 05:13–05:43)
`run_full_live.sh 8_final casce_gat_v2.pt,casce_gat_v3.pt,casce_gat_v3p.pt --class all --pgbench --specs 'dataset_test/run_*/specs/*.yaml' 'dataset_benign_extra/run_10[7-9]/specs/*.yaml' 'dataset_benign_extra/run_11[0-2]/specs/*.yaml'`
- **Three daemons followed the same live logs at once**, each with `--threads 1`, while three fold trainings were also running on the machine.
- **Traffic:** all 226 `dataset_test` scenario sessions, the held-out `benign_extra` runs 107–112 (120 sessions, never used for any training), and 1,654 pgbench sessions.
- The provisioning logins left by earlier runs were dropped first.
- Comparison: `workload_simulation/live_compare.py live_runs/8_final daemon_v2_live daemon_v3_live daemon_v3p_live`.

| Group | daemon_v2_live | daemon_v3_live | daemon_v3p_live |
|---|---|---|---|
| Attacks: all attempted | 93/93 | 93/93 | 93/93 |
| Attacks: executed | 56/56 | 56/56 | 56/56 |
| Attacks: refused by Postgres | 37/37 | 37/37 | 37/37 |
| Benign scenarios (dataset_test) | 0/133 | 0/133 | 3/133 |
| Benign extra templates | 46/120 | 8/120 | 0/120 |
| pgbench | 0/1654 | 0/1654 | 0/1654 |
| Precision / recall / F1 | 0.669 / 1.000 / 0.802 | 0.921 / 1.000 / 0.959 | 0.969 / 1.000 / 0.984 |
| FPR (all benign) | 0.0241 (46/1907) | 0.0042 (8/1907) | 0.0016 (3/1907) |
| Real-time alerts on sessions finally benign | 0 | 19 | 0 |
| Attack alert latency median / p90 / max (s) | 1.61 / 2.50 / 3.03 | 1.63 / 2.43 / 3.14 | 1.61 / 2.43 / 3.09 |

| Benign template (false alarms) | v2 | v3 | v3P |
|---|---|---|---|
| audit_archive | 25/25 | 0/25 | 0/25 |
| bi_export | 14/14 | 0/14 | 0/14 |
| replica_health | 7/16 | 8/16 | 0/16 |
| teller_routine | 0/31 | 0/31 | 3/31 |
| all other benign templates and pgbench | 0 | 0 | 0 |

**Reading.**
- **All three models detect every attack**: 93/93 attempted and 56/56 executed. They do it **in real time**, with a median of 1.6 s and a maximum of 3.1 s from the attack's last event to the alert. Before `--threads 1` it was 5.5 s and 12.8 s.
- **v2 → v3 → v3P, false alarms on all benign traffic: 2.4% → 0.42% → 0.16%.**
  - v3's gain is generalization: the extra templates are unseen for v3.
  - v3P's further gain is coverage: those templates are known to v3P, with new instances.
  - v3P also removes v3's 19 transient mid-session alerts.
- **v3P's 3 false alarms are on `teller_routine`**, a template v3 handles perfectly (scores of 0). All 3 sessions repeat one identical lookup twice. The repeat collapses into one Query node with two edges, a shape rare in training, and v3P's GAT saturates at 1.0 on it. It is single-model fragility, not a systematic error (28/31 teller sessions are fine). Seeds or ensembling would show whether it is stable.
- **Recommended deployment model: v3P**, with **v3** as the evaluated generalization model.

### 9_load: throughput and stability (Oct 9, 05:45–05:57)
`run_full_live.sh 9_load casce_gat_v3p.pt --pgbench-only 600 --pgbench-rate 8 --pgbench-clients 4`: a 10-minute load test. pgbench opened a new session for every transaction, at 8.1 sessions/s, with the v3P daemon live (`--threads 1`). A fold training ran on the same machine at the same time.

| Measure | Result |
|---|---|
| Sessions captured / scored | 4,868 / 4,868 |
| False alarms | 0 |
| Final score lag after a session's last event | median 2.0 s, p90 5.4 s, p99 6.9 s, max 7.3 s (stable, no backlog growth) |
| Scoring pass (Alg 2–4) | median 106 ms, p99 112 ms, max 158 ms |
| Daemon CPU | ≈ 78% of one core throughout |
| Daemon memory (RSS) | 794 MB → 798 MB over 10 min (mostly the torch runtime; no leak) |

**Capacity.** One single-threaded daemon handles about 8–9 new sessions/s, and it is near saturation at 8/s. Beyond that, sessions can be sharded across daemons by backend pid, or `--rescore-every` raised to trade alert latency for throughput. Neither is implemented.

### T, v3 confirmed on 3 seeds (`loto_v3_f1/`, original θ rule)
Seeds 2 and 3 ran overnight. Seed 3 had two folds trained twice by a duplicated queue; they were re-tuned and re-reported from their final checkpoints, and the numbers were unchanged.

| Config (7 folds × 3 seeds) | Recall | FPR | F1 | ROC-AUC |
|---|---|---|---|---|
| v2 | 0.818 ± 0.104 | 0.403 ± 0.058 | 0.673 ± 0.128 | 0.614 ± 0.078 |
| **v3** | 0.794 ± 0.153 | 0.333 ± 0.083 | **0.729 ± 0.121** | 0.662 ± 0.136 |

- **Per fold, v3 (3 seeds):**
  - **Perfect in all 3 seeds:** alter_role_esc, compliance_exfil, priv_abuse.
  - teller_pii_dump is perfect in 2 seeds; in seed 3 the unseen benign compliance_audit scores above the attack (recall 0, FPR 1).
  - defense_impair and etl_exfil_mal have FPR 1.0 in every seed: the unseen benign ETL is always flagged.
  - multi_apt recall is 0.22.
- **Conclusion.** The single-seed F1 of 0.83 was optimistic. v3's offline generalization gain over v2 is real but modest (+0.06 F1, about half a standard deviation). The live unseen-benign result (6_full: 94 → 17 false alarms of 240) shows a larger effect. That is because those unseen templates differ from attacks mainly in the identifiers v3 masks, while the failing offline folds (ETL, audit) are designed hard negatives.

### Open after the overnight run
- **v3P seed check (done 08:50).** `casce_gat_v3p_s7.pt` was trained exactly like v3P with seed 7 (early stop at epoch 34, θ 0.55) and replayed on the 8_final capture (`live_eval_overnight/8_final/compare_v3p_seeds.md`).
  - **0 false alarms on all 1,907 benign sessions**, so seed 42's 3 teller_routine false alarms are seed-specific.
  - **It misses all 12 `defense_impair` sessions** (risk 0.376). All 12 were refused by Postgres; every *executed* attack is caught (56/56), but attempted recall is 81/93.
  - Each v3P seed has a different blind spot. **Averaging several seeds (an ensemble) is the next step** before choosing a single deployment checkpoint.
- **4D (unseen attack techniques, live)** still needs the adapted attack scripts (`4d-live-attack-workload` branch).
- **Daemon throughput** is about 8 sessions/s per single-threaded daemon. Sharding by backend pid is the scaling path.

### v3P ensemble (Oct 9 morning)
- **Ensemble support** (`algorithm_4_hybrid.load_model`). A model sidecar holding `{"ensemble": [member .pt files]}` loads its members and averages their GAT probabilities (`EnsembleGAT`). Tuning, evaluation and the daemon use it unchanged through `--model-path <name>.pt`; no `.pt` of its own is needed. `casce_gat_v3p_ens2.json` combines v3P seeds 42 and 7.
- **Evaluation:** `run_ensemble_eval.sh casce_gat_v3p_ens2` runs θ tuning on the v3P validation set (θ = 0.55), the offline test, and a replay of 8_final. Results are in `live_eval_ensemble/`.

| | v3P seed 42 | v3P seed 7 | **ensemble (42 + 7)** |
|---|---|---|---|
| Offline: E1 test + held-out benign_extra 107–112 (706) | F1 0.984, FPR 0.49% | – | **F1 1.000, FPR 0, ROC-AUC 1.0** |
| 8_final replay: attacks attempted / executed | 93/93, 56/56 | 81/93, 56/56 | **93/93, 56/56** |
| 8_final replay: false alarms (1,907 benign) | 3 | 0 | **0** |

**Caveat.** The ensemble was tried *after* seeing the single models' errors on 8_final, so 8_final flatters it. Confirmation therefore uses **fresh instances never used for any model or decision** (10_confirm below).

### 10_confirm: fresh live confirmation (Oct 9, 09:17–09:33)
- **Fresh scenario instances never used for any model or decision:** `dataset_confirm`, 5 runs of the 13 standard templates (`generate_batch.py --seed 2026`, 118 sessions: 61 benign, 57 attacks), and `dataset_benign_confirm`, 3 runs of the extra benign templates (`--template-set benign_extra --seed 999`, renumbered run_201–203, 60 sessions). All runs pass `validate_run.py`.
- **Live run:** v3, v3P and the 2-model ensemble all scored in real time (`run_full_live.sh 10_confirm casce_gat_v3.pt,casce_gat_v3p.pt,casce_gat_v3p_ens2.pt …`), with 937 pgbench sessions as background load.

| Live, fresh instances | v3 | v3P | **ensemble (42 + 7)** |
|---|---|---|---|
| Attacks: attempted / executed / refused | 57/57, 31/31, 26/26 | 57/57, 31/31, 26/26 | **57/57, 31/31, 26/26** |
| False alarms: standard benign / extra benign / pgbench | 0/61, 2/60, 0/937 | 0/61, 0/60, 0/937 | **0/61, 0/60, 0/937** |
| Precision / recall / F1 | 0.966 / 1.0 / 0.983 | 1.0 / 1.0 / 1.0 | **1.0 / 1.0 / 1.0** |
| Transient alerts (final verdict benign) | 7 | 0 | **0** |
| Attack alert latency median / p90 / max | 1.59 / 2.63 / 2.92 s | 1.56 / 2.58 / 3.01 s | **1.66 / 2.59 / 3.15 s** |

**Conclusion.** On fresh live traffic, v3P and its ensemble detect every attack with no false alarms, alerting within about 1.6 s. The ensemble adds about 0.1 s of latency and removes the per-seed blind spots seen on 8_final. **Recommended deployment: `casce_gat_v3p_ens2`.**

**Scope, unchanged.** These are new instances of templates the deployed models were trained on. Detection of *unseen* attack techniques is measured by the template-disjoint folds (v3: F1 0.73 ± 0.12) and will be measured live by 4D.
