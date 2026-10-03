# CASCE pipeline review: leakage, thresholds and experiments (2026-10-02)

This document records what the repository does now, what is wrong with it, and what should change. Every claim was checked against the code or data. Nothing has been modified yet. Measurements come from `eval_test_report_v2/leakage_report.json`, `eval_test_report_holdout_priv_abuse/`, `models_seeds/`, and a calibration run whose numbers are quoted in section D.

---

## A. Current pipeline

| Stage | File / function | What it does |
|---|---|---|
| Data generation | `datagen/generate_batch.py` (`CATEGORY_GENERATORS`), `datagen/codegen.py` | 13 hand-written **template builders** for the banking domain: 7 malicious and 6 benign. Each run draws 20 scenarios from these. `dataset_dev` uses seed 42 (40 runs, 900 sessions) and `dataset_test` uses seed 123 (10 runs, 226 sessions, 93 malicious). |
| What a seed changes | same | Which templates are drawn per run, branch ids, amounts, random passwords, shadow-role name (`svc_shadow`, `admin_backup` or `dba_maint`), destination IP, and timing. **The SQL statements of each template stay the same.** Every run's pids start at 20000. |
| Alg 1–3 | `algorithm_1.py`, `algorithm2.py`, `algorithm_3_abstract.py`, `main.py` | Correlate kernel and Postgres events, build one graph per session, add rule-based behavior nodes, and write `enriched_<run>_<pid>_<Label>.graphml`. Test graphs have a median of 14 nodes and 19 edges. |
| Split | `prepare_algo4_dataset.py` | "family_aware". The family id is the **scenario instance** (`banking_priv_abuse_0003`). Dev instances whose id string also appears in test are dropped (117 of 244). The rest are shuffled 80/20 with seed 42. |
| Training extras | `build_training_graphs.py` | Prefix graphs of the train and val sessions, plus 60 live pgbench sessions each for train and val, all benign. |
| Features | `algorithm_4_hybrid.featurize_node` / `node_hash_text` | 24 dims per node: a 16-dim hash of node text and 8 numbers. The node text is the full SQL for Query nodes, the file path for File, the command line for Process, the role name for Role, the IP for Endpoint and the label for Behavior. The 8 numbers are four Alg 3 scores, has_ts, recency, in-degree and out-degree. |
| Model | `HeteroGAT` | 2× HeteroConv(GATv2), per-type mean pool, MLP. |
| Score | `detect` / `fuse_scores` | `risk = 1-(1-0.75·rule)(1-0.75·gat)`. When no rule fires, risk can't exceed 0.75. |
| Training | `train_gat` | Adam, batch size 1, early stopping on validation loss. |
| Threshold tuning | `tune_thresholds` | Sweeps θ from 0.05 to 0.95 on whatever data is passed in (in practice, validation). If several values tie on F1, it takes the middle one. |
| Testing | `evaluate_model` | Confusion matrix at `--theta-a`. |
| Live | `workload_simulation/run_live_scenarios.py` → `realtime_daemon.py` → `workload_simulation/evaluate_live.py` | Replays the **`dataset_test` specs** against a real Postgres. Ground truth comes from `PGAPPNAME`, which is written only to `session_labels.jsonl` and never enters the graph. Sessions are scored by the same Alg 1–4 code. |

---

## B. Findings

### Confirmed problems (with evidence)
1. **Template leakage.** All 13 templates appear in train, val and test. 108 of 226 test graphs (71 of 93 malicious) have the **same SQL sequence** as a training graph. With literals masked, **all 93 malicious test graphs** have a match (`leakage_report.json → test_vs_train_sql_matches`).
2. **The "family overlap" check doesn't measure anything.** It compares instance-id strings across two datasets generated with different seeds (`prepare_algo4_dataset.py`, the `overlapping_test_families` logic). `banking_priv_abuse_0003` in dev and in test are unrelated instances of the same template. The check removes 117 dev instances for no benefit and reports "no overlap" even though every template overlaps.
3. **A side effect of (2):** `etl_exfil_mal` ends up with only **2 training graphs and 0 validation graphs**. This is the "only two graphs" from the feedback. It doesn't mean the whole model trains on 2 graphs (see H).
4. **Validation can't set θ.** On validation the GAT outputs about 0 or about 1 for **100% of graphs**. Benign risk is at most 0.29 and malicious risk at least 0.75, so every θ from 0.30 to 0.75 gives F1 = 1.0. The value 0.55 is simply the midpoint picked by the tie rule; the data played no part in it.
5. **Class-exclusive strings reach the model.** Role nodes occur **only** in malicious graphs (96 of them). All 15 file paths and all role names belong to one class only. Full SQL text is hashed into the features.
6. **Stale default θ = 0.40** in `realtime_daemon.py:347` and `workload_simulation/evaluate_live.py:72`. It was tuned for the old v1 model (commit `9593f8fc`: "retrain GAT (theta=0.40, F1=0.901)") and does not apply to v2.
7. **Recency mixes time units.** Kernel nodes carry nanosecond timestamps (e.g. Process `9503036397457`), while Postgres nodes carry epoch seconds (`1789937100`). `recency = ts / max_ts`, so in any session with a kernel event every Query gets recency ≈ 0.0002. The feature ends up encoding "has kernel activity" rather than time order.
8. **Two edge types are dropped.** `('Query','spawns','Process')` and `('Query','accesses','Role')` are missing from `FORWARD_EDGE_TYPES` and are skipped when loading. Process and Role nodes therefore never exchange messages with queries.
9. **Single-seed results, and training is not deterministic.** The same seed does not reproduce the same model. v2 test F1 over three seeds is 0.985 ± 0.017, so the reported 1.0 is the best of the three runs.

### Probable (strong evidence, not proven)
- **The model may partly detect strings rather than behavior.** Evidence: findings (5) and (4), and the fact that the holdout GAT still ranks unseen priv_abuse sessions first. Those sessions share tokens such as `SUPERUSER` and `pg_authid` with kept templates. A feature ablation would be needed to prove it (see P3).

### Correct as implemented
- No graph or session is shared between train, val and test. Prefix graphs stay inside their split.
- **θ was never tuned on test.** Both 0.55 values came from validation.
- The holdout removes priv_abuse from training, validation and prefixes.
- pids, session ids, usernames and client ports are **not** features in v2.
- The live pipeline uses the same Alg 1–4 code. Live scores match synthetic scores for all 226 sessions (mean |Δ| 0.002). The label never enters the graph.
- 5b metrics come from one joint confusion matrix over the mixed traffic.

---

## C. Leakage summary

| What | Shared across train/val/test? | Is it a model input? |
|---|---|---|
| Graph or session | No | — |
| Scenario instance | No | — |
| **Template (behavior)** | **Yes, all 13** | Indirectly, through SQL text and structure |
| SQL sequence (literals masked) | **Yes: 93 of 93 malicious test graphs** | Yes (Query text is hashed) |
| Role names, file paths, IPs | Yes, and class-exclusive | Yes |
| pid, session id, username | Filenames repeat (pids start at 20000) | **No** |

**Does this explain the high scores? Yes.** With leakage measured at the template level, the test set is a re-instantiation of the training set.

---

## D. Threshold analysis

| Value | Where | Origin | Should be used for |
|---|---|---|---|
| 0.50 | `algorithm_4_hybrid.py:173` `THETA_A` | Constant used as the CLI default | Nothing (always pass θ explicitly) |
| 0.40 | defaults in `realtime_daemon.py:347` and `evaluate_live.py:72` | v1 model (`casce_gat.pt`) tuning | **The v1 model only** |
| 0.55 (v2) | `tune_out_v2/threshold_sweep.json` | v2 tuned on E1 validation (508 graphs) | v2, general evaluation |
| 0.55 (holdout) | `tune_out_holdout_priv_abuse/` | Holdout model tuned on **its own** validation (500 graphs, no priv_abuse) | Holdout model only |

- **The friend's question: was 0.55 tuned for the holdout and used only when testing it?** Yes. The holdout model was tuned on its own validation set, which contains no priv_abuse, and 0.55 was used only to test that model. v2 independently got 0.55 from its own validation set.
  - The two values match because both validation sets are flat from 0.30 to 0.75 (finding B4), not because one was copied from the other.
- **Which threshold each run used:**
  - Offline tests: 0.55.
  - v2 live runs: 0.55.
  - v1 live runs: 0.40, which is correct for v1.
- **Confusion matrices at both thresholds:**

| Model, set | θ = 0.40 (TN/FP/FN/TP) | θ = 0.55 |
|---|---|---|
| v2, validation | 456/0/0/52 | 456/0/0/52 |
| v2, test | 133/0/0/93 | 133/0/0/93 |
| holdout, test | 133/0/**5**/88 | 133/0/**7**/86 |

  - Switching the holdout model to 0.40 *because* it does better on test would be tuning on test. That is not allowed.
- **Calibration diagnosis.** Ranking is good (test ROC-AUC 0.993 to 1.0), so the cause isn't weak features. But Platt or isotonic calibration **cannot be fitted** on this validation set: it is perfectly separated, and every prediction is 0 or 1.
  - Also, `risk` is a fusion score capped at 0.75, not a probability.
  - The root cause is that validation is too easy (B1, B4), not a calibration bug. Fix the split first; calibration only becomes meaningful afterwards.

---

## E. Experiment "4D"

**There is no experiment called 4D in the repo.** The live experiments are listed below. All of them replay the `dataset_test` specs, which use the same 13 templates, or pgbench, which was also in training.

| Run | Traffic | n |
|---|---|---|
| 4a | pgbench only | 331 |
| 4b | benign scenarios only | 133 |
| 4c | benign scenarios + pgbench | 312 |
| 5a | attacks only | 93 |
| 5b | everything at once (mixed) | 1251 |

**None of these is an out-of-distribution test.** A valid 4D needs behavior the model has never seen:
- **Attacks:** the 44 hand-written scripts in `workload_simulation/attack_workload/*.sh` have never been run. Examples: `CREATE ROLE hacker SUPERUSER`, `COPY TO PROGRAM 'cat /etc/shadow'`, a reverse shell, `DROP` on pgbench tables. Alternatively, new scenarios written without looking at the templates.
- **Benign:** a different application workload, not pgbench.

---

## F. Experiment 5B

| Check | Result |
|---|---|
| Contains benign and malicious traffic together | **Yes**: 1025 pgbench + 133 benign scenarios + 93 attacks, run concurrently |
| One joint confusion matrix | **Yes** ("ALL n=1251" row) |
| TP/FP/FN/TN, precision, recall, F1, FPR | Correct (FNR isn't printed; it equals 1 − recall) |
| Threshold | v2 at 0.55, which is correct |
| Unseen? | **No**: same templates as test (and train), same pgbench workload as training |

**Verdict:** 5B is a valid *mixed-traffic, live-capture* test. It shows the live pipeline works under load with no false alarms. It is not a generalization test.

---

## G. Hold-out experiment (priv_abuse)

| Question | Answer |
|---|---|
| Excluded from training? | **Yes**: full sessions and prefixes (`make_holdout_labels.py`; asserted in `leakage_report.py`) |
| Excluded from validation? | **Yes** |
| Appears only at test time? | **Yes**: 16 test graphs |
| Does tuning leak the held-out family? | **No** |
| Priv-abuse-specific features still present in training? | **Partly**: `CREATE ROLE … SUPERUSER` and the `pg_authid` dump are in `multi_apt` (19 training graphs), `ALTER ROLE … SUPERUSER` is in `alter_role_esc` (19), and `pg_authid` reads are in the benign `dba_shadow_audit` (15). 5 of priv_abuse's 8 statements never appear in training. |
| Result | Detected 9/16, 16/16 and 16/16 over three seeds (recall 0.85 ± 0.25), zero false positives |

**Verdict:** the template really is unseen, but the technique is only partly unseen.

---

## H. "Two training graphs" and feature memorization

| | Graphs |
|---|---|
| v2 training | **1472** = 308 full sessions + 924 prefixes + 240 pgbench |
| v2 validation | 508 |
| Test | 226 |

- The "2" refers to **`etl_exfil_mal`, which has 2 training graphs and 0 validation graphs** (B3). The model as a whole does not train on two graphs.
- **Features that allow memorization:**
  - Query SQL text, file paths, command lines and role names, which are template-specific.
  - The presence of a Role node, which occurs only in malicious graphs.
  - Endpoint IPs, which are partly class-exclusive.
  - Behavior labels, which come from rules rather than ground truth (acceptable).
- **Behavioral or structural features:** node and edge types, degrees and the Alg 3 scores.
- **Do the same features exist in live data?** Yes, and live scores match synthetic ones.

---

## I. Recommended changes, by priority

### P0: methodological correctness
1. **Template-disjoint evaluation.** Use leave-one-template-out over all 7 malicious templates. In each fold:
   - **Test:** one held-out malicious template, plus held-out benign templates.
   - **Validation:** a *different* malicious template and a benign template.
   - **Train:** all remaining templates.

   Use all 900 dev sessions plus test. Report per-template recall and FPR, with mean ± std over folds and at least 3 seeds. This replaces "different seed of the same template" with genuinely unseen behavior.
2. **Replace the meaningless overlap check.** Check overlap at the template level, and stop dropping dev instances because of id collisions.
3. **Keep E1, but relabel it** as "seen templates (in-distribution)".

### P1: experiment correctness
4. **Build a real 4D:** run unseen attacks (`attack_workload/*.sh` or newly written scenarios) and a different benign workload live, then evaluate with the per-fold or v2 θ.
5. **Run at least 5 seeds** for every reported configuration.
6. (Optional) **A strict escalation holdout** that removes priv_abuse, alter_role_esc and multi_apt.

### P2: threshold and evaluation correctness
7. **Store the tuned θ in the model's sidecar JSON** and have the daemon and evaluator read it. Remove the stale 0.40 defaults.
8. **Report threshold-free metrics** (ROC-AUC, PR-AUC) alongside the confusion matrix at the validation θ, and add FNR. Mark `evaluate.py`, `run_pipeline.py`, `undersample.py`, `evaluate_holdout_experiment.py` and `test_zeroday_holdout.py` as stale.

### P3: model and features (only after P0–P2)
9. **Feature ablation / v3:** mask literals, role names and paths; fix the recency units; add the dropped edge types. Compare against v2 on the P0 folds.
10. **Calibration**, only if validation then contains scores in the ambiguous range.

---

## J. Exact files and functions

| # | File / function | Current behavior | Proposed behavior | Reason |
|---|---|---|---|---|
| 1 | `make_holdout_labels.py` (generalize) or a new `make_template_folds.py` | Removes one family from existing label files | Builds train/val/test label files per fold from a template list | P0-1 |
| 1 | `build_training_graphs.py` (run only, no change) | Prefixes for the 375 train+val sessions | Prefixes for all 900 dev sessions | Folds need prefixes for every template |
| 1 | `run_seed.sh`, `holdout_report.py`, `seed_summary.py` | One holdout config | Loop over folds and seeds | P0-1 |
| 2 | `prepare_algo4_dataset.py`, the `overlapping_test_families` block | Drops dev instances whose id matches test | Template-level check; no dropping | P0-2 |
| 7 | `algorithm_4_hybrid.tune_thresholds` | Prints θ | Also writes θ into `<model>.json` | P2-7 |
| 7 | `realtime_daemon.main`, `evaluate_live.main` | `default=0.40` | θ from the sidecar; error if it is missing | P2-7 |
| 8 | `algorithm_4_hybrid.evaluate_model` | P/R/F1/accuracy | Also FPR, FNR, ROC-AUC, PR-AUC | P2-8 |
| 9 | `algorithm_4_hybrid.node_hash_text`, `featurize_node`, `FORWARD_EDGE_TYPES` | v2 | New `FEATURE_VERSION=3` (v2 left unchanged) | P3 |

---

## K. Experiment matrix (as actually implemented)

| Experiment | Training data | Validation | Test data | Unseen? | θ source | Purpose |
|---|---|---|---|---|---|---|
| E1 (v2) | dev train split (all 13 templates) + prefixes + pgbench_1 | dev val split + prefixes + pgbench_2 | dataset_test (226) | **No**: same templates, different seed | v2 val → 0.55 | Known-template detection |
| H1 holdout | as E1, minus priv_abuse | as E1, minus priv_abuse | dataset_test (priv_abuse = 16) | Template yes, technique partly | holdout val → 0.55 | Unseen-template detection |
| 4a | (v2) | — | live pgbench | No (pgbench was in training) | 0.55 (v2) / 0.40 (v1) | Live false alarms |
| 4b | (v2) | — | live benign scenarios | No | same | Live false alarms |
| 4c | (v2) | — | live benign + pgbench | No | same | Live false alarms under load |
| 5a | (v2) | — | live attacks | No | same | Live detection and latency |
| 5b | (v2 / holdout) | — | live mixed, 1251 sessions | No (holdout: priv_abuse unseen) | 0.55 | Live mixed traffic |
| 4D | — | — | **does not exist** | — | — | Planned out-of-distribution environment |
| Proposed LOTO | all but 2 templates | 1 different template | 1 held-out template | **Yes** | fold val | Real generalization |
