# Template-disjoint (LOTO) results: running notes

Per-fold notes written while the seed-1 runs finished. **All 21 runs are complete; the final table and conclusions are in `EXPERIMENTS.md` → "T: template-disjoint evaluation".** Seeds 2–3 changed some folds a lot (e.g. compliance_exfil recall 0 → 1), so use the 3-seed numbers there, not the seed-1 numbers below.

## etl_exfil_mal, seed 1 (finished 22:33)
- **Fold design.** Test: unseen `etl_exfil_mal` (62 sessions) and `etl_repl_ben` (62). Validation: unseen `multi_apt` and `manager_eod`.
- **Training.** Validation loss was lowest at epoch 1 (2.98) and **rose** after that (8.8 by epoch 5). Early stopping kept the epoch-1 model. The better the model fits the training templates, the worse it does on an unseen one, which is the shortcut-learning signature.
- **θ = 0.10.** Validation F1 was 1.0 only at θ 0.05–0.10, so the GAT detects unseen `multi_apt` only weakly.
- **Unseen test:** TP 62, FN 0, FP 62, TN 0, so recall 1.0 and FPR 1.0. ROC-AUC is **0.0** on the fused risk and 0.5 on the GAT score alone.
  - **This is not a bug.** The GAT scores every graph of the unseen ETL pair at 0, so risk comes from the rule engine alone. The rules give benign replication 0.2962 and exfiltration 0.2927 (both "ingress tool transfer"). At θ 0.10 both are flagged.
  - **In plain terms, without ETL templates in training the model cannot distinguish exfiltration to an external host from replication to an internal one.** The two sessions differ mainly in their destination.
- **Seen templates at θ 0.10.** All seen attacks are still detected, but seen benign `etl_internal` gets 15 of 15 false alarms (seen-test FPR 0.165). The low θ chosen on an unseen validation template costs false alarms elsewhere.

## defense_impair, seed 1 (finished 22:35)
- **Fold design.** Test: unseen `defense_impair` (72 sessions) and `etl_internal` (76). Validation: unseen `etl_exfil_mal` and `etl_repl_ben`, the matched ETL pair.
- **Training.** As before, validation loss was best at epoch 1 and rose afterwards (up to 15.1).
- **θ = 0.45.** On validation, precision is 0.5 at every θ: the model flags benign and malicious ETL replication alike.
- **Unseen test:** TP 72, FN 0, FP 76, TN 0, so recall 1.0 and FPR 1.0.
  - The **unseen attack** `defense_impair` is detected (risk 0.80).
  - The **unseen benign** `etl_internal` (`COPY … TO PROGRAM curl` to an internal replica) gets GAT 1.0 and is flagged in all 76 sessions.
  - ROC-AUC 0.0 is a degenerate value: both classes saturate at GAT = 1.0, and the slightly higher rule score of the benign sessions decides the order. The meaningful statement is that **the two are not separable**.
- **Pattern across both folds.** The model has learned "data leaves the database through COPY TO PROGRAM / curl, so this is an attack". It handles benign ETL/replication correctly **only when that exact benign template was in training**. Unseen benign sessions that move data out are false alarms, and unseen exfiltration that resembles benign ETL is missed.

## compliance_exfil, seed 1 (finished 22:37)
- **Fold design.** Test: unseen `compliance_exfil` (78 sessions) and `dba_shadow_audit` (40). Validation: unseen `defense_impair` and `etl_internal`.
- **Training.** Validation loss was best at epoch 1 and rose to 13.95.
- **θ = 0.70**, tuned on validation.
- **Unseen test:** TP 0, FN 78, FP 0, TN 40, so recall 0.0 and FPR 0.0. However, ROC-AUC is **1.0** on both the fused risk and the GAT alone.
  - Unseen attacks score 0.47–0.54 and unseen benign sessions score 0.014, so the ranking is perfect.
  - θ = 0.70, chosen on a *different* unseen template, sits above every attack. **All 78 are missed.**
- **This is the "good ranking, wrong threshold" case.** On unseen templates the score scale shifts from template to template, so a θ tuned on one unseen template does not transfer to another.

## alter_role_esc, seed 1 (finished 23:03)
- **Fold design.** Test: unseen `alter_role_esc` (35 sessions) and `compliance_audit` (145). Validation: unseen `compliance_exfil` and `dba_shadow_audit`.
- **Training.** Validation loss bounced (0.66, 0.73, 1.63, 1.73, **0.24**, 3.49, …), so the best model came from epoch 5. θ = 0.65.
- **Unseen test:** TP 35, FN 0, FP 0, TN 145, so recall 1.0, FPR 0.0 and ROC-AUC 1.0. This is a **clean success** on an unseen template: `ALTER ROLE … SUPERUSER` followed by exfiltration.
- **Trade-off on seen templates.** On the dataset_test copies of training templates, seen F1 is only 0.767: `priv_abuse` was detected in 0 of 16 sessions and `multi_apt` in 6 of 18.
  - Both templates *were* in training. Early stopping, now driven by an unseen validation template, stops before the model has fully fit them.
  - Optimising for unseen templates costs accuracy on seen ones.

## multi_apt, seed 1 (finished 23:11)
- **Fold design.** Test: unseen `multi_apt` (96 sessions: recon, escalate and exfil stages) and `manager_eod` (153). Validation: unseen `priv_abuse` and `teller_routine`.
- **Training.** Validation loss was 5.8 at epoch 1 and rose to 29.8, so the epoch-1 model was kept. θ = 0.65.
- **Unseen test:** TP 0, FN 96, FP 0, TN 153, so recall 0.0, FPR 0.0 and ROC-AUC 0.67.
  - Most `multi_apt` sessions score exactly 0. The highest score is 0.545, which is below θ.
  - **The unseen multi-stage APT goes completely undetected.** Its individual stages (recon queries, `CREATE ROLE`, curl exfiltration) resemble steps of other attacks, but this model does not recognise them.
- **Seen templates.** Seen `etl_exfil_mal` is missed too (0 of 14), with scores of 0.54–0.56, just below θ.

## priv_abuse, seed 1 (finished 23:20)
- **Fold design.** Test: unseen `priv_abuse` (84 sessions) and `teller_routine` (142). Validation: unseen `teller_pii_dump` and `compliance_audit`.
- **Training.** Validation loss stayed low (0.04–0.43); the best model was from epoch 2. θ = 0.55.
- **Unseen test:** TP 84, FN 0, FP 5, TN 137, so recall 1.0, FPR 0.035, F1 0.971 and ROC-AUC 1.0. Seen templates: F1 1.0.
- This beats the earlier single holdout model, which detected 27 of these 84 sessions at the same θ. The difference comes from the validation template, which changes early stopping and θ, and from seed variance.
- **Caveat (as before).** The kept training templates `multi_apt` (`CREATE ROLE … SUPERUSER`, `pg_authid` dump) and `alter_role_esc` (`ALTER ROLE … SUPERUSER`) cover priv_abuse's key steps, so this template is unseen but its technique is not new.

## teller_pii_dump, seed 1 (finished 23:34)
- **Fold design.** Test: unseen `teller_pii_dump` (81 sessions) and `compliance_audit` (145). Validation: unseen `alter_role_esc` and `dba_shadow_audit`. θ = 0.60.
- **Unseen test:** TP 73, FN 8, FP 145, TN 0, so recall 0.90 and FPR 1.0. ROC-AUC is **0.0, and 0.0 on the GAT alone too**, so this is a true inversion rather than a tie.
  - The unseen **benign** `compliance_audit` scores 0.74, *higher* than the unseen **attack** `teller_pii_dump` at 0.57–0.70.
  - A compliance audit legitimately reads sensitive customer data in bulk. Without that benign template in training, the model treats it as more suspicious than the actual PII dump.

## Pattern so far (seed 1)
| Unseen attack fold | Recall | FPR | ROC-AUC | Failure mode |
|---|---|---|---|---|
| etl_exfil_mal | 1.00 | 1.00 | 0.0 (degenerate) | GAT ≈ 0 for the whole unseen ETL pair; θ = 0.10 flags everything |
| defense_impair | 1.00 | 1.00 | 0.0 (degenerate) | Attack caught, but unseen benign ETL also gets GAT = 1.0 |
| compliance_exfil | 0.00 | 0.00 | 1.0 | Perfect ranking, θ too high |
| alter_role_esc | 1.00 | 0.00 | 1.0 | None (but seen priv_abuse/multi_apt missed) |
| multi_apt | 0.00 | 0.00 | 0.67 | Unseen APT scored ≈ 0, missed entirely |
| priv_abuse | 1.00 | 0.035 | 1.0 | Small FPR on unseen teller_routine |
| teller_pii_dump | 0.90 | 1.00 | 0.0 (true inversion) | Unseen benign compliance audit scored above the attack |
| **Macro over 7 folds** | **0.70** | **0.43** | **0.52** | F1 0.54; pooled TN 475, FP 288, FN 182, TP 326 |

**Seed-1 conclusion.** Once the test templates are genuinely unseen, performance falls from F1 ≈ 0.99 to a macro F1 of 0.54. ROC-AUC averages 0.52, which is chance level on average, though it varies widely from fold to fold.
- **Generalizes:** 2 of 7 attack templates, `alter_role_esc` and `priv_abuse`. Both share key SQL steps with other training attacks.
- **Fails in three distinct ways:**
  1. Unseen benign data movement or bulk reads are flagged as attacks: ETL, compliance audit.
  2. Unseen attacks score near 0: `multi_apt`.
  3. Ranking is right but the θ tuned on another unseen template doesn't transfer: `compliance_exfil`.

This is consistent with the shortcut finding: the model learns template-specific SQL and strings rather than general malicious behavior.

