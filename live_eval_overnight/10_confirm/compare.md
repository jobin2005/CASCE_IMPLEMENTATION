## 10_confirm: final verdicts per traffic group (flagged / sessions)

| Group | daemon_v3_live | daemon_v3p_live | daemon_v3p_ens2_live |
|---|---|---|---|
| Attacks: all attempted | 57/57 | 57/57 | 57/57 |
| Attacks: executed | 31/31 | 31/31 | 31/31 |
| Attacks: refused by Postgres | 26/26 | 26/26 | 26/26 |
| Benign scenarios (13 standard templates) | 0/61 | 0/61 | 0/61 |
| Benign extra templates | 2/60 | 0/60 | 0/60 |
| pgbench | 0/937 | 0/937 | 0/937 |
| Precision / recall / F1 | 0.966 / 1.000 / 0.983 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| FPR (all benign) | 0.0019 (2/1058) | 0.0000 (0/1058) | 0.0000 (0/1058) |
| Real-time alerts on sessions finally benign | 7 | 0 | 0 |
| Attack alert latency median / p90 / max (s) | 1.59 / 2.63 / 2.92 | 1.56 / 2.58 / 3.01 | 1.66 / 2.59 / 3.15 |

## Benign templates: false alarms

| Template | daemon_v3_live | daemon_v3p_live | daemon_v3p_ens2_live |
|---|---|---|---|
| audit_archive | 0/12 | 0/12 | 0/12 |
| bi_export | 0/11 | 0/11 | 0/11 |
| compliance_audit | 0/15 | 0/15 | 0/15 |
| dba_shadow_audit | 0/5 | 0/5 | 0/5 |
| etl_internal | 0/5 | 0/5 | 0/5 |
| etl_repl_ben | 0/6 | 0/6 | 0/6 |
| kyc_review | 0/9 | 0/9 | 0/9 |
| manager_eod | 0/16 | 0/16 | 0/16 |
| nightly_backup | 0/11 | 0/11 | 0/11 |
| replica_health | 2/10 | 0/10 | 0/10 |
| teller_routine | 0/14 | 0/14 | 0/14 |
| user_provisioning | 0/7 | 0/7 | 0/7 |
