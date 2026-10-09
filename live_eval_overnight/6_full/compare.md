## 6_full: final verdicts per traffic group (flagged / sessions)

| Group | daemon_v2_replay | daemon_v3_live | daemon_v3_replay |
|---|---|---|---|
| Attacks: all attempted | 93/93 | 93/93 | 93/93 |
| Attacks: executed | 56/56 | 56/56 | 56/56 |
| Attacks: refused by Postgres | 37/37 | 37/37 | 37/37 |
| Benign scenarios (dataset_test) | 0/133 | 0/133 | 0/133 |
| Benign extra templates | 94/240 | 17/240 | 17/240 |
| pgbench | 0/2335 | 0/2335 | 0/2335 |
| Precision / recall / F1 | 0.497 / 1.000 / 0.664 | 0.845 / 1.000 / 0.916 | 0.845 / 1.000 / 0.916 |
| FPR (all benign) | 0.0347 (94/2708) | 0.0063 (17/2708) | 0.0063 (17/2708) |
| Real-time alerts on sessions finally benign | 0 | 35 | 35 |
| Attack alert latency median / p90 / max (s) | 940.48 / 1294.42 / 1404.89 | 5.48 / 8.49 / 12.78 | 1004.21 / 1359.43 / 1484.18 |

## Benign templates: false alarms

| Template | daemon_v2_replay | daemon_v3_live | daemon_v3_replay |
|---|---|---|---|
| audit_archive | 43/43 | 0/43 | 0/43 |
| bi_export | 35/35 | 0/35 | 0/35 |
| compliance_audit | 0/32 | 0/32 | 0/32 |
| dba_shadow_audit | 0/13 | 0/13 | 0/13 |
| etl_internal | 0/15 | 0/15 | 0/15 |
| etl_repl_ben | 0/14 | 0/14 | 0/14 |
| kyc_review | 0/40 | 0/40 | 0/40 |
| manager_eod | 0/28 | 0/28 | 0/28 |
| nightly_backup | 0/44 | 0/44 | 0/44 |
| replica_health | 16/43 | 17/43 | 17/43 |
| teller_routine | 0/31 | 0/31 | 0/31 |
| user_provisioning | 0/35 | 0/35 | 0/35 |
