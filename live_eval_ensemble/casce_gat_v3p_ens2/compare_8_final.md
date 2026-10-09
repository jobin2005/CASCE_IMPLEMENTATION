## 8_final: final verdicts per traffic group (flagged / sessions)

| Group | daemon_v3_live | daemon_v3p_live | daemon_v3p_s7_replay | daemon_v3p_ens2_replay |
|---|---|---|---|---|
| Attacks: all attempted | 93/93 | 93/93 | 81/93 | 93/93 |
| Attacks: executed | 56/56 | 56/56 | 56/56 | 56/56 |
| Attacks: refused by Postgres | 37/37 | 37/37 | 25/37 | 37/37 |
| Benign scenarios (dataset_test) | 0/133 | 3/133 | 0/133 | 0/133 |
| Benign extra templates | 8/120 | 0/120 | 0/120 | 0/120 |
| pgbench | 0/1654 | 0/1654 | 0/1654 | 0/1654 |
| Precision / recall / F1 | 0.921 / 1.000 / 0.959 | 0.969 / 1.000 / 0.984 | 1.000 / 0.871 / 0.931 | 1.000 / 1.000 / 1.000 |
| FPR (all benign) | 0.0042 (8/1907) | 0.0016 (3/1907) | 0.0000 (0/1907) | 0.0000 (0/1907) |
| Real-time alerts on sessions finally benign | 19 | 0 | 0 | 0 |
| Attack alert latency median / p90 / max (s) | 1.63 / 2.43 / 3.14 | 1.61 / 2.43 / 3.09 | 11605.67 / 12029.24 / 12145.73 | 13214.57 / 13621.37 / 13751.38 |

## Benign templates: false alarms

| Template | daemon_v3_live | daemon_v3p_live | daemon_v3p_s7_replay | daemon_v3p_ens2_replay |
|---|---|---|---|---|
| audit_archive | 0/25 | 0/25 | 0/25 | 0/25 |
| bi_export | 0/14 | 0/14 | 0/14 | 0/14 |
| compliance_audit | 0/32 | 0/32 | 0/32 | 0/32 |
| dba_shadow_audit | 0/13 | 0/13 | 0/13 | 0/13 |
| etl_internal | 0/15 | 0/15 | 0/15 | 0/15 |
| etl_repl_ben | 0/14 | 0/14 | 0/14 | 0/14 |
| kyc_review | 0/20 | 0/20 | 0/20 | 0/20 |
| manager_eod | 0/28 | 0/28 | 0/28 | 0/28 |
| nightly_backup | 0/26 | 0/26 | 0/26 | 0/26 |
| replica_health | 8/16 | 0/16 | 0/16 | 0/16 |
| teller_routine | 0/31 | 3/31 | 0/31 | 0/31 |
| user_provisioning | 0/19 | 0/19 | 0/19 | 0/19 |
