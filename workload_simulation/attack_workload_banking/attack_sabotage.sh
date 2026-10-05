#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_sabotage.sh (legacy: casce_tpcb, -U postgres).
# Connection, table and label changed; the statement itself is unchanged.
# pgbench_history (append-only ledger) -> transactions (its banking equivalent).
# MUST run last in the batch, after pgbench stops (see manifest.jsonl / README).
# dba has no DROP privilege on this table either, so this is expected to be denied;
# the attempt is still captured and labelled.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: sabotage (drop table), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:sabotage_drop_transactions_r${REPEAT}" \
  $PSQL -U dba -c "DROP TABLE IF EXISTS transactions CASCADE;"
