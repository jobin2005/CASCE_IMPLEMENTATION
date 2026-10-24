#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_sqli_union.sh (legacy: casce_tpcb, -U postgres).
# Connection, table and label changed; the statement's structure (a deliberately
# mismatched UNION, probing column count) is unchanged. pgbench_accounts.aid -> accounts.account_id.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: SQL injection (UNION column-count probe), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:sqli_union_r${REPEAT}" \
  $PSQL -U teller -c "SELECT * FROM accounts WHERE account_id = 1 UNION ALL SELECT 1, 2, 3;"
