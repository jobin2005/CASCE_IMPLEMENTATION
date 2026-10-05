#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_sqli_time.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the statement is unchanged (pg_sleep needs no table).
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: SQL injection (time-based blind probe), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:sqli_time_r${REPEAT}" \
  $PSQL -U teller -c "SELECT pg_sleep(2);"
