#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_privilege_abuse.sh (legacy: casce_tpcb, -U postgres).
# Connection and label changed per call; pgbench_tellers has no banking equivalent, so the
# third statement targets accounts instead (see ../ood_4d/sample_sessions.sh note on this).
# Three psql calls = three sessions = three manifest lines (see manifest.jsonl).
#
# CAVEAT: step 1 (create the backdoor role) is expected to be denied -- dba has CREATEROLE
# but not the right to grant SUPERUSER (only a real superuser can). Steps 2 and 3 then try
# to connect AS "hacker", a role that was never created, so those two connections are
# expected to fail outright (authentication failure, before the Postgres hook attaches).
# Keep them anyway: a workload that reproduces the live DB's actual denial behaviour is
# more informative than one rewritten to always succeed, and the caller already treats a
# statement-level denial as a valid, expected 4D result (see the two "correctly denied"
# attack statements in the existing run_live_scenarios.py --check-sql result).
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: privilege abuse / backdoor role creation, repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:privabuse_create_role_r${REPEAT}" \
  $PSQL -U dba -c "CREATE ROLE hacker WITH SUPERUSER LOGIN PASSWORD 'hacked';"

export PGPASSWORD='hacked'
PGAPPNAME="casce_label=Malicious:privabuse_disable_logging_r${REPEAT}" \
  $PSQL -U hacker -c "SELECT set_config('log_statement', 'none', false);"
PGAPPNAME="casce_label=Malicious:privabuse_tamper_balance_r${REPEAT}" \
  $PSQL -U hacker -c "UPDATE accounts SET balance = 99999 WHERE account_id = 1;"
unset PGPASSWORD
