#!/usr/bin/env bash
# 4D reference sample: what ONE labelled live session looks like, and how a
# legacy script from ../attack_workload/ is adapted to it. See EXPERIMENTS.md,
# "4D: plan".
#
# Rules for every session in the 4D workload:
#   1. One psql call = one session = one label.
#   2. Label via PGAPPNAME=casce_label=<Benign|Malicious>:<group>_<name>_r<repeat>
#      (the Postgres hook writes it to session_labels.jsonl only; the detector
#      never sees it).
#   3. Database casce_banking over TCP (-h 127.0.0.1), as a banking role
#      (teller, branch_manager, compliance_officer, batch_etl_service, dba),
#      never -U postgres / -d casce_tpcb.
#   4. One manifest line per session in manifest.jsonl (see bottom).
#
# Run inside the container (docker exec -i -u root casce_environment bash < this file)
# while logger.sh is capturing.
set -u
REPEAT=${REPEAT:-1}
PSQL="psql -X -q -h 127.0.0.1 -d casce_banking"

# --- Example 1: a benign session (backup by the DBA) -----------------------
PGAPPNAME="casce_label=Benign:backup_accounts_r${REPEAT}" \
  $PSQL -U dba -c "COPY (SELECT account_id, branch_id, balance FROM accounts) TO PROGRAM 'gzip > /var/backups/postgresql/accounts_r${REPEAT}.csv.gz'"

# --- Example 2: adapting a legacy attack script ----------------------------
# Original (../attack_workload/attack_sqli_union.sh):
#   psql -U postgres -d casce_tpcb -c "<SQL on pgbench_accounts>"
# Adapted -- only three things change, the attack logic stays as written:
#   a) connection:  -U postgres -d casce_tpcb   ->  -h 127.0.0.1 -U teller -d casce_banking
#   b) tables:      pgbench_accounts(aid, bid, abalance) -> accounts(account_id, branch_id, balance)
#                   pgbench_branches -> branches,  pgbench_history -> transactions
#                   (pgbench_tellers has no banking equivalent: use accounts or customers)
#   c) label:       PGAPPNAME="casce_label=Malicious:sqli_union_r${REPEAT}"
# i.e.:
#   PGAPPNAME="casce_label=Malicious:sqli_union_r${REPEAT}" $PSQL -U teller -c "<the script's SQL, tables renamed>"
# Statements a teller is not allowed to run fail with "permission denied";
# that is fine and expected -- the attempt is still captured and labelled.

# --- manifest.jsonl: one line per session ----------------------------------
# {"key": "backup_accounts_r1", "class": "benign", "group": "backup", "new_technique": true,
#  "source": "benign_edge_cases.sh", "role": "dba", "repeat": 1}
# {"key": "sqli_union_r1", "class": "malicious", "group": "sql_injection", "new_technique": true,
#  "source": "attack_sqli_union.sh", "role": "teller", "repeat": 1}
#
# group: exfiltration | os_command | sql_injection | reverse_shell | sabotage |
#        backdoor_role | multi_stage  (benign: backup | maintenance | reporting | app_traffic)
# new_technique: false only for backdoor CREATE ROLE and plain curl exfiltration
#                (those resemble the training templates).
# Ordering: anything that drops a table runs last, after pgbench stops.
# Skip scripts that never call psql (OS-only); list them as excluded.
