#!/bin/bash
echo "Simulating SQL Injection Attack (attack_sqli_role)..."
/dataset_workspace/logger.sh mark_attack "attack_sqli_role" start
psql -U postgres -d casce_tpcb -c "CREATE ROLE sqli_admin SUPERUSER LOGIN PASSWORD 'hacked';"
/dataset_workspace/logger.sh mark_attack "attack_sqli_role" end
