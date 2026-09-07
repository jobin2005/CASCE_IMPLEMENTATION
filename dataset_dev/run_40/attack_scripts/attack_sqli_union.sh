#!/bin/bash
echo "Simulating SQL Injection Attack (attack_sqli_union)..."
/dataset_workspace/logger.sh mark_attack "attack_sqli_union" start
psql -U postgres -d casce_tpcb -c "SELECT * FROM pgbench_accounts WHERE aid = 1 UNION ALL SELECT 1, 2, 3;"
/dataset_workspace/logger.sh mark_attack "attack_sqli_union" end
