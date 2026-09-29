#!/bin/bash
echo "Simulating SQL Injection Attack (attack_sqli_time)..."
/dataset_workspace/logger.sh mark_attack "attack_sqli_time" start
psql -U postgres -d casce_tpcb -c "SELECT pg_sleep(2);"
/dataset_workspace/logger.sh mark_attack "attack_sqli_time" end
