#!/bin/bash
echo "Simulating DB-only Unauthorized Query (Category 2)..."

# An attacker queries a sensitive table inside the DB layer but doesn't write to disk or network.
# Thus, no anomalous kernels traces are produced. Relying exclusively on DB detection.
psql -U postgres -d casce_tpcb -c "SELECT aid, abalance FROM pgbench_accounts ORDER BY abalance DESC LIMIT 5000;" > /dev/null

echo "DB-only unauthorized query simulated."
