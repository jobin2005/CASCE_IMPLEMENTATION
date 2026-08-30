#!/bin/bash
echo "Simulating Sabotage Attack (Attack 2)..."

# Drop critical operational tables
psql -U postgres -d casce_tpcb -c "DROP TABLE IF EXISTS pgbench_history CASCADE;"

echo "Sabotage attempted."
