#!/bin/bash
echo "Simulating Sabotage Attack (Attack 2)..."

/dataset_workspace/logger.sh mark_attack "attack_sabotage" start

# Drop critical operational tables
psql -U postgres -d casce_tpcb -c "DROP TABLE IF EXISTS pgbench_history CASCADE;"

/dataset_workspace/logger.sh mark_attack "attack_sabotage" end

echo "Sabotage attempted."
