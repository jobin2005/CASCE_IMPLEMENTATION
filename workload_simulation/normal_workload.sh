#!/bin/bash
echo "Starting normal workload simulation using pgbench..."

pgbench -c 50 -j 4 -t 100 -U postgres -d casce_tpcb > /dev/null 2>&1

echo "Simulating Benign Administrative Tasks (False-Positive Stress Testing)..."

psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 1000) TO '/tmp/legit_admin_backup.csv';" > /dev/null 2>&1

echo "1,admin,setup" > /tmp/legit_seed_data.csv
psql -U postgres -d casce_tpcb -c "CREATE TABLE IF NOT EXISTS temp_load (id INT, role TEXT, note TEXT);" > /dev/null 2>&1
psql -U postgres -d casce_tpcb -c "COPY temp_load FROM '/tmp/legit_seed_data.csv' DELIMITER ',';" > /dev/null 2>&1

psql -U postgres -d casce_tpcb -c "VACUUM FULL pgbench_accounts;" > /dev/null 2>&1

psql -U postgres -d casce_tpcb -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" > /dev/null 2>&1 || true

echo "Normal workload simulation completed."
