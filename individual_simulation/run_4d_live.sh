#!/usr/bin/env bash
# Run the 4D OOD attack workload inside the Docker container
# and capture events via the pg_telemetry hook.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTAINER="casce_environment"
ATTACK_DIR="workload_simulation/attack_workload_banking"
LIVE_DIR="${REPO_ROOT}/individual_simulation/live_4d_run"
REPEAT=1

mkdir -p "$LIVE_DIR"

echo "=== 4D Live Attack Run ==="
echo "Container: $CONTAINER"
echo "Repeat: $REPEAT"
echo ""

# Step 1: Copy attack scripts into the container
echo "[1/5] Copying attack scripts into container..."
docker cp "${REPO_ROOT}/${ATTACK_DIR}" "${CONTAINER}:/tmp/attack_workload_banking"

# Step 2: Clear old logs and ensure logging is active
echo "[2/5] Clearing old logs and enabling capture..."
docker exec -u root "$CONTAINER" bash -c '
  > /dataset_workspace/postgres_events.json
  > /dataset_workspace/session_labels.jsonl
  touch /dataset_workspace/.casce_logging_active
  chmod 666 /dataset_workspace/postgres_events.json /dataset_workspace/session_labels.jsonl /dataset_workspace/.casce_logging_active
  chown postgres:postgres /dataset_workspace/postgres_events.json /dataset_workspace/session_labels.jsonl
'

# Step 3: Run some benign workload first (for false alarm measurement)
echo "[3/5] Running benign workload..."
docker exec "$CONTAINER" bash -c '
  # Benign: normal teller queries
  PGAPPNAME="casce_label=Benign:normal_teller_query_1" \
    psql -X -q -h 127.0.0.1 -U teller -d casce_banking \
    -c "SELECT count(*) FROM accounts WHERE balance > 50000;"
  sleep 1
  PGAPPNAME="casce_label=Benign:normal_balance_check_1" \
    psql -X -q -h 127.0.0.1 -U teller -d casce_banking \
    -c "SELECT account_id, balance FROM accounts WHERE account_id = 42;"
  sleep 1
  PGAPPNAME="casce_label=Benign:normal_customer_lookup_1" \
    psql -X -q -h 127.0.0.1 -U teller -d casce_banking \
    -c "SELECT full_name, email FROM customers WHERE customer_id = 100;"
  sleep 1
  # Benign: compliance officer audit
  PGAPPNAME="casce_label=Benign:compliance_audit_1" \
    psql -X -q -h 127.0.0.1 -U compliance_officer -d casce_banking \
    -c "SELECT c.full_name, count(t.transaction_id) FROM customers c JOIN accounts a ON a.customer_id = c.customer_id JOIN transactions t ON t.account_id = a.account_id GROUP BY c.customer_id, c.full_name HAVING count(t.transaction_id) > 100 LIMIT 10;"
  sleep 1
  # Benign: DBA maintenance
  PGAPPNAME="casce_label=Benign:dba_maintenance_1" \
    psql -X -q -h 127.0.0.1 -U dba -d casce_banking \
    -c "SELECT schemaname, tablename, n_live_tup, last_vacuum FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 5;"
  sleep 1
  # Benign: branch manager report
  PGAPPNAME="casce_label=Benign:branch_report_1" \
    psql -X -q -h 127.0.0.1 -U branch_manager -d casce_banking \
    -c "SELECT b.branch_name, count(a.account_id) as num_accounts, sum(a.balance) as total_balance FROM branches b JOIN accounts a ON a.branch_id = b.branch_id GROUP BY b.branch_id, b.branch_name ORDER BY total_balance DESC LIMIT 5;"
  sleep 1
  echo "  Benign workload done (6 sessions)"
'

# Step 4: Run ALL 30 attack scripts (REPEAT=1)
echo "[4/5] Running 4D attack workload (30 scripts)..."
# Run all scripts EXCEPT sabotage (which goes last)
for script in \
  attack_exfil_var_0.sh attack_exfil_var_1.sh attack_exfil_var_2.sh \
  attack_exfil_var_4.sh attack_exfil_var_5.sh attack_exfil_var_6.sh \
  attack_exfil_var_8.sh attack_exfil_var_9.sh attack_exfil_var_10.sh \
  attack_exfil_var_12.sh attack_exfil_var_13.sh attack_exfil_var_14.sh \
  attack_exfil_var_16.sh attack_exfil_var_17.sh attack_exfil_var_18.sh \
  attack_priv_var_cat_passwd.sh attack_priv_var_cat_shadow.sh \
  attack_priv_var_chmod_tmp.sh attack_priv_var_crontab_persist.sh \
  attack_priv_var_enum_system.sh attack_priv_var_find_keys.sh \
  attack_priv_var_remote_bash.sh \
  attack_sqli_copy.sh attack_sqli_role.sh attack_sqli_time.sh attack_sqli_union.sh \
  attack_reverse_shell.sh \
  attack_privilege_abuse.sh attack_multi_session_apt.sh \
  attack_sabotage.sh
do
  echo "  Running: $script"
  docker exec -e REPEAT=$REPEAT "$CONTAINER" bash "/tmp/attack_workload_banking/$script" 2>&1 || true
  sleep 1
done

# Step 5: Stop logging and copy results out
echo "[5/5] Stopping capture and copying results..."
docker exec -u root "$CONTAINER" rm -f /dataset_workspace/.casce_logging_active

# Copy captured events out
docker cp "${CONTAINER}:/dataset_workspace/postgres_events.json" "${LIVE_DIR}/postgres_events.json"
docker cp "${CONTAINER}:/dataset_workspace/session_labels.jsonl" "${LIVE_DIR}/session_labels.jsonl" 2>/dev/null || true

# Copy the manifest
cp "${REPO_ROOT}/${ATTACK_DIR}/manifest.jsonl" "${LIVE_DIR}/manifest.jsonl"

# Count what we captured
PG_EVENTS=$(wc -l < "${LIVE_DIR}/postgres_events.json")
echo ""
echo "=== Capture Complete ==="
echo "  postgres_events.json: ${PG_EVENTS} events"
echo "  Output directory: ${LIVE_DIR}/"
echo ""
echo "Next: run main.py to build graphs, then render them."
