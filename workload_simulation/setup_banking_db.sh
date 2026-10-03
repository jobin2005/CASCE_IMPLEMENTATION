#!/bin/bash
# One-time setup of the live banking database that the synthetic scenarios
# (datagen/domains/banking.yaml) are written against. Run as root inside
# casce_environment, from the host:
#
#   docker exec -i -u root casce_environment bash < workload_simulation/setup_banking_db.sh
#
# Idempotent: re-running drops and recreates casce_banking and its data.
# pgbench's casce_tpcb database is not touched.
set -euo pipefail

DB=casce_banking
PSQL="psql -X -q -v ON_ERROR_STOP=1 -U postgres"

echo "[1/5] tools: iproute2 (the scenario runner makes endpoint IPs local so curl fails fast)"
if ! command -v ip >/dev/null; then
    apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null
fi

echo "[2/5] database $DB"
$PSQL -d postgres -c "DROP DATABASE IF EXISTS $DB WITH (FORCE);"
$PSQL -d postgres -c "CREATE DATABASE $DB;"
# CASCE hook for every new session in this database (same as casce_tpcb)
$PSQL -d postgres -c "ALTER DATABASE $DB SET session_preload_libraries = 'pg_telemetry';"

echo "[3/5] schema + seed data"
$PSQL -d $DB <<'SQL'
CREATE TABLE branches (
    branch_id  text PRIMARY KEY,
    name       text NOT NULL,
    is_active  boolean NOT NULL DEFAULT true
);
CREATE TABLE customers (
    customer_id integer PRIMARY KEY,
    full_name   text NOT NULL,
    national_id text NOT NULL,
    address     text NOT NULL,
    branch_id   text NOT NULL REFERENCES branches
);
CREATE TABLE accounts (
    account_id   integer PRIMARY KEY,
    customer_id  integer NOT NULL REFERENCES customers,
    branch_id    text NOT NULL REFERENCES branches,
    account_type text NOT NULL,
    balance      numeric(14,2) NOT NULL,
    updated_at   timestamp NOT NULL DEFAULT now()
);
CREATE TABLE transactions (
    transaction_id   bigserial PRIMARY KEY,
    account_id       integer NOT NULL REFERENCES accounts,
    amount           numeric(14,2) NOT NULL,
    counterparty     text NOT NULL,
    transaction_time timestamp NOT NULL
);
CREATE TABLE audit_logs (
    log_id     bigserial PRIMARY KEY,
    actor      text NOT NULL,
    action     text NOT NULL,
    logged_at  timestamp NOT NULL DEFAULT now()
);

-- 30 branches: BR-001 .. BR-030 (scenarios use BR-001/002/003/014/027)
INSERT INTO branches
SELECT format('BR-%s', lpad(i::text, 3, '0')), format('Branch %s', i), i <> 30
FROM generate_series(1, 30) i;

-- 10,000 customers (scenario literals go up to customer_id 9809)
INSERT INTO customers
SELECT i,
       format('Customer %s', i),
       format('NID-%s', lpad((i * 7919 % 1000000)::text, 6, '0')),
       format('%s Main Road, City %s', i % 500, i % 40),
       format('BR-%s', lpad((1 + i % 30)::text, 3, '0'))
FROM generate_series(1::bigint, 10000) i;

-- 100,000 accounts, 10 per customer (scenario literals go up to account_id 97880)
INSERT INTO accounts (account_id, customer_id, branch_id, account_type, balance)
SELECT a, c.customer_id, c.branch_id,
       (ARRAY['savings','current','fixed_deposit'])[1 + (a % 3)::int],
       round((a * 104729 % 500000)::numeric / 1.7, 2)
FROM generate_series(1::bigint, 100000) a
JOIN customers c ON c.customer_id = 1 + (a - 1) % 10000;

-- 300,000 transactions spread over 2026
INSERT INTO transactions (account_id, amount, counterparty, transaction_time)
SELECT 1 + (t * 7349 % 100000),
       round((t * 31337 % 120000)::numeric / 1.3, 2),
       (ARRAY['Customer Transfer','Salary','Utility Bill','Card Payment','Loan EMI'])[1 + (t % 5)::int],
       timestamp '2026-01-01' + (t * 97 % 31536000) * interval '1 second'
FROM generate_series(1::bigint, 300000) t;

INSERT INTO audit_logs (actor, action)
SELECT 'system', format('nightly job %s', i) FROM generate_series(1, 1000) i;

CREATE INDEX ON accounts (branch_id);
CREATE INDEX ON accounts (customer_id);
CREATE INDEX ON customers (branch_id);
CREATE INDEX ON transactions (account_id);
CREATE INDEX ON transactions (transaction_time);
ANALYZE;
SQL

echo "[4/5] roles (the banking domain's roles, incl. dba for the benign_extra templates)"
$PSQL -d $DB <<'SQL'
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['teller','branch_manager','compliance_officer','batch_etl_service'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN', r);
        END IF;
    END LOOP;
END $$;

GRANT CONNECT ON DATABASE casce_banking TO teller, branch_manager, compliance_officer, batch_etl_service;
GRANT USAGE ON SCHEMA public TO teller, branch_manager, compliance_officer, batch_etl_service;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO teller, branch_manager, compliance_officer, batch_etl_service;
GRANT INSERT, UPDATE ON accounts, transactions TO teller, batch_etl_service;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO teller, batch_etl_service;
-- every scenario's OS activity comes from COPY ... TO PROGRAM
GRANT pg_execute_server_program TO teller, branch_manager, compliance_officer, batch_etl_service;
-- the compliance password-policy audit reads pg_authid
GRANT SELECT ON pg_catalog.pg_authid TO compliance_officer;

-- dba (benign_extra templates): provisions ordinary logins, runs audit-log retention
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dba') THEN
        CREATE ROLE dba LOGIN CREATEROLE;
    END IF;
END $$;
GRANT CONNECT ON DATABASE casce_banking TO dba;
GRANT USAGE ON SCHEMA public TO dba;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dba;
GRANT DELETE ON audit_logs TO dba;
GRANT pg_execute_server_program, pg_read_all_stats TO dba;
SQL

echo "[5/5] folders the scenarios write into"
for d in /var/lib/postgresql/reports /var/lib/postgresql/audit /var/lib/postgresql/.cache /tmp/.cache \
         /var/lib/postgresql/kyc /var/backups/postgresql /var/backups/audit; do
    mkdir -p "$d" && chown postgres:postgres "$d"
done

$PSQL -d $DB -c "SELECT (SELECT count(*) FROM customers) AS customers, (SELECT count(*) FROM accounts) AS accounts, (SELECT count(*) FROM transactions) AS transactions;"
echo "casce_banking ready."
