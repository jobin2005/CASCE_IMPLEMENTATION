#!/usr/bin/env python3
"""Build a browsable graph catalog for seen and unseen attack/benign cases.

This creates a folder structure like:
  individual_simulation/graph_catalog/
    seen_attacks/
      attack_01_banking_priv_abuse/
        graph.png
        graphml/
    seen_benign/
      benign_01_banking_teller_routine/
        graph.png
        graphml/
    unseen_attacks/
      unseen_attack_01_case_04_unseen_malicious/
        graph.png
        graphml/
    unseen_benign/
      unseen_benign_01_case_03_unseen_benign/
        graph.png
        graphml/
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "individual_simulation"
OUT_ROOT = ROOT / "graph_catalog"
PAPER_SUITE = ROOT / "paper_4case_suite"


def safe_name(value: str) -> str:
    # Keep names readable and filesystem-safe.
    s = value.strip().lower()
    s = s.replace("/", "_")
    s = s.replace(" ", "_")
    s = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in s)
    s = s.strip("._-")
    return s or "case"


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _shorten_node_label(node_id: str, node_data: dict) -> str:
    """Create a concise, readable label from a raw GraphML node ID."""
    kind = node_data.get("type", node_data.get("label", "Unknown"))

    # Parse tuple-style IDs  like  ('Query', 5)  or  ('File', '/var/lib/...')
    import re
    m = re.match(r"\(\s*'(\w+)'\s*,\s*(.+)\s*\)", str(node_id))
    if m:
        ntype, value = m.group(1), m.group(2).strip().strip("'\"()")
    else:
        ntype = kind
        value = str(node_id)

    if ntype == "Behavior" or kind == "Behavior":
        # e.g. Behavior_DESTRUCTIVE_DB_OPERATION_3 → DESTR_DB_OP 3
        # behavior_label in data is the clean tag (e.g. "DATA_ACCESS")
        bl = node_data.get("behavior_label", "")
        if bl:
            tag = bl
        else:
            tag = str(node_id).replace("Behavior_", "")
        # Extract trailing sequence number from node ID
        id_str = str(node_id)
        parts = id_str.rsplit("_", 1)
        seq = parts[1] if len(parts) == 2 and parts[1].isdigit() else ""
        # Abbreviate long behaviour tags
        abbrevs = {
            "DESTRUCTIVE_DB_OPERATION": "DESTR_DB_OP",
            "DATA_ACCESS": "DATA_ACC",
            "UNIX_SHELL_EXECUTION": "SHELL_EXEC",
            "DEFENSE_IMPAIRMENT": "DEF_IMPAIR",
            "EXTERNAL_TRANSFER": "EXT_XFER",
            "POTENTIAL_INGRESS_TOOL_TRANSFER": "INGRESS_XFER",
            "PRIVILEGE_ESCALATION": "PRIV_ESC",
            "ROLE_CREATION": "ROLE_CRT",
            "SUSPICIOUS_GRANT": "SUSP_GRANT",
        }
        short = abbrevs.get(tag, tag[:18])
        return f"{short} {seq}".strip()

    if ntype == "File":
        # Keep only the filename from a path
        fname = value.rsplit("/", 1)[-1] if "/" in value else value
        return f"File:{fname[:20]}"

    if ntype == "Endpoint":
        # Simplify  ('192.168.1.100', 8443)  → 192…100:8443
        ep = value.replace("'", "").replace('"', '').strip("() ")
        parts = [p.strip() for p in ep.split(",")]
        if len(parts) == 2:
            ip, port = parts
            octets = ip.split(".")
            short_ip = f"{octets[0]}…{octets[-1]}" if len(octets) == 4 else ip[:12]
            return f"EP:{short_ip}:{port}"
        return f"EP:{ep[:18]}"

    if ntype == "Table":
        tname = node_data.get("table_name", value)
        return f"Tbl:{tname[:16]}"

    if ntype == "Query":
        return f"Q{value}"

    if ntype == "Session":
        return f"Sess:{value}"

    if ntype == "Process":
        comm = node_data.get("comm", "")
        return f"Proc:{comm}" if comm else f"Proc:{value}"

    if ntype == "Role":
        return f"Role:{value[:14]}"

    if ntype == "Target":
        return f"Tgt:{value[:14]}"

    return str(node_id)[:18]


def render_graph(graphml_path: Path, out_png: Path, title: str | None = None) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import networkx as nx
    import numpy as np

    G = nx.read_graphml(graphml_path)

    # ── colour palette (richer, with slight transparency for nodes) ──
    node_color_map = {
        "Session":  "#56CFE1",
        "Query":    "#FF9F1C",
        "Table":    "#FFD166",
        "Process":  "#06D6A0",
        "File":     "#EF476F",
        "Endpoint": "#118AB2",
        "Behavior": "#9B5DE5",
        "Role":     "#80B918",
        "Target":   "#F77F00",
        "Unknown":  "#CBD5E1",
    }

    edge_style_map = {
        "related":      {"color": "#4A4E69", "style": "solid",  "width": 1.4},
        "evidence_for": {"color": "#E63946", "style": "dashed", "width": 1.6},
        "precedes":     {"color": "#457B9D", "style": "dotted", "width": 1.8},
    }
    default_edge_style = {"color": "#6C757D", "style": "solid", "width": 1.2}

    # ── build working copy with layer subsets ──
    H = G.copy()
    layer_map = {
        "Session": 0, "Query": 1, "Table": 2, "File": 3,
        "Process": 4, "Endpoint": 5, "Behavior": 6,
        "Role": 7, "Target": 8, "Unknown": 9,
    }
    for node, data in H.nodes(data=True):
        kind = data.get("type", data.get("label", "Unknown"))
        data["subset"] = layer_map.get(kind, 9)

    # ── layout: multipartite then rescale for breathing room ──
    pos = nx.multipartite_layout(H, subset_key="subset", align="horizontal")

    # Spread layers out more on the y-axis and add jitter to reduce overlap
    xs = np.array([pos[n][0] for n in H.nodes()])
    ys = np.array([pos[n][1] for n in H.nodes()])
    if np.ptp(xs) > 0:
        for n in H.nodes():
            pos[n] = (pos[n][0] * 1.5, pos[n][1] * 2.0)

    # Fine-tune: within each layer, space nodes further apart horizontally
    from collections import defaultdict
    layer_nodes: dict[int, list] = defaultdict(list)
    for n in H.nodes():
        layer_nodes[H.nodes[n]["subset"]].append(n)

    for layer_id, nodes in layer_nodes.items():
        if len(nodes) <= 1:
            continue
        nodes_sorted = sorted(nodes, key=lambda n: pos[n][0])
        min_gap = 0.45  # minimum horizontal gap
        for i in range(1, len(nodes_sorted)):
            prev = nodes_sorted[i - 1]
            curr = nodes_sorted[i]
            gap = pos[curr][0] - pos[prev][0]
            if gap < min_gap:
                shift = min_gap - gap
                for j in range(i, len(nodes_sorted)):
                    pos[nodes_sorted[j]] = (pos[nodes_sorted[j]][0] + shift, pos[nodes_sorted[j]][1])

    # ── prepare labels ──
    short_labels = {}
    for n in H.nodes():
        short_labels[n] = _shorten_node_label(n, H.nodes[n])

    # ── edge grouping by relation type ──
    edge_groups: dict[str, list] = defaultdict(list)
    edge_labels = {}
    for u, v, data in H.edges(data=True):
        rel = data.get("relation", data.get("type", data.get("label", "related")))
        edge_groups[rel].append((u, v))
        edge_labels[(u, v)] = rel

    # ── figure ──
    num_nodes = H.number_of_nodes()
    fig_w = max(18, 14 + num_nodes * 0.35)
    fig_h = max(11, 9 + num_nodes * 0.18)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("#FAFBFC")
    ax.set_facecolor("#FAFBFC")

    # ── draw edges by type (different colours/styles) ──
    for rel, edges in edge_groups.items():
        style = edge_style_map.get(rel, default_edge_style)
        nx.draw_networkx_edges(
            H, pos, edgelist=edges,
            width=style["width"],
            edge_color=style["color"],
            style=style["style"],
            arrows=True,
            arrowsize=14,
            alpha=0.7,
            ax=ax,
            connectionstyle="arc3,rad=0.06",
            min_source_margin=18,
            min_target_margin=18,
        )

    # ── draw nodes ──
    node_colors = [
        node_color_map.get(
            H.nodes[n].get("type", H.nodes[n].get("label", "Unknown")),
            node_color_map["Unknown"],
        )
        for n in H.nodes()
    ]
    nx.draw_networkx_nodes(
        H, pos,
        node_color=node_colors,
        node_size=1000,
        edgecolors="#2B2D42",
        linewidths=1.5,
        alpha=0.92,
        ax=ax,
    )

    # ── draw node labels (with text background for readability) ──
    for n in H.nodes():
        x, y = pos[n]
        ax.text(
            x, y - 0.08,  # offset below node centre
            short_labels[n],
            fontsize=7,
            fontweight="bold",
            ha="center", va="top",
            bbox=dict(boxstyle="round,pad=0.25", facecolor="white", edgecolor="none", alpha=0.85),
            zorder=5,
        )

    # ── draw edge labels with offset to avoid node overlap ──
    for (u, v), label in edge_labels.items():
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        # Offset perpendicular to edge direction
        dx, dy = x2 - x1, y2 - y1
        length = max((dx**2 + dy**2) ** 0.5, 1e-6)
        # perpendicular offset
        ox, oy = -dy / length * 0.07, dx / length * 0.07
        ax.text(
            mx + ox, my + oy,
            label,
            fontsize=6,
            fontstyle="italic",
            ha="center", va="center",
            color="#4A4E69",
            bbox=dict(boxstyle="round,pad=0.15", facecolor="#F0F0F0", edgecolor="none", alpha=0.75),
            zorder=4,
        )

    # ── legend ──
    present_types = sorted({
        H.nodes[n].get("type", H.nodes[n].get("label", "Unknown"))
        for n in H.nodes()
    })
    legend_handles = []
    for t in present_types:
        legend_handles.append(
            mpatches.Patch(color=node_color_map.get(t, node_color_map["Unknown"]), label=t)
        )
    # Add edge-type entries
    for rel, style in edge_style_map.items():
        if rel in edge_groups:
            legend_handles.append(
                mpatches.Patch(facecolor="none", edgecolor=style["color"], label=f"edge: {rel}", linestyle=style["style"])
            )
    ax.legend(
        handles=legend_handles,
        loc="upper left",
        fontsize=7,
        framealpha=0.85,
        edgecolor="#DEE2E6",
        title="Node / Edge Types",
        title_fontsize=8,
    )

    # ── title ──
    if title:
        ax.set_title(
            title,
            fontsize=14,
            fontweight="bold",
            color="#2B2D42",
            pad=18,
        )

    ax.axis("off")
    plt.margins(x=0.15, y=0.15)
    fig.tight_layout(pad=2.0)
    fig.savefig(out_png, dpi=200, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def run_cmd(cmd: list[str], cwd: Path) -> None:
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(cwd), check=True)


def generate_for_spec(spec_path: Path, dest_dir: Path, label_kind: str) -> None:
    spec_data = load_yaml(spec_path)
    scenario_id = spec_data.get("scenario_id") or spec_path.stem
    case_name = f"{label_kind}_{scenario_id}"
    case_dir = dest_dir / safe_name(case_name)
    case_dir.mkdir(parents=True, exist_ok=True)

    tmp_dir = ROOT / "tmp_runs" / safe_name(case_name)
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    run_dir = tmp_dir / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "specs").mkdir(exist_ok=True)
    shutil.copy2(spec_path, run_dir / "specs" / spec_path.name)

    run_cmd([sys.executable, "datagen/codegen.py", str(run_dir)], REPO)
    run_cmd([sys.executable, "datagen/validate_run.py", str(run_dir)], REPO)
    run_cmd([sys.executable, "main.py", str(run_dir)], REPO)

    graphml_dir = tmp_dir / "enriched_graphs" / "graphml"
    graphml_candidates = sorted(graphml_dir.glob("*.graphml"))
    if not graphml_candidates:
        raise FileNotFoundError(f"No GraphML found for {spec_path} in {graphml_dir}")
    graphml = graphml_candidates[0]
    (case_dir / "graphml").mkdir(parents=True, exist_ok=True)
    shutil.copy2(graphml, case_dir / "graphml" / graphml.name)

    out_png = case_dir / "graph.png"
    render_graph(graphml, out_png, title=scenario_id)

    # Save a summary JSON.
    (case_dir / "summary.json").write_text(json.dumps({
        "scenario_id": scenario_id,
        "default_class": spec_data.get("default_class"),
        "family_id": spec_data.get("family_id"),
        "graph_file": graphml.name,
        "kind": label_kind,
    }, indent=2), encoding="utf-8")

    shutil.rmtree(tmp_dir)


def generate_for_existing_case(case_dir: Path, dest_dir: Path, label_kind: str) -> None:
    case_id = case_dir.name
    case_name = f"{label_kind}_{case_id}"
    target = dest_dir / safe_name(case_name)
    target.mkdir(parents=True, exist_ok=True)

    graphml_candidates = sorted((case_dir / "algo3").glob("*.graphml"))
    if not graphml_candidates:
        raise FileNotFoundError(f"No algo3 GraphML files in {case_dir}")

    graphml = graphml_candidates[0]
    (target / "graphml").mkdir(parents=True, exist_ok=True)
    shutil.copy2(graphml, target / "graphml" / graphml.name)

    out_png = target / "graph.png"
    render_graph(graphml, out_png, title=case_id)
    (target / "summary.json").write_text(json.dumps({
        "case_id": case_id,
        "kind": label_kind,
        "graph_file": graphml.name,
    }, indent=2), encoding="utf-8")


def main():
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    for sub in ["seen_attacks", "seen_benign", "unseen_attacks", "unseen_benign"]:
        (OUT_ROOT / sub).mkdir(parents=True, exist_ok=True)

    # Select 12 seen malicious scenarios and 6 seen benign scenarios.
    malicious_specs = []
    benign_specs = []
    for spec_path in sorted(REPO.glob("dataset_test/run_*/specs/*.yaml")):
        data = load_yaml(spec_path)
        cls = data.get("default_class")
        if cls == "malicious" and not data.get("matched_pair_id"):
            malicious_specs.append(spec_path)
        elif cls == "benign" and not data.get("matched_pair_id"):
            benign_specs.append(spec_path)

    # Use the first 12 malicious and first 6 benign examples.
    for idx, spec_path in enumerate(malicious_specs[:12], start=1):
        generate_for_spec(spec_path, OUT_ROOT / "seen_attacks", f"attack_{idx:02d}")
    for idx, spec_path in enumerate(benign_specs[:6], start=1):
        generate_for_spec(spec_path, OUT_ROOT / "seen_benign", f"benign_{idx:02d}")

    # Build four unseen attack and four unseen benign cases from the remaining
    # valid dataset specs, excluding the seen selection.
    seen_attack_paths = {str(p.resolve()) for p in malicious_specs[:12]}
    seen_benign_paths = {str(p.resolve()) for p in benign_specs[:6]}

    unseen_malicious_specs = [
        p for p in malicious_specs[12:] if str(p.resolve()) not in seen_attack_paths
    ][:4]
    unseen_benign_specs = [
        p for p in benign_specs[6:] if str(p.resolve()) not in seen_benign_paths
    ][:4]

    for idx, spec_path in enumerate(unseen_malicious_specs, start=1):
        generate_for_spec(spec_path, OUT_ROOT / "unseen_attacks", f"unseen_attack_{idx:02d}")
    for idx, spec_path in enumerate(unseen_benign_specs, start=1):
        generate_for_spec(spec_path, OUT_ROOT / "unseen_benign", f"unseen_benign_{idx:02d}")

    summary = {
        "seen_attacks": len(sorted((OUT_ROOT / "seen_attacks").iterdir())),
        "seen_benign": len(sorted((OUT_ROOT / "seen_benign").iterdir())),
        "unseen_attacks": len(sorted((OUT_ROOT / "unseen_attacks").iterdir())),
        "unseen_benign": len(sorted((OUT_ROOT / "unseen_benign").iterdir())),
    }
    (OUT_ROOT / "catalog_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
