#!/usr/bin/env python3
"""
Algorithm 3: Context-Aware Graph Abstraction & MITRE ATT&CK Behavior Node Extraction
========================================================================================

Extracts high-level MITRE ATT&CK Behavior nodes and chronological precedence edges
from session-level heterogeneous provenance graphs (produced by Algorithm 2).

Integrates:
  1. Multi-Dimensional Similarity (Structural, Semantic, Temporal)
  2. MultiDiGraph Edge Relation Helpers
  3. Comprehensive Node Text & Timestamp Attribute Fallbacks
  4. Chronological Precedence Chaining
"""

import os
import sys
import json
import argparse
import math
import glob
from pathlib import Path
import networkx as nx
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


def parse_args():
    parser = argparse.ArgumentParser(description="Algorithm 3 Graph Abstraction & Behavior Node Extraction")
    parser.add_argument('--input-dir', required=True, help='Path to directory containing input graph files (.json or .graphml)')
    parser.add_argument('--outdir', required=True, help='Directory to save enriched graphs')
    parser.add_argument('--theta-struct', type=float, default=0.50, help='Structural similarity threshold')
    parser.add_argument('--theta-beh', type=float, default=0.45, help='Behavior confidence threshold')
    return parser.parse_args()


class BehaviorTemplate:
    def __init__(self, label, mitre_id, graph_structure, semantic_keywords, temporal_constraints):
        self.label = label
        self.mitre_id = mitre_id
        self.structure = graph_structure
        self.semantic_keywords = semantic_keywords
        self.temporal_constraints = temporal_constraints


def initialize_templates():
    templates = []
    
    # 1. DATA_ACCESS (Project-defined Semantic Behavior)
    g_access = nx.DiGraph()
    g_access.add_node("T_Query", type="Query")
    g_access.add_node("T_Table", type="Table")
    g_access.add_edge("T_Query", "T_Table", relation="accesses")
    templates.append(BehaviorTemplate(
        label="DATA_ACCESS", 
        mitre_id="N/A", 
        graph_structure=g_access, 
        semantic_keywords=["pg_authid", "pg_shadow", "pg_roles", "password", "credential", "secret", "information_schema", "audit_logs", "accounts", "customers"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 2. DATA_PACKAGING (T1560.001)
    g_package = nx.DiGraph()
    g_package.add_node("T_Process", type="Process")
    g_package.add_node("T_File", type="File")
    g_package.add_edge("T_Process", "T_File", relation="opens")
    templates.append(BehaviorTemplate(
        label="DATA_PACKAGING", 
        mitre_id="T1560.001", 
        graph_structure=g_package, 
        semantic_keywords=["tar", "gzip", "zip", "7z", "rar", "bak", "dump"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 3. EXTERNAL_TRANSFER (T1048)
    g_transfer = nx.DiGraph()
    g_transfer.add_node("T_Process", type="Process")
    g_transfer.add_node("T_Endpoint", type="Endpoint")
    g_transfer.add_edge("T_Process", "T_Endpoint", relation="connects_to")
    templates.append(BehaviorTemplate(
        label="EXTERNAL_TRANSFER", 
        mitre_id="T1048", 
        graph_structure=g_transfer, 
        semantic_keywords=["curl", "wget", "nc", "ncat", "ssh", "scp", "ftp", "exfil", "http"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 4. DESTRUCTIVE_DB_OPERATION (T1485)
    g_destruct = nx.DiGraph()
    g_destruct.add_node("T_Query", type="Query")
    g_destruct.add_node("T_Table", type="Table")
    g_destruct.add_edge("T_Query", "T_Table", relation="accesses")
    templates.append(BehaviorTemplate(
        label="DESTRUCTIVE_DB_OPERATION", 
        mitre_id="T1485", 
        graph_structure=g_destruct, 
        semantic_keywords=["drop", "delete", "truncate"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 5. OS_CREDENTIAL_DUMPING (T1003.008)
    g_cred_dump = nx.DiGraph()
    g_cred_dump.add_node("T_Query", type="Query")
    g_cred_dump.add_node("T_Table", type="Table")
    g_cred_dump.add_edge("T_Query", "T_Table", relation="accesses")
    templates.append(BehaviorTemplate(
        label="OS_CREDENTIAL_DUMPING", 
        mitre_id="T1003.008", 
        graph_structure=g_cred_dump, 
        semantic_keywords=["pg_shadow", "passwd", "shadow", "credentials", "usename"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 6. UNIX_SHELL_EXECUTION (T1059.004)
    g_shell = nx.DiGraph()
    g_shell.add_node("T_Query", type="Query")
    g_shell.add_node("T_Process", type="Process")
    g_shell.add_edge("T_Query", "T_Process", relation="spawns")
    templates.append(BehaviorTemplate(
        label="UNIX_SHELL_EXECUTION", 
        mitre_id="T1059.004", 
        graph_structure=g_shell, 
        semantic_keywords=["bash", "sh", "dash", "ksh", "zsh", "program", "curl", "copy"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 7. ACCOUNT_MANIPULATION (T1098)
    g_account = nx.DiGraph()
    g_account.add_node("T_Query", type="Query")
    g_account.add_node("T_Role", type="Role")
    g_account.add_edge("T_Query", "T_Role", relation="modifies")
    templates.append(BehaviorTemplate(
        label="ACCOUNT_MANIPULATION", 
        mitre_id="T1098", 
        graph_structure=g_account, 
        semantic_keywords=["create role", "alter role", "superuser", "login", "grant", "revoke"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 8. POTENTIAL_INGRESS_TOOL_TRANSFER (T1105)
    g_ingress = nx.DiGraph()
    g_ingress.add_node("T_Process", type="Process")
    g_ingress.add_node("T_Endpoint", type="Endpoint")
    g_ingress.add_edge("T_Process", "T_Endpoint", relation="connects_to")
    templates.append(BehaviorTemplate(
        label="POTENTIAL_INGRESS_TOOL_TRANSFER", 
        mitre_id="T1105", 
        graph_structure=g_ingress, 
        semantic_keywords=["wget", "curl", "fetch", "git", "clone"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 9. INDICATOR_REMOVAL_FILE (T1070.004)
    g_file_del = nx.DiGraph()
    g_file_del.add_node("T_Process", type="Process")
    g_file_del.add_node("T_File", type="File")
    g_file_del.add_edge("T_Process", "T_File", relation="opens")
    templates.append(BehaviorTemplate(
        label="INDICATOR_REMOVAL_FILE", 
        mitre_id="T1070.004", 
        graph_structure=g_file_del, 
        semantic_keywords=["rm", "unlink", "remove", "truncate"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 10. DEFENSE_IMPAIRMENT (Project-defined)
    # Uses Query→Configuration(modifies) since ALTER SYSTEM SET now produces
    # Configuration nodes via sqlfacts (is_system_config: true).
    # Also matches Query→Table(accesses) for TRUNCATE TABLE audit_logs.
    g_def = nx.DiGraph()
    g_def.add_node("T_Query", type="Query")
    g_def.add_node("T_Config", type="Configuration")
    g_def.add_edge("T_Query", "T_Config", relation="modifies")
    templates.append(BehaviorTemplate(
        label="DEFENSE_IMPAIRMENT", 
        mitre_id="T1562", 
        graph_structure=g_def, 
        semantic_keywords=["pg_settings", "log_statement", "log_min_messages", "alter system set", "disable", "truncate table audit_logs"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    # 11. DEFENSE_IMPAIRMENT via destructive table ops (TRUNCATE audit_logs)
    g_def_db = nx.DiGraph()
    g_def_db.add_node("T_Query", type="Query")
    g_def_db.add_node("T_Table", type="Table")
    g_def_db.add_edge("T_Query", "T_Table", relation="accesses")
    templates.append(BehaviorTemplate(
        label="DEFENSE_IMPAIRMENT", 
        mitre_id="T1562", 
        graph_structure=g_def_db, 
        semantic_keywords=["audit_logs", "truncate", "delete", "log"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    return templates


# Pre-fit TF-IDF Vectorizer
GLOBAL_CORPUS = [" ".join(_t.semantic_keywords) for _t in initialize_templates()]
VECTORIZER = TfidfVectorizer().fit(GLOBAL_CORPUS)


def _get_node_type(G_s, n):
    data = G_s.nodes[n]
    return data.get("type") or data.get("node_type")


def _get_node_text(G_s, n):
    data = G_s.nodes[n]
    parts = []
    for k in ("query", "raw_sql", "sql", "table_name", "role_name", "comm", "cmd", "executable", "filepath", "path", "arg", "dest_ip", "label", "command"):
        v = data.get(k)
        if v:
            parts.append(str(v))
    return " ".join(parts).lower()


def _get_node_timestamp(G_s, n):
    data = G_s.nodes[n]
    ts = data.get("timestamp_unix") or data.get("timestamp")
    if ts is not None:
        try:
            return float(ts)
        except (ValueError, TypeError):
            pass
    return None


def _get_edge_relations(G_s, u, v):
    if not G_s.has_edge(u, v):
        return set()
    relations = set()
    edge_data_dict = G_s.get_edge_data(u, v)
    if isinstance(edge_data_dict, dict):
        if any(k in edge_data_dict for k in ("rel", "relation")):
            rel = edge_data_dict.get("rel") or edge_data_dict.get("relation")
            if rel:
                relations.add(rel)
        else:
            for d in edge_data_dict.values():
                if isinstance(d, dict):
                    rel = d.get("rel") or d.get("relation")
                    if rel:
                        relations.add(rel)
    return relations


def calculate_graded_s_struct(G_s, T, theta_struct=0.50, max_matches=10):
    template = T.structure

    t_root = max(template.nodes(), key=lambda n: template.out_degree(n))
    t_root_type = template.nodes[t_root].get("type")

    candidates = [
        n for n in G_s.nodes()
        if _get_node_type(G_s, n) == t_root_type
    ]

    graded_matches = []

    for root in candidates:
        mapping = {t_root: root}
        used_actual_nodes = {root}

        for t_child in template.successors(t_root):
            required_type = template.nodes[t_child].get("type")
            required_relation = template.edges[t_root, t_child].get("relation")

            best_candidate = None
            for actual_child in G_s.successors(root):
                if actual_child in used_actual_nodes:
                    continue

                actual_type = _get_node_type(G_s, actual_child)
                actual_relations = _get_edge_relations(G_s, root, actual_child)

                if actual_type == required_type and (not required_relation or required_relation in actual_relations):
                    best_candidate = actual_child
                    break

            if best_candidate is not None:
                mapping[t_child] = best_candidate
                used_actual_nodes.add(best_candidate)

        matched_nodes = len(mapping)
        total_template_nodes = template.number_of_nodes()
        s_n = matched_nodes / max(1, total_template_nodes)

        matched_edges = 0
        total_template_edges = template.number_of_edges()

        for t_u, t_v, t_data in template.edges(data=True):
            if t_u not in mapping or t_v not in mapping:
                continue

            g_u = mapping[t_u]
            g_v = mapping[t_v]

            actual_relations = _get_edge_relations(G_s, g_u, g_v)
            required_relation = t_data.get("relation")

            if required_relation in actual_relations or not required_relation:
                matched_edges += 1

        s_e = 1.0 if total_template_edges == 0 else (matched_edges / total_template_edges)
        s_struct = 0.30 * s_n + 0.70 * s_e

        if s_struct >= theta_struct:
            graded_matches.append({
                "nodes": list(mapping.values()),
                "mapping": mapping,
                "s_node": s_n,
                "s_edge": s_e,
                "s_struct": s_struct
            })

        if len(graded_matches) >= max_matches:
            break

    return graded_matches


import re


def _keyword_matches(keyword: str, factual_text_lower: str) -> bool:
    """Word/phrase-boundary match, not substring containment.

    The previous version did `keyword in factual_text_lower`, which fires on
    accidental substrings -- e.g. keyword "nc" matches inside "pgbench_branches",
    keyword "sh" matches inside "shadow", keyword "login" matches inside any
    ordinary auth-related text. This was the exact bug the overfitting report
    found (EXTERNAL_TRANSFER/"nc" firing 529 times on ordinary branch-table
    queries). A single-word keyword must match a whole token; a multi-word
    phrase ("create role") is matched with \\b-anchored boundaries so it
    doesn't fire on partial phrase overlap either.
    """
    keyword = keyword.strip()
    if not keyword:
        return False
    if " " in keyword:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        return re.search(pattern, factual_text_lower) is not None
    tokens = set()
    for t in re.findall(r"[\w./]+", factual_text_lower):
        tokens.add(t)
        tokens.update(p for p in re.split(r"[./]+", t) if p)  # also expose path/extension components, e.g. "/bin/sh" -> "bin", "sh"
    return keyword in tokens


def calculate_s_sem(matched_nodes, G_s, T_keywords):
    if not matched_nodes or not T_keywords:
        return 0.0

    factual_values = [_get_node_text(G_s, n) for n in matched_nodes]
    factual_text = " ".join(v for v in factual_values if v).lower()
    if not factual_text:
        return 0.0

    matched_keywords = 0
    for keyword in T_keywords:
        kw = str(keyword).lower()
        if _keyword_matches(kw, factual_text):
            matched_keywords += 1

    s_coverage = matched_keywords / max(1, len(T_keywords))

    template_text = " ".join(str(k).lower() for k in T_keywords)
    vectors = VECTORIZER.transform([factual_text, template_text]).toarray()
    norm_f = np.linalg.norm(vectors[0])
    norm_t = np.linalg.norm(vectors[1])

    s_tfidf = 0.0 if (norm_f == 0 or norm_t == 0) else float(np.dot(vectors[0], vectors[1]) / (norm_f * norm_t))

    s_sem = 0.60 * s_coverage + 0.40 * s_tfidf
    return float(s_sem)


def calculate_s_temp(matched_nodes, G_s, template):
    timestamps = []
    for n in matched_nodes:
        ts = _get_node_timestamp(G_s, n)
        if ts is not None:
            timestamps.append(ts)

    if not timestamps:
        return 1.0

    delta_t = max(timestamps) - min(timestamps)
    max_gap = template.temporal_constraints.get("max_gap", 60.0)

    if delta_t > max_gap:
        return 0.0

    return float(math.exp(-delta_t / max_gap))


def abstract_session_graph(G_s, templates, theta_struct=0.50, theta_beh=0.45, chain_gap=120.0):
    G_enriched = G_s.copy()

    alpha = 0.40   # Structural
    beta = 0.35    # Semantic
    gamma = 0.25   # Temporal

    behavior_counter = 0
    detected_behaviors = []
    seen_behaviors = set()

    for template in templates:
        matches = calculate_graded_s_struct(G_s, template, theta_struct=theta_struct)

        for match_info in matches:
            matched_nodes = match_info["nodes"]
            s_struct = match_info["s_struct"]

            if s_struct < theta_struct:
                continue

            s_sem = calculate_s_sem(matched_nodes, G_s, template.semantic_keywords)

            # Option C: semantic gate — a template must have nonzero semantic
            # overlap to fire, preventing purely structural matches from
            # tagging every Query→Table edge with every behavior label.
            if s_sem == 0.0:
                continue

            s_temp = calculate_s_temp(matched_nodes, G_s, template)

            # For single-hop templates (all matched nodes come from ONE event,
            # e.g. Query--accesses-->Table), delta_t is always exactly 0 and
            # s_temp is therefore always exactly 1.0 -- not because the match
            # is temporally tight, but because there's no second timestamp to
            # compare against at all. Letting that automatic 1.0 count toward
            # confidence gives every single-hop match a free 0.25, independent
            # of whether anything temporal is actually being measured. Only
            # score s_temp for templates where a real time gap can exist.
            is_multi_hop = template.structure.number_of_edges() > 1
            effective_gamma = gamma if is_multi_hop else 0.0
            # Redistribute the freed weight to BETA (semantic), not alpha --
            # s_struct is equally trivial (also always 1.0) for these
            # templates, so boosting alpha would just recreate the same
            # degenerate floor under a different name. Only s_sem carries
            # real discriminating signal here.
            effective_beta = beta if is_multi_hop else (beta + gamma)

            confidence = (alpha * s_struct) + (effective_beta * s_sem) + (effective_gamma * s_temp)

            if confidence < theta_beh:
                continue

            evidence_key = (template.label, tuple(sorted(matched_nodes)))
            if evidence_key in seen_behaviors:
                continue
            seen_behaviors.add(evidence_key)

            timestamps = [_get_node_timestamp(G_s, n) for n in matched_nodes if _get_node_timestamp(G_s, n) is not None]
            beh_timestamp = max(timestamps) if timestamps else 0.0

            behavior_counter += 1
            beh_node_name = f"Behavior_{template.label}_{behavior_counter}"

            G_enriched.add_node(
                beh_node_name,
                type="Behavior",
                node_type="Behavior",
                label=f"[{template.mitre_id}] {template.label}",
                mitre_id=template.mitre_id,
                behavior_label=template.label,
                confidence=str(round(confidence, 3)),
                s_struct=str(round(s_struct, 3)),
                s_sem=str(round(s_sem, 3)),
                s_temp=str(round(s_temp, 3)),
                timestamp_unix=beh_timestamp
            )

            for node in matched_nodes:
                G_enriched.add_edge(node, beh_node_name, rel="evidence_for", relation="evidence_for")

            detected_behaviors.append({
                "node_name": beh_node_name,
                "timestamp": beh_timestamp,
                "label": template.label
            })

    # Chronological behavior chaining
    detected_behaviors.sort(key=lambda x: x["timestamp"])

    for i in range(1, len(detected_behaviors)):
        previous = detected_behaviors[i - 1]
        current = detected_behaviors[i]
        delta = current["timestamp"] - previous["timestamp"]

        if previous["node_name"] != current["node_name"] and 0 <= delta <= chain_gap:
            G_enriched.add_edge(previous["node_name"], current["node_name"], rel="precedes", relation="precedes")

    return G_enriched, detected_behaviors


def run_batch(input_dir: Path, out_dir: Path, theta_struct=0.50, theta_beh=0.45):
    input_dir = Path(input_dir).resolve()
    out_dir = Path(out_dir).resolve()

    graphml_out = out_dir / "graphml"
    json_out = out_dir / "json"
    graphml_out.mkdir(parents=True, exist_ok=True)
    json_out.mkdir(parents=True, exist_ok=True)

    templates = initialize_templates()
    print(f"Initialized {len(templates)} MITRE ATT&CK Behavioral Templates.")

    # Find graph files (.json or .graphml)
    graphml_files = sorted(input_dir.glob("*.graphml")) + sorted((input_dir / "graphml").glob("*.graphml"))
    json_files = sorted(input_dir.glob("*.json"))

    target_files = graphml_files if graphml_files else json_files
    if not target_files:
        print(f"Error: No graph files (.json or .graphml) found in '{input_dir}'")
        sys.exit(1)

    print(f"Found {len(target_files)} graph files to process.")

    manifest = []
    total_behavior_nodes = 0

    for fpath in target_files:
        session_id = fpath.stem
        if fpath.suffix == ".graphml":
            G_s = nx.read_graphml(fpath)
        else:
            data = json.loads(fpath.read_text())
            try:
                G_s = nx.node_link_graph(data, directed=True, multigraph=True)
            except Exception:
                # Fallback for NetworkX node-link structure
                G_s = nx.MultiDiGraph()
                for node in data.get("nodes", []):
                    nid = node.pop("id")
                    G_s.add_node(nid, **node)
                for edge in data.get("links", []) or data.get("edges", []):
                    src = edge.pop("source")
                    tgt = edge.pop("target")
                    G_s.add_edge(src, tgt, **edge)

        G_enriched, detected = abstract_session_graph(G_s, templates, theta_struct=theta_struct, theta_beh=theta_beh)
        total_behavior_nodes += len(detected)

        # Export JSON format
        json_path = json_out / f"enriched_{session_id}.json"
        json_path.write_text(json.dumps(nx.node_link_data(G_enriched), default=str))

        # Export GraphML format
        G_export = G_enriched.copy()
        for n, d in G_export.nodes(data=True):
            for k, v in list(d.items()):
                if isinstance(v, (dict, list, tuple)):
                    d[k] = json.dumps(v)
                elif v is None:
                    d[k] = ""
        if G_export.is_multigraph():
            for u, v, k, d in G_export.edges(keys=True, data=True):
                for ek, ev in list(d.items()):
                    if isinstance(ev, (dict, list, tuple)):
                        d[ek] = json.dumps(ev)
                    elif ev is None:
                        d[ek] = ""
        else:
            for u, v, d in G_export.edges(data=True):
                for ek, ev in list(d.items()):
                    if isinstance(ev, (dict, list, tuple)):
                        d[ek] = json.dumps(ev)
                    elif ev is None:
                        d[ek] = ""

        graphml_path = graphml_out / f"enriched_{session_id}.graphml"
        nx.write_graphml(G_export, graphml_path)

        manifest.append({
            "session_id": session_id,
            "behavior_count": len(detected),
            "behaviors": [b["label"] for b in detected],
            "total_nodes": G_enriched.number_of_nodes(),
            "total_edges": G_enriched.number_of_edges()
        })

    # Save manifest
    manifest_path = out_dir / "enriched_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\nSUCCESS: Extracted {total_behavior_nodes} Behavior nodes across {len(target_files)} scenario graphs.")
    print(f"Saved Enriched Graphs to '{out_dir}'")
    print(f"Saved Manifest to '{manifest_path}'")


if __name__ == '__main__':
    args = parse_args()
    run_batch(Path(args.input_dir), Path(args.outdir), theta_struct=args.theta_struct, theta_beh=args.theta_beh)