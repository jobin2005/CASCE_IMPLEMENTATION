import os
import argparse
import networkx as nx
import numpy as np
import math
from sklearn.feature_extraction.text import TfidfVectorizer
from networkx.algorithms import isomorphism

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', required=True, help='Path to directory containing input graphml files')
    parser.add_argument('--outdir', required=True, help='Directory to save enriched graphs (GraphML format)')
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
        semantic_keywords=["pg_authid", "pg_shadow", "pg_roles", "password", "credential", "secret"], 
        temporal_constraints={"max_gap": 5.0}
    ))

    # 2. DATA_PACKAGING (T1560.001)
    g_package = nx.DiGraph()
    g_package.add_node("T_Process", type="Process")
    g_package.add_node("T_Utility", type="File")
    g_package.add_node("T_Input", type="File")
    g_package.add_node("T_Archive", type="File")
    
    g_package.add_edge("T_Process", "T_Utility", relation="opens")
    g_package.add_edge("T_Process", "T_Input", relation="opens")
    g_package.add_edge("T_Process", "T_Archive", relation="opens")
    
    templates.append(BehaviorTemplate(
        label="DATA_PACKAGING", 
        mitre_id="T1560.001", 
        graph_structure=g_package, 
        semantic_keywords=["tar", "gzip", "zip", "7z", "rar"], 
        temporal_constraints={"max_gap": 30.0}
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
        semantic_keywords=["curl", "wget", "nc", "ncat", "ssh", "scp", "ftp"], 
        temporal_constraints={"max_gap": 30.0}
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
        temporal_constraints={"max_gap": 15.0}
    ))

    # 5. OS_CREDENTIAL_DUMPING (T1003.008)
    g_cred_dump = nx.DiGraph()
    g_cred_dump.add_node("T_Process", type="Process")
    g_cred_dump.add_node("T_File", type="File")
    g_cred_dump.add_edge("T_Process", "T_File", relation="opens")
    templates.append(BehaviorTemplate(
        label="OS_CREDENTIAL_DUMPING", 
        mitre_id="T1003.008", 
        graph_structure=g_cred_dump, 
        semantic_keywords=["/etc/shadow", "/etc/passwd"], 
        temporal_constraints={"max_gap": 15.0}
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
        semantic_keywords=["bash", "sh", "dash", "ksh", "zsh", "program"], 
        temporal_constraints={"max_gap": 10.0}
    ))

    # 7. ACCOUNT_MANIPULATION (T1098)
    g_account = nx.DiGraph()
    g_account.add_node("T_Query", type="Query")
    g_account.add_node("T_Role", type="Role")
    g_account.add_edge("T_Query", "T_Role", relation="accesses")
    templates.append(BehaviorTemplate(
        label="ACCOUNT_MANIPULATION", 
        mitre_id="T1098", 
        graph_structure=g_account, 
        semantic_keywords=["create role", "alter role", "superuser", "login", "grant", "revoke"], 
        temporal_constraints={"max_gap": 30.0}
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

    # 9. INDICATOR_REMOVAL_HISTORY (T1070.003)
    g_hist = nx.DiGraph()
    g_hist.add_node("T_Process", type="Process")
    g_hist.add_node("T_File", type="File")
    g_hist.add_edge("T_Process", "T_File", relation="opens")
    templates.append(BehaviorTemplate(
        label="INDICATOR_REMOVAL_HISTORY", 
        mitre_id="T1070.003", 
        graph_structure=g_hist, 
        semantic_keywords=["bash_history", "history", "clear"], 
        temporal_constraints={"max_gap": 10.0}
    ))

    # 10. INDICATOR_REMOVAL_FILE (T1070.004)
    g_file_del = nx.DiGraph()
    g_file_del.add_node("T_Process", type="Process")
    g_file_del.add_node("T_File", type="File")
    g_file_del.add_edge("T_Process", "T_File", relation="opens")
    templates.append(BehaviorTemplate(
        label="INDICATOR_REMOVAL_FILE", 
        mitre_id="T1070.004", 
        graph_structure=g_file_del, 
        semantic_keywords=["rm", "unlink", "remove"], 
        temporal_constraints={"max_gap": 10.0}
    ))

    # 11. DEFENSE_IMPAIRMENT (Project-defined)
    g_def = nx.DiGraph()
    g_def.add_node("T_Query", type="Query")
    g_def.add_node("T_Table", type="Table")
    g_def.add_edge("T_Query", "T_Table", relation="accesses")
    templates.append(BehaviorTemplate(
        label="DEFENSE_IMPAIRMENT", 
        mitre_id="N/A", 
        graph_structure=g_def, 
        semantic_keywords=["pg_settings", "log_statement", "log_min_messages", "alter system set", "disable"], 
        temporal_constraints={"max_gap": 60.0}
    ))

    return templates

# Efficient pre-fit TF-IDF Vectorizer across all semantic vectors for the 10 templates.
GLOBAL_CORPUS = []
for _t in initialize_templates():
    GLOBAL_CORPUS.append(" ".join(_t.semantic_keywords))
VECTORIZER = TfidfVectorizer().fit(GLOBAL_CORPUS)

def calculate_graded_s_struct(G_s, T, theta_struct=0.6, max_matches=10):
    template = T.structure

    # 1. Find candidate anchor nodes
    t_root = max(
        template.nodes(),
        key=lambda n: template.out_degree(n)
    )

    t_root_type = template.nodes[t_root].get("type")

    candidates = [
        n for n, data in G_s.nodes(data=True)
        if data.get("type") == t_root_type
    ]

    graded_matches = []

    # 2. Evaluate each candidate anchor
    for root in candidates:
        mapping = {t_root: root}
        used_actual_nodes = {root}

        # 3. Match template neighbors
        for t_child in template.successors(t_root):
            required_type = template.nodes[t_child].get("type")
            required_relation = template.edges[t_root, t_child].get("relation")

            best_candidate = None
            for actual_child in G_s.successors(root):
                if actual_child in used_actual_nodes:
                    continue

                actual_type = G_s.nodes[actual_child].get("type")
                
                # Check for relation logic properly
                edge_data = G_s.get_edge_data(root, actual_child)
                actual_relation = edge_data.get("relation") if edge_data else None

                # Simplified node compatibility purely relying on relation + type (semantic hook comes later in pipeline)
                if actual_type == required_type and actual_relation == required_relation:
                    best_candidate = actual_child
                    break

            if best_candidate is not None:
                mapping[t_child] = best_candidate
                used_actual_nodes.add(best_candidate)

        # 4. Node similarity
        matched_nodes = len(mapping)
        total_template_nodes = template.number_of_nodes()
        s_n = matched_nodes / max(1, total_template_nodes)

        # 5. Edge/relation similarity
        matched_edges = 0
        total_template_edges = template.number_of_edges()

        for t_u, t_v, t_data in template.edges(data=True):
            if t_u not in mapping or t_v not in mapping:
                continue

            g_u = mapping[t_u]
            g_v = mapping[t_v]

            if not G_s.has_edge(g_u, g_v):
                continue

            actual_edge = G_s.get_edge_data(g_u, g_v)
            actual_relation = actual_edge.get("relation") if actual_edge else None
            required_relation = t_data.get("relation")

            if actual_relation == required_relation:
                matched_edges += 1

        if total_template_edges == 0:
            s_e = 1.0
        else:
            s_e = matched_edges / total_template_edges

        # 6. Final structural similarity
        s_struct = 0.30 * s_n + 0.70 * s_e

        # 7. Structural gate
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

def calculate_s_sem(matched_nodes, G_s, T_keywords):
    if not matched_nodes or not T_keywords:
        return 0.0

    factual_values = []
    for n in matched_nodes:
        label = G_s.nodes[n].get("label", "")
        if label:
            factual_values.append(str(label).lower())

    if not factual_values:
        return 0.0

    factual_text = " ".join(factual_values)
    factual_text_lower = factual_text.lower()

    matched_keywords = 0
    for keyword in T_keywords:
        keyword = str(keyword).lower().strip()
        if keyword and keyword in factual_text_lower:
            matched_keywords += 1

    s_coverage = matched_keywords / max(1, len(T_keywords))

    template_text = " ".join(str(k).lower() for k in T_keywords)
    vectors = VECTORIZER.transform([factual_text, template_text]).toarray()
    norm_f = np.linalg.norm(vectors[0])
    norm_t = np.linalg.norm(vectors[1])

    if norm_f == 0 or norm_t == 0:
        s_tfidf = 0.0
    else:
        s_tfidf = float(np.dot(vectors[0], vectors[1]) / (norm_f * norm_t))

    s_sem = 0.60 * s_coverage + 0.40 * s_tfidf
    return float(s_sem)

def calculate_s_temp(matched_nodes, G_s, template):
    timestamps = []
    for n in matched_nodes:
        ts = G_s.nodes[n].get("timestamp")
        if ts is None:
            continue
        try:
            timestamps.append(float(ts))
        except (ValueError, TypeError):
            continue

    if not timestamps:
        return 0.0

    delta_t = max(timestamps) - min(timestamps)
    max_gap = template.temporal_constraints.get("max_gap", 30.0)

    if delta_t > max_gap:
        return 0.0

    s_temp = math.exp(-delta_t / max_gap)
    return float(s_temp)

def abstract_session_graph(G_s, templates, theta_struct=0.60, theta_beh=0.60, chain_gap=60.0):
    G_enriched = G_s.copy()

    # Initial weights
    alpha = 0.40   # Structural
    beta = 0.35    # Semantic
    gamma = 0.25   # Temporal

    behavior_counter = 0
    detected_behaviors = []
    seen_behaviors = set()

    # 1. Process each behavior template
    for template in templates:
        matches = calculate_graded_s_struct(G_s, template, theta_struct=theta_struct)

        # 2. Evaluate each structural candidate
        for match_info in matches:
            matched_nodes = match_info["nodes"]
            s_struct = match_info["s_struct"]

            # Structural gate
            if s_struct < theta_struct:
                continue

            # 3. Semantic similarity
            s_sem = calculate_s_sem(matched_nodes, G_s, template.semantic_keywords)

            # 4. Temporal similarity
            s_temp = calculate_s_temp(matched_nodes, G_s, template)

            # 5. Behaviour confidence
            confidence = (alpha * s_struct) + (beta * s_sem) + (gamma * s_temp)

            # 6. Behaviour confidence gate
            if confidence < theta_beh:
                continue

            # 7. Duplicate suppression
            evidence_key = (template.label, tuple(sorted(matched_nodes)))
            if evidence_key in seen_behaviors:
                continue
            seen_behaviors.add(evidence_key)

            # 8. Determine behavior timestamp
            timestamps = []
            for n in matched_nodes:
                ts = G_s.nodes[n].get("timestamp")
                if ts is None:
                    continue
                try:
                    timestamps.append(float(ts))
                except (ValueError, TypeError):
                    continue

            beh_timestamp = max(timestamps) if timestamps else 0.0

            # 9. Create behavior node
            behavior_counter += 1
            beh_node_name = f"Behavior_{template.label}_{behavior_counter}"

            G_enriched.add_node(
                beh_node_name,
                type="Behavior",
                label=f"[{template.mitre_id}] {template.label}",
                confidence=str(round(confidence, 3)),
                s_struct=str(round(s_struct, 3)),
                s_sem=str(round(s_sem, 3)),
                s_temp=str(round(s_temp, 3)),
                timestamp=str(beh_timestamp)
            )

            # 10. Evidence relationships
            for node in matched_nodes:
                G_enriched.add_edge(node, beh_node_name, relation="evidence_for")

            detected_behaviors.append({
                "node_name": beh_node_name,
                "timestamp": beh_timestamp
            })

    # 11. Chronological behavior chaining
    detected_behaviors.sort(key=lambda x: x["timestamp"])

    for i in range(1, len(detected_behaviors)):
        previous = detected_behaviors[i - 1]
        current = detected_behaviors[i]

        delta = current["timestamp"] - previous["timestamp"]

        # Avoid self-links / invalid timestamps and enforce the temporal chaining boundary
        if previous["node_name"] != current["node_name"] and 0 <= delta <= chain_gap:
            G_enriched.add_edge(previous["node_name"], current["node_name"], relation="precedes")

    return G_enriched

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    
    templates = initialize_templates()
    print(f"Initialized {len(templates)} MITRE ATT&CK Behavioral Templates.")
    
    processed = 0
    for filename in os.listdir(args.input_dir):
        if filename.endswith(".graphml"):
            G_s = nx.read_graphml(os.path.join(args.input_dir, filename))
            G_enriched = abstract_session_graph(G_s, templates)
            nx.write_graphml(G_enriched, os.path.join(args.outdir, f"enriched_{filename}"))
            processed += 1
            
    print(f"Successfully processed {processed} session graphs with strict Chronological Tracking.")
    print(f"Algorithm 3 Generation Complete.")

if __name__ == '__main__':
    main()
