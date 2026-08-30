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
    
    # Template: DATA_ACCESS (T1003) -> Query reads_from Table
    g_access = nx.DiGraph()
    g_access.add_node("T_Query", type="Query")
    g_access.add_node("T_Table", type="Table")
    g_access.add_edge("T_Query", "T_Table", relation="reads_from")
    templates.append(BehaviorTemplate(
        label="DATA_ACCESS", 
        mitre_id="T1003", 
        graph_structure=g_access, 
        semantic_keywords=["select", "from", "pg_class", "pg_shadow", "pg_authid"], 
        temporal_constraints={"max_gap": 5.0}
    ))

    # Template: DATA_PACKAGING (T1560) -> Process executes File
    g_package = nx.DiGraph()
    g_package.add_node("T_Process", type="Process")
    g_package.add_node("T_File", type="File")
    g_package.add_edge("T_Process", "T_File", relation="executes")
    templates.append(BehaviorTemplate(
        label="DATA_PACKAGING", 
        mitre_id="T1560", 
        graph_structure=g_package, 
        semantic_keywords=["tar", "gzip", "zip"], 
        temporal_constraints={"max_gap": 30.0}
    ))

    # Template: EXTERNAL_TRANSFER (T1048) -> Process connects_to Endpoint
    g_transfer = nx.DiGraph()
    g_transfer.add_node("T_Process", type="Process")
    g_transfer.add_node("T_Endpoint", type="Endpoint")
    g_transfer.add_edge("T_Process", "T_Endpoint", relation="connects_to")
    templates.append(BehaviorTemplate(
        label="EXTERNAL_TRANSFER", 
        mitre_id="T1048", 
        graph_structure=g_transfer, 
        semantic_keywords=["curl", "wget", "nc", "bash", "sh"], 
        temporal_constraints={"max_gap": 30.0}
    ))

    # Template: OBJECT_DESTRUCTION (T1485) -> Query modifies Table
    g_destruct = nx.DiGraph()
    g_destruct.add_node("T_Query", type="Query")
    g_destruct.add_node("T_Table", type="Table")
    g_destruct.add_edge("T_Query", "T_Table", relation="modifies")
    templates.append(BehaviorTemplate(
        label="OBJECT_DESTRUCTION", 
        mitre_id="T1485", 
        graph_structure=g_destruct, 
        semantic_keywords=["drop", "delete", "truncate", "rm", "unlink"], 
        temporal_constraints={"max_gap": 15.0}
    ))

    return templates

# Efficient pre-fit TF-IDF Vectorizer
GLOBAL_CORPUS = [
    "select from pg_class pg_shadow pg_authid", 
    "tar gzip zip", 
    "curl wget nc bash sh",
    "drop delete truncate rm unlink"
]
VECTORIZER = TfidfVectorizer().fit(GLOBAL_CORPUS)

def calculate_s_struct(G_sub, T):
    nm = isomorphism.categorical_node_match(["type"], ["Unknown"])
    em = isomorphism.categorical_edge_match(["relation"], ["Unknown"])
    matcher = isomorphism.DiGraphMatcher(G_sub, T.structure, node_match=nm, edge_match=em)
    
    # MENTOR FIX 1 & 2: Finding arbitrary matching subgraphs (multiple matches!)
    match_list = []
    for mapping in matcher.subgraph_isomorphisms_iter():
        match_list.append(list(mapping.keys()))
    return match_list

def calculate_s_sem(matched_nodes, G_s, T_keywords):
    factual_text = " ".join([G_s.nodes[n].get("label", "").lower() for n in matched_nodes])
    template_text = " ".join(T_keywords)
    
    if not factual_text.strip(): return 0.0
    
    # MENTOR FIX 6 & USER OVR: Keeping mathematics but efficient!
    vectors = VECTORIZER.transform([factual_text, template_text]).toarray()
    norm_f = np.linalg.norm(vectors[0])
    norm_t = np.linalg.norm(vectors[1])
    
    if norm_f == 0 or norm_t == 0: return 0.0
    return float(np.dot(vectors[0], vectors[1]) / (norm_f * norm_t))

def calculate_s_temp(matched_nodes, G_s, template):
    timestamps = []
    for n in matched_nodes:
        ts = G_s.nodes[n].get("timestamp")
        if ts is not None:
            try:
                timestamps.append(float(ts))
            except ValueError:
                pass
                
    if not timestamps:
        # Fallback if Algorithm 2 modifications aren't flushed yet
        return 0.90 
        
    delta_t = max(timestamps) - min(timestamps)
    max_gap = template.temporal_constraints.get("max_gap", 30.0)
    
    # MENTOR FIX 4: Actual temporal calculation S_{temp} = e^{-\Delta t/\tau}
    return float(math.exp(-delta_t / max_gap))

def abstract_session_graph(G_s, templates, theta_beh=0.60):
    G_enriched = G_s.copy()
    
    # MENTOR FIX 7: Equal weight sums nicely to 1.0
    alpha = 0.33
    beta = 0.33
    gamma = 0.34
    
    behavior_counter = 0
    detected_behaviors = []

    for template in templates:
        # MENTOR FIX: We must search against the pure factual graph (G_s), NOT G_enriched, 
        # to guarantee behavior nodes don't topologically feed back into future searches!
        matches = calculate_s_struct(G_s, template)
        
        for matched_nodes in matches:
            s_sem = calculate_s_sem(matched_nodes, G_s, template.semantic_keywords)
            s_temp = calculate_s_temp(matched_nodes, G_s, template)
            
            # Confidence Calculation
            confidence = (alpha * 1.0) + (beta * s_sem) + (gamma * s_temp)
            
            if confidence >= theta_beh:
                behavior_counter += 1
                beh_node_name = f"Behavior_{template.label}_{behavior_counter}"
                
                # MENTOR FIX: A behavior is considered completed at the LATEST matched fact's timestamp
                node_timestamps = [float(G_s.nodes[n].get("timestamp", 0)) for n in matched_nodes if G_s.nodes[n].get("timestamp")]
                beh_timestamp = max(node_timestamps) if node_timestamps else 0.0
                
                G_enriched.add_node(beh_node_name, 
                                  type="Behavior", 
                                  label=f"[{template.mitre_id}] {template.label}", 
                                  confidence=str(round(confidence, 3)),
                                  timestamp=str(beh_timestamp))
                                  
                # Evidence Edging
                for v in matched_nodes:
                    G_enriched.add_edge(v, beh_node_name, relation="evidence_for")
                    
                detected_behaviors.append({
                    "node_name": beh_node_name,
                    "timestamp": beh_timestamp
                })
                
    # MENTOR FIX 5: Chronological Chaining!
    detected_behaviors.sort(key=lambda x: x["timestamp"])
    
    for i in range(1, len(detected_behaviors)):
        prev_node = detected_behaviors[i-1]["node_name"]
        curr_node = detected_behaviors[i]["node_name"]
        G_enriched.add_edge(prev_node, curr_node, relation="precedes")
                
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
