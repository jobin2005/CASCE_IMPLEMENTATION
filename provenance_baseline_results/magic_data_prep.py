#!/usr/bin/env python3
"""Convert the CASCE multi-domain corpus into MAGIC's expected input format.

MAGIC's batch-level loader (utils/loaddata.py, StreamspotDataset) expects one
networkx.node_link_data JSON file per graph, with a single integer `type` on
every node and every edge (0-indexed, one-hot encoded internally by MAGIC's
own transform_graph). Multi-edges are collapsed to single edges -- this is
not a handicap imposed here, it's exactly what MAGIC's own streamspot_parser.py
does to its native data (`if not g.has_edge(...)`).

Uses the SAME family-disjoint split as CASCE's own GAT and the other
baselines (output/corpus_multidomain/algo4_splits/), so MAGIC's numbers are
apples-to-apples with the rest of the comparison table.
"""
import json
import sys
from pathlib import Path

import networkx as nx

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "output" / "corpus_multidomain"
OUT = Path(__file__).resolve().parent / "magic" / "data" / "casce"


def convert():
    splits = {}
    for part in ("train", "val", "test"):
        splits[part] = json.loads((CORPUS / "algo4_splits" / f"{part}_labels.json").read_text())

    node_types, edge_types = {}, {}
    manifest = {"train": [], "val": [], "test": []}
    OUT.mkdir(parents=True, exist_ok=True)

    gidx = 0
    for part, labels in splits.items():
        for fname, label in labels.items():
            path = CORPUS / "graphml" / fname
            if not path.exists():
                continue
            G = nx.read_graphml(path)
            H = nx.DiGraph()
            for n, d in G.nodes(data=True):
                t = d.get("type", "Unknown")
                node_types.setdefault(t, len(node_types))
                H.add_node(n, type=node_types[t])
            edge_iter = G.edges(keys=True, data=True) if G.is_multigraph() else G.edges(data=True)
            for edge in edge_iter:
                u, v, d = edge[0], edge[1], edge[-1]
                rel = d.get("relation", d.get("rel", "unknown"))
                edge_types.setdefault(rel, len(edge_types))
                if not H.has_edge(u, v):
                    H.add_edge(u, v, type=edge_types[rel])
            H = nx.convert_node_labels_to_integers(H)

            out_fname = f"{gidx}.json"
            (OUT / out_fname).write_text(json.dumps(nx.node_link_data(H)))
            manifest[part].append({"idx": gidx, "file": out_fname, "label": int(label)})
            gidx += 1

    (OUT / "manifest.json").write_text(json.dumps({
        "node_type_map": node_types, "edge_type_map": edge_types, "splits": manifest,
    }, indent=2))
    for part in ("train", "val", "test"):
        n = len(manifest[part])
        n_mal = sum(m["label"] for m in manifest[part])
        print(f"{part}: {n} graphs ({n_mal} malicious, {n - n_mal} benign)")
    print(f"node types ({len(node_types)}): {node_types}")
    print(f"edge types ({len(edge_types)}): {edge_types}")
    print(f"-> {OUT}")


if __name__ == "__main__":
    convert()
