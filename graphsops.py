import networkx as nx
from schema import NODE_KEY

SPAWN_WINDOW_SEC = 5.0  # governs only the very first Query -> child-process hop


def get_node(G, node_type, key):
    nid = (node_type, key)
    return nid if nid in G.nodes else None


def add_or_update_node(G, node_type, attrs):
    key = NODE_KEY[node_type](attrs)
    nid = (node_type, key)
    if nid in G.nodes:
        G.nodes[nid]["last_seen"] = attrs.get("timestamp_unix")
    else:
        G.add_node(nid, type=node_type, **attrs)
    return nid


def add_directed_edge(G, u, v, rel, event_id, ts):
    """Coalesce repeated identical (u, rel, v) triples into one edge with a
    count + event_id list, instead of stacking a parallel edge per occurrence."""
    if G.has_edge(u, v, key=rel):
        edge = G[u][v][rel]
        edge["count"] += 1
        edge["event_ids"].append(event_id)
        edge["last_seen"] = ts
    else:
        G.add_edge(u, v, key=rel, rel=rel, count=1,
                   event_ids=[event_id], first_seen=ts, last_seen=ts)


def find_connection_rule(G, node_type, e, facts):
    ts = e.get("timestamp_unix")

    if node_type == "Query":
        u = get_node(G, "Session", e["session_key"])
        if u is None:
            u = add_or_update_node(G, "Session", {"session_key": e["session_key"],
                                                     "timestamp_unix": ts})
        return u, "executes"

    if node_type == "Table":
        return get_node(G, "Query", e["event_id"]), "accesses"

    if node_type == "Role":
        return get_node(G, "Query", e["event_id"]), "accesses"

    if node_type == "Process":
        # Priority 1: PID lineage -- parent already a Process node in G?
        # Handles multi-hop chains (sh -> gzip -> curl) regardless of elapsed
        # time between hops (fixes the 30s-delayed exfiltration case).
        ppid = e.get("ppid")
        parent_proc = get_node(G, "Process", ppid) if ppid else None
        if parent_proc is not None:
            return parent_proc, "spawns"

        # Priority 2: first child of a pending COPY ... TO PROGRAM query,
        # within a short window (this hop happens near-instantly regardless
        # of what the shell command itself later sleeps for).
        pending = G.graph.get("pending_spawn_source")
        pending_ts = G.graph.get("pending_spawn_ts")
        if pending is not None and pending_ts is not None and (ts - pending_ts) < SPAWN_WINDOW_SEC:
            q = get_node(G, "Query", pending)
            if q is not None:
                return q, "spawns"

        return None, None  # orphaned process -- log for review, don't crash

    if node_type == "Endpoint":
        return get_node(G, "Process", e["pid"]), "connects_to"

    if node_type == "File":
        return get_node(G, "Process", e["pid"]), "opens"

    return None, None