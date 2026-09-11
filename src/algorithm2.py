import csv
import json
from pathlib import Path

import networkx as nx

from schema import NODE_TYPES
from sqlfacts import extract_query_facts
from graphsops import add_or_update_node, add_directed_edge, find_connection_rule
from loader import load_attributed_events

ORPHAN_LOG: list[dict] = []   # module-level, drained by run() at the end of each run
PARSE_ERROR_LOG: list[dict] = []


def identify_node_types(e: dict, facts: dict) -> list[str]:
    if e.get("source") == "postgres":
        types = ["Query"]
        if facts.get("table_name"):
            types.append("Table")
        if facts.get("role_name"):
            types.append("Role")
        return types
    syscall = e.get("syscall")
    if syscall == "execve":
        return ["Process"]
    if syscall in ("openat", "unlink", "rename"):
        return ["Process", "File"]  # need the Process node to exist so 'opens' has a source
    if syscall == "connect":
        types = ["Process"]
        if e.get("dest_ip"):  # AF_UNIX/AF_INET6 connects carry no dest_ip -- skip Endpoint for those
            types.append("Endpoint")
        return types
    return []


def process_event(session_key: int, e: dict, active_graphs: dict[int, nx.MultiDiGraph]):
    G = active_graphs.setdefault(session_key, nx.MultiDiGraph())
    ts = e["timestamp_unix"]

    facts = extract_query_facts(e.get("query")) if e.get("source") == "postgres" else {}
    if facts.get("parse_error"):
        PARSE_ERROR_LOG.append({"session_key": session_key, "event_id": e["event_id"],
                                  "error": facts["parse_error"], "query": e.get("query")})

    node_types = identify_node_types(e, facts)
    for nt in node_types:
        if nt not in NODE_TYPES:
            continue
        attrs = {**e, **facts, "timestamp_unix": ts}
        if nt == "File" and "filepath" not in attrs:
            attrs["filepath"] = e.get("arg", "")  # real kernel schema stores path in 'arg'
        v = add_or_update_node(G, nt, attrs)
        u, rel = find_connection_rule(G, nt, e, facts)
        if u is not None:
            add_directed_edge(G, u, v, rel, e["event_id"], ts)
        elif nt == "Process":
            ORPHAN_LOG.append({"session_key": session_key, "event_id": e["event_id"],
                                 "pid": e.get("pid"), "ppid": e.get("ppid"), "comm": e.get("comm")})

    if facts.get("is_program"):
        G.graph["pending_spawn_source"] = e["event_id"]
        G.graph["pending_spawn_ts"] = ts

    G.graph["last_event_ts"] = ts


def run(event_table_path: Path, correlation_path: Path, out_dir: Path,
        run_id: str, labels_path: Path | None = None):
    ORPHAN_LOG.clear()
    PARSE_ERROR_LOG.clear()

    labels = {}
    if labels_path and labels_path.exists():
        with labels_path.open() as f:
            for row in csv.DictReader(f):
                if row["session_id"]:
                    labels[int(row["session_id"])] = row["label"]

    attributed = load_attributed_events(event_table_path, correlation_path)

    active_graphs: dict[int, nx.MultiDiGraph] = {}
    for e in attributed:
        process_event(e["session_key"], e, active_graphs)

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows = []
    for session_key, G in active_graphs.items():
        fname = f"{run_id}_session_{session_key}.json"
        (out_dir / fname).write_text(json.dumps(nx.node_link_data(G), default=str))
        manifest_rows.append({
            "run_id": run_id,
            "session_key": session_key,
            "label": labels.get(session_key, "unknown"),
            "graph_file": fname,
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
        })

    with (out_dir / "manifest.jsonl").open("a") as manifest:
        for row in manifest_rows:
            manifest.write(json.dumps(row) + "\n")

    if ORPHAN_LOG:
        with (out_dir / f"{run_id}_orphans.jsonl").open("w") as f:
            for row in ORPHAN_LOG:
                f.write(json.dumps(row) + "\n")
    if PARSE_ERROR_LOG:
        with (out_dir / f"{run_id}_parse_errors.jsonl").open("w") as f:
            for row in PARSE_ERROR_LOG:
                f.write(json.dumps(row) + "\n")

    return active_graphs, manifest_rows, list(ORPHAN_LOG), list(PARSE_ERROR_LOG)


if __name__ == "__main__":
    import sys
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4],
        Path(sys.argv[5]) if len(sys.argv) > 5 else None)