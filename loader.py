import csv
import json
from pathlib import Path


def load_attributed_events(event_table_path: Path, correlation_path: Path) -> list[dict]:
    """Join Algorithm 1's two output files into one attributed-event stream,
    sorted by true occurrence time (not by whichever order retries resolved
    them, which need not match chronological order)."""
    event_table = {e["event_id"]: e for e in json.load(open(event_table_path))}
    attributed = []
    with open(correlation_path) as f:
        for row in csv.DictReader(f):
            event = event_table[int(row["event_id"])]
            merged = {
                **event["raw"],
                "session_key": int(row["session_key"]),
                "event_id": event["event_id"],
                "source": event["source"],
                "timestamp_unix": event["timestamp"],  # top-level: already clock-calibrated
            }
            attributed.append(merged)
    attributed.sort(key=lambda e: e["timestamp_unix"])
    return attributed