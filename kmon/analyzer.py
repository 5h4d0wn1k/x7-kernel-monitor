"""Analyzer: baseline comparison and anomaly scoring."""

import json
import os
import time


def capture_baseline(process_events, network_events):
    """Capture a clean baseline snapshot."""
    pids = {e.get("pid"): e.get("exe", "") for e in process_events if e.get("collector") == "process"}
    conns = [(e.get("local"), e.get("remote")) for e in network_events if e.get("collector") == "network"]
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid_count": len(pids),
        "pids": pids,
        "connection_count": len(conns),
        "connections": conns,
    }


def compare_to_baseline(current_events, baseline):
    """Compare current snapshot against baseline. Returns list of differences."""
    if not baseline:
        return []

    diffs = []
    curr_pids = {e.get("pid"): e for e in current_events if e.get("collector") == "process"}
    base_pids = baseline.get("pids", {})

    new_pids = set(curr_pids.keys()) - set(base_pids.keys())
    gone_pids = set(base_pids.keys()) - set(curr_pids.keys())

    for pid in new_pids:
        ev = curr_pids[pid]
        diffs.append({
            "type": "new_process",
            "pid": pid,
            "exe": ev.get("exe", ""),
            "comm": ev.get("comm", ""),
        })

    for pid in gone_pids:
        diffs.append({
            "type": "process_gone",
            "pid": pid,
            "exe": base_pids[pid],
        })

    curr_conns = [(e.get("local"), e.get("remote"))
                  for e in current_events if e.get("collector") == "network"]
    base_conns = set(baseline.get("connections", []))

    for c in curr_conns:
        if c not in base_conns:
            diffs.append({"type": "new_connection", "local": c[0], "remote": c[1]})

    return diffs


def write_jsonl(events, path):
    """Append events to JSONL file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def read_jsonl(path):
    """Read JSONL file into list of dicts."""
    events = []
    if not os.path.isfile(path):
        return events
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
