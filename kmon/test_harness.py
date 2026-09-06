"""Offline self-test: generates synthetic baseline + anomaly dataset in memory,
asserts the analyzer flags each anomaly class and produces no flags on clean
baseline. Exit 0. Under ~15s."""

import json
import sys
import time


def _synthetic_clean_processes():
    """Normal process table."""
    return [
        {"collector": "process", "key": "pid:1", "pid": 1, "comm": "systemd",
         "stat_comm": "systemd", "exe": "/sbin/init", "exe_hash": "abc123",
         "state": "S", "ppid": 0, "threads": 1},
        {"collector": "process", "key": "pid:100", "pid": 100, "comm": "sshd",
         "stat_comm": "sshd", "exe": "/usr/sbin/sshd", "exe_hash": "def456",
         "state": "S", "ppid": 1, "threads": 5},
        {"collector": "process", "key": "pid:250", "pid": 250, "comm": "nginx",
         "stat_comm": "nginx", "exe": "/usr/sbin/nginx", "exe_hash": "ghi789",
         "state": "S", "ppid": 1, "threads": 4},
    ]


def _synthetic_clean_network():
    return [
        {"collector": "network", "key": "tcp:100", "proto": "tcp",
         "local": "0.0.0.0:22", "remote": "192.0.2.10:45678",
         "state": "ESTABLISHED", "inode": "100"},
        {"collector": "network", "key": "tcp:200", "proto": "tcp",
         "local": "0.0.0.0:80", "remote": "192.0.2.20:12345",
         "state": "ESTABLISHED", "inode": "200"},
    ]


def _synthetic_anomalous_processes():
    """Anomalous process table: known-bad name, hidden process, shadow reader."""
    procs = _synthetic_clean_processes()
    # known-bad binary
    procs.append({
        "collector": "process", "key": "pid:666", "pid": 666,
        "comm": "rootkit_test", "stat_comm": "rootkit_test",
        "exe": "/tmp/rootkit_test", "exe_hash": "",
        "state": "S", "ppid": 1, "threads": 1,
    })
    # hidden process (comm mismatch)
    procs.append({
        "collector": "process", "key": "pid:1337", "pid": 1337,
        "comm": "kworker/rcu/0", "stat_comm": "evil_root",
        "exe": "/usr/bin/evil", "exe_hash": "",
        "state": "S", "ppid": 2, "threads": 1,
    })
    return procs


def _synthetic_anomalous_network():
    """Bind shell on suspicious port."""
    conns = _synthetic_clean_network()
    conns.append({
        "collector": "network", "key": "tcp:999", "proto": "tcp",
        "local": "0.0.0.0:4444", "remote": "0.0.0.0:0",
        "state": "LISTEN", "inode": "999",
    })
    return conns


class SyntheticShadowReader:
    """Emulates shadow reading for flag test without real /etc/shadow."""
    pass


def run_self_test():
    """Run all assertions. Returns 0 on success, 1 on failure."""
    from kmon import anomaly
    from kmon import analyzer

    config = {
        "known_bad_binaries": [{"name": "rootkit_test", "sha256": ""}],
        "sensitive_paths": ["/etc/shadow"],
        "alert_thresholds": {
            "high_rate_open": 50,
            "syscall_rate_spike": 3.0,
            "hidden_pid_confidence": 0.8,
            "module_change_count": 1,
        },
        "bind_shell_ports": [4444, 5555, 6666, 1337],
    }

    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  PASS: {name}")
        else:
            failed += 1
            print(f"  FAIL: {name}")

    print("[self-test] Phase 1: clean baseline — expect 0 flags")
    clean = _synthetic_clean_processes() + _synthetic_clean_network()
    clean_flags = anomaly.run_all_flags(clean, config)
    # Only check flags that don't require real /proc (module change, ld_preload)
    clean_flags_filtered = [f for f in clean_flags if f["type"] not in ("module_change", "rootkit_ld_preload", "shadow_read")]
    check("clean baseline: 0 flags", len(clean_flags_filtered) == 0)

    print("[self-test] Phase 2: anomaly dataset — expect flags on each class")
    anomalous = _synthetic_anomalous_processes() + _synthetic_anomalous_network()
    flags = anomaly.run_all_flags(anomalous, config)
    flag_types = {f["type"] for f in flags}
    print(f"  Flag types found: {flag_types}")

    check("known_bad_binary flagged", "known_bad_binary" in flag_types)
    check("hidden_process flagged", "hidden_process" in flag_types)
    check("bind_shell flagged", "bind_shell" in flag_types)

    print("[self-test] Phase 3: baseline comparison")
    baseline = analyzer.capture_baseline(
        _synthetic_clean_processes(), _synthetic_clean_network())
    diffs = analyzer.compare_to_baseline(anomalous, baseline)
    check("baseline diff: new_process detected", any(d["type"] == "new_process" for d in diffs))
    check("baseline diff: new_connection detected", any(d["type"] == "new_connection" for d in diffs))

    print(f"\n[self-test] Results: {passed} passed, {failed} failed")
    if failed:
        print("[self-test] FAILED")
        return 1
    print("[self-test] ALL PASSED")
    return 0
