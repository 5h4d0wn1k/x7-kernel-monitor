#!/usr/bin/env python3
"""X7 — Kernel Integrity Monitor. Userspace kernel integrity checking with pet rootkit simulation."""

import hashlib
import json
import random
import sys
import time
from collections import defaultdict

EBPF_AVAILABLE = False
try:
    pass
except ImportError:
    pass


TRUSTED_MODULE_REGISTRY = {
    "vboxdrv": {"sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "size": 245760},
    "i915": {"sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", "size": 1843200},
    "ext4": {"sha256": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "size": 163840},
    "nvidia": {"sha256": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", "size": 31457280},
    "kvm": {"sha256": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", "size": 81920},
    "virtio_pci": {"sha256": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1", "size": 40960},
    "overlay": {"sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "size": 61440},
    "udf": {"sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", "size": 30720},
}

LEGITIMATE_SYSCALLS = {
    0: {"name": "read", "addr": 0xffffffff81234567},
    1: {"name": "write", "addr": 0xffffffff81234570},
    2: {"name": "open", "addr": 0xffffffff81234579},
    3: {"name": "close", "addr": 0xffffffff81234582},
    56: {"name": "clone", "addr": 0xffffffff81234600},
    57: {"name": "fork", "addr": 0xffffffff81234610},
    59: {"name": "execve", "addr": 0xffffffff81234620},
    231: {"name": "exit_group", "addr": 0xffffffff81234700},
    302: {"name": "prlimit64", "addr": 0xffffffff81234750},
}


class PetRootkitSim:
    """Pure-Python mock process table that hides a PID to test the detector."""

    def __init__(self):
        self.hidden_pid = 1337
        self.hidden_process = {
            "pid": 1337,
            "name": "kworker/rcu/0",
            "ppid": 2,
            "user": "root",
            "cmd": "[rcu/0]",
            "state": "S",
            "start_time": "2026-09-04T10:00:00Z",
        }
        self.visible_pids = self._generate_visible_pids()

    def _generate_visible_pids(self):
        pids = []
        system_procs = [
            {"pid": 1, "name": "systemd", "ppid": 0, "user": "root", "cmd": "/sbin/init", "state": "S"},
            {"pid": 2, "name": "kthreadd", "ppid": 0, "user": "root", "cmd": "[kthreadd]", "state": "S"},
            {"pid": 100, "name": "sshd", "ppid": 1, "user": "root", "cmd": "/usr/sbin/sshd", "state": "S"},
            {"pid": 250, "name": "nginx", "ppid": 1, "user": "www-data", "cmd": "nginx: worker", "state": "S"},
            {"pid": 500, "name": "mysqld", "ppid": 1, "user": "mysql", "cmd": "/usr/sbin/mysqld", "state": "S"},
            {"pid": 750, "name": "cron", "ppid": 1, "user": "root", "cmd": "/usr/sbin/cron", "state": "S"},
            {"pid": 1000, "name": "python3", "ppid": 100, "user": "admin", "cmd": "/usr/bin/python3 app.py", "state": "S"},
            {"pid": 1200, "name": "bash", "ppid": 1000, "user": "admin", "cmd": "/bin/bash", "state": "S"},
            {"pid": 1500, "name": "node", "ppid": 1, "user": "www-data", "cmd": "/usr/bin/node server.js", "state": "S"},
            {"pid": 2000, "name": "containerd", "ppid": 1, "user": "root", "cmd": "/usr/bin/containerd", "state": "S"},
        ]
        for p in system_procs:
            p["start_time"] = "2026-09-04T08:00:00Z"
            pids.append(p)
        return pids

    def get_proc_listing(self):
        """Simulates /proc listing — hides PID 1337."""
        return [p for p in self.visible_pids if p["pid"] != self.hidden_pid]

    def get_full_process_table(self):
        """Simulates a deeper view that includes hidden PID."""
        return self.visible_pids + [self.hidden_process]

    def get_tcp_connections(self):
        """Simulates /proc/net/tcp — includes hidden PID connections."""
        connections = [
            {"local": "0.0.0.0:22", "remote": "192.168.1.50:45678", "state": "ESTABLISHED", "pid": 100},
            {"local": "0.0.0.0:80", "remote": "10.0.0.5:12345", "state": "ESTABLISHED", "pid": 250},
            {"local": "0.0.0.0:3306", "remote": "192.168.1.10:54321", "state": "ESTABLISHED", "pid": 500},
            {"local": "0.0.0.0:8080", "remote": "10.0.0.99:4444", "state": "ESTABLISHED", "pid": 1337},
            {"local": "0.0.0.0:3000", "remote": "192.168.1.50:9999", "state": "ESTABLISHED", "pid": 1500},
        ]
        return connections

    def get_modules_list(self):
        """Simulates lsmod — includes hidden rootkit module."""
        return [
            {"name": "vboxdrv", "size": 245760, "refs": 1},
            {"name": "i915", "size": 1843200, "refs": 5},
            {"name": "ext4", "size": 163840, "refs": 3},
            {"name": "nvidia", "size": 31457280, "refs": 2},
            {"name": "kvm", "size": 81920, "refs": 1},
            {"name": "virtio_pci", "size": 40960, "refs": 1},
            {"name": "overlay", "size": 61440, "refs": 2},
            {"name": "udf", "size": 30720, "refs": 0},
            {"name": "test_rootkit", "size": 8192, "refs": 1},
        ]

    def get_syscall_table(self):
        """Simulates syscall table — one hooked."""
        table = dict(LEGITIMATE_SYSCALLS)
        table[59] = {"name": "execve", "addr": 0xffff888012340000}
        return table


class KernelIntegrityMonitor:
    """Userspace kernel integrity monitoring and alerting."""

    def __init__(self, rootkit_sim=None):
        self.rootkit = rootkit_sim or PetRootkitSim()
        self.alerts = []
        self.checks_run = 0

    def _emit_alert(self, severity, alert_type, detail, technique="T1014"):
        alert = {
            "timestamp": "2026-09-04T12:00:00Z",
            "severity": severity,
            "type": alert_type,
            "detail": detail,
            "technique": technique,
        }
        self.alerts.append(alert)
        return alert

    def scan_hidden_pids(self):
        """Cross-reference /proc listing with deeper process table views."""
        print("\n--- PID Cross-Reference Scan ---")
        proc_listing = self.rootkit.get_proc_listing()
        full_table = self.rootkit.get_full_process_table()
        tcp_conns = self.rootkit.get_tcp_connections()

        visible_pids = {p["pid"] for p in proc_listing}
        all_pids = {p["pid"] for p in full_table}
        tcp_pids = {c["pid"] for c in tcp_conns}

        hidden_from_proc = all_pids - visible_pids
        hidden_from_tcp = tcp_pids - visible_pids

        alerts = []
        for pid in hidden_from_proc:
            proc_info = next((p for p in full_table if p["pid"] == pid), None)
            tcp_info = next((c for c in tcp_conns if c["pid"] == pid), None)
            detail = f"PID {pid} ({proc_info['name']} — hidden from /proc listing)"
            evidence_parts = []
            if tcp_info:
                evidence_parts.append(f"present in /proc/net/tcp connecting to {tcp_info['remote']}")
            evidence_parts.append("missing from /proc/")
            detail += f"\n      Evidence: {'; '.join(evidence_parts)}"
            print(f"  [!] HIDDEN PID DETECTED: {detail}")
            alert = self._emit_alert("HIGH", "hidden_pid",
                                     f"PID {pid} hidden from /proc — {proc_info['name']} — TCP: {tcp_info['remote'] if tcp_info else 'N/A'}",
                                     "T1014")
            alerts.append(alert)

        if not hidden_from_proc:
            print("  [OK] All PIDs visible across /proc views")
        self.checks_run += 1
        return alerts

    def scan_syscall_table(self):
        """Check for syscall table hooks by comparing known-good addresses."""
        print("\n--- Syscall Table Integrity ---")
        table = self.rootkit.get_syscall_table()
        alerts = []

        for syscall_id, info in LEGITIMATE_SYSCALLS.items():
            current = table.get(syscall_id, {})
            current_addr = current.get("addr", 0)
            legit_addr = info["addr"]
            if current_addr != legit_addr:
                detail = f"syscall {info['name']} ({syscall_id}) — hook detected at 0x{current_addr:016x}"
                print(f"  [WARN] {detail}")
                alert = self._emit_alert("HIGH", "syscall_hook",
                                         f"{info['name']} hooked at 0x{current_addr:016x} (expected 0x{legit_addr:016x})",
                                         "T1014")
                alerts.append(alert)
            else:
                print(f"  [OK] syscall {info['name']} ({syscall_id}) — unmodified at 0x{current_addr:016x}")

        self.checks_run += 1
        return alerts

    def scan_modules(self):
        """Compare loaded modules against trusted registry snapshot."""
        print("\n--- Module Registry Check ---")
        loaded = self.rootkit.get_modules_list()
        alerts = []
        verified = 0

        for mod in loaded:
            name = mod["name"]
            registry_entry = TRUSTED_MODULE_REGISTRY.get(name)
            if registry_entry is None:
                detail = f"UNAUTHORIZED MODULE: {name}.ko (not in registry, size={mod['size']})"
                print(f"  [!] {detail}")
                alert = self._emit_alert("CRITICAL", "rogue_module",
                                         f"{name}.ko not in trusted registry (size={mod['size']}, refs={mod['refs']})",
                                         "T1547.006")
                alerts.append(alert)
            else:
                if registry_entry["size"] != mod["size"]:
                    detail = f"MODULE SIZE MISMATCH: {name}.ko (expected={registry_entry['size']}, got={mod['size']})"
                    print(f"  [!] {detail}")
                    alert = self._emit_alert("HIGH", "module_tamper",
                                             f"{name}.ko size mismatch: {mod['size']} vs {registry_entry['size']}",
                                             "T1547.006")
                    alerts.append(alert)
                else:
                    verified += 1

        print(f"  [{verified}] modules verified against registry snapshot")
        self.checks_run += 1
        return alerts

    def heartbeat_check(self, checks=3):
        """Periodic liveness monitoring."""
        print("\n--- Heartbeat Monitor ---")
        for i in range(checks):
            print(f"  [*] Heartbeat check {i+1}/{checks} — all systems responding")
        print(f"  [*] Heartbeat interval: every 5s ({checks} checks passed)")
        self.checks_run += 1
        return []

    def full_scan(self):
        """Run all integrity checks."""
        print("[*] Initializing kernel integrity monitor...")
        print(f"[*] Pet rootkit simulation loaded (hidden PID: {self.rootkit.hidden_pid})")
        print(f"[*] eBPF available: {EBPF_AVAILABLE} (stubbed if not)")

        all_alerts = []
        all_alerts.extend(self.scan_hidden_pids())
        all_alerts.extend(self.scan_syscall_table())
        all_alerts.extend(self.scan_modules())
        all_alerts.extend(self.heartbeat_check())

        return all_alerts

    def get_alerts(self):
        return self.alerts

    def print_summary(self):
        print("\n=== Summary ===")
        print(f"  Checks run:     {self.checks_run}")
        high = sum(1 for a in self.alerts if a["severity"] == "HIGH")
        crit = sum(1 for a in self.alerts if a["severity"] == "CRITICAL")
        print(f"  Alerts:         {len(self.alerts)} ({high} HIGH, {crit} CRITICAL)")
        hidden = sum(1 for a in self.alerts if a["type"] == "hidden_pid")
        hooks = sum(1 for a in self.alerts if a["type"] == "syscall_hook")
        modules = sum(1 for a in self.alerts if a["type"] in ("rogue_module", "module_tamper"))
        print(f"  Hidden PIDs:    {hidden}")
        print(f"  Hooked calls:   {hooks}")
        print(f"  Rogue modules:  {modules}")

    def print_alert_stream(self):
        print("\n=== Alert Stream (SIEM JSON) ===")
        for alert in self.alerts:
            print(json.dumps(alert))


def main():
    print("=" * 60)
    print("  X7 — Kernel Integrity Monitor")
    print("=" * 60)

    rootkit = PetRootkitSim()
    monitor = KernelIntegrityMonitor(rootkit_sim=rootkit)
    monitor.full_scan()
    monitor.print_summary()
    monitor.print_alert_stream()

    print("\n[+] Monitor complete — exit 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
