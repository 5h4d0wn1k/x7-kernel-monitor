"""Anomaly detection flags.

Each function takes collector events + config and returns a list of
alert dicts with {severity, type, detail, technique, collector}.

Flags:
  - known_bad_binary: PID running a known-bad binary name (with hash check)
  - shadow_read: process reading /etc/shadow
  - bind_shell: unusual bind shell on high port
  - hidden_process: comm mismatch or abnormal thread count
  - rootkit_ld_preload: LD_PRELOAD env in /proc/PID/environ
  - rootkit_module_change: kernel module list delta
"""

import hashlib
import os


def _read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, PermissionError):
        return ""


def _sha256_path(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _base_alert(severity, atype, detail, technique, collector):
    return {
        "severity": severity,
        "type": atype,
        "detail": detail,
        "technique": technique,
        "collector": collector,
    }


def flag_known_bad_binaries(process_events, config):
    bad = config.get("known_bad_binaries", [])
    alerts = []
    for ev in process_events:
        if ev.get("collector") != "process":
            continue
        exe = ev.get("exe", "")
        comm = ev.get("comm", "")
        for bad_entry in bad:
            name = bad_entry.get("name", "")
            expected_hash = bad_entry.get("sha256", "")
            if name and (name in exe or name in comm):
                if expected_hash and ev.get("exe_hash") != expected_hash:
                    alerts.append(_base_alert("CRITICAL", "known_bad_binary",
                        f"PID {ev['pid']} matches {name} (hash mismatch: {ev.get('exe_hash', '')})",
                        "T1014", "process"))
                else:
                    alerts.append(_base_alert("HIGH", "known_bad_binary",
                        f"PID {ev['pid']} matches known-bad name {name}",
                        "T1014", "process"))
    return alerts


def flag_shadow_read(process_events, config):
    sensitive = config.get("sensitive_paths", [])
    alerts = []
    for ev in process_events:
        if ev.get("collector") != "process":
            continue
        pid = ev.get("pid", 0)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (OSError, PermissionError):
            continue
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except (OSError, PermissionError):
                continue
            if "/etc/shadow" in link:
                alerts.append(_base_alert("CRITICAL", "shadow_read",
                    f"PID {pid} ({ev.get('comm', '?')}) has /etc/shadow open",
                    "T1003.008", "file"))
    return alerts


def flag_bind_shell(network_events, config):
    bind_ports = set(config.get("bind_shell_ports", []))
    alerts = []
    for ev in network_events:
        if ev.get("collector") != "network":
            continue
        if ev.get("state") != "LISTEN":
            continue
        local = ev.get("local", "")
        parts = local.rsplit(":", 1)
        if len(parts) == 2:
            try:
                port = int(parts[1])
            except ValueError:
                continue
            if port in bind_ports:
                alerts.append(_base_alert("MEDIUM", "bind_shell",
                    f"Unusual bind on port {port}: {local}",
                    "T1059.004", "network"))
    return alerts


def flag_hidden_process(process_events, config):
    """Detect PID hiding by comm mismatch or extreme thread counts."""
    alerts = []
    for ev in process_events:
        if ev.get("collector") != "process":
            continue
        stat_comm = ev.get("stat_comm", "")
        comm = ev.get("comm", "")
        if stat_comm and comm and stat_comm != comm:
            alerts.append(_base_alert("HIGH", "hidden_process",
                f"PID {ev['pid']}: comm '{comm}' != stat_comm '{stat_comm}'",
                "T1014", "process"))

        threads = ev.get("threads", 0)
        if threads > 500:
            alerts.append(_base_alert("MEDIUM", "hidden_process",
                f"PID {ev['pid']} ({comm}): {threads} threads (abnormal)",
                "T1014", "process"))
    return alerts


def flag_ld_preload(process_events, config):
    """Check /proc/PID/environ for LD_PRELOAD."""
    alerts = []
    for ev in process_events:
        if ev.get("collector") != "process":
            continue
        pid = ev.get("pid", 0)
        environ = _read_file(f"/proc/{pid}/environ")
        if "LD_PRELOAD" in environ:
            alerts.append(_base_alert("CRITICAL", "rootkit_ld_preload",
                f"PID {ev['pid']} ({ev.get('comm', '?')}) has LD_PRELOAD set",
                "T1574.006", "process"))
    return alerts


_prev_modules = None


def flag_module_change(events, config):
    """Detect kernel module list changes via /proc/modules."""
    global _prev_modules
    content = _read_file("/proc/modules")
    current = set()
    for line in content.strip().split("\n"):
        name = line.split()[0] if line.strip() else ""
        if name:
            current.add(name)

    alerts = []
    if _prev_modules is not None:
        added = current - _prev_modules
        removed = _prev_modules - current
        threshold = config.get("alert_thresholds", {}).get("module_change_count", 1)

        for mod in added:
            alerts.append(_base_alert("HIGH", "module_change",
                f"Module loaded: {mod}",
                "T1547.006", "process"))
        for mod in removed:
            alerts.append(_base_alert("MEDIUM", "module_change",
                f"Module unloaded: {mod}",
                "T1547.006", "process"))

    _prev_modules = current
    return alerts


ALL_FLAGS = [
    flag_known_bad_binaries,
    flag_shadow_read,
    flag_bind_shell,
    flag_hidden_process,
    flag_ld_preload,
    flag_module_change,
]


def run_all_flags(collector_events, config):
    alerts = []
    for fn in ALL_FLAGS:
        alerts.extend(fn(collector_events, config))
    return alerts
