"""Collector base class + plugin implementations.

Each collector is a self-contained class that reads from /proc, /sys,
or optionally eBPF (guarded import — never crashes if absent).

Collectors:
  - ProcessCollector: /proc scanning for process listing
  - NetworkCollector: /proc/net/* for connections + RX/TX
  - FileCollector: sensitive-path open rate (periodic /proc/PID/fd scan)
  - SyscallCollector: abnormal syscall rate proxy via load + ps
"""

import hashlib
import os
import re
import time
from abc import ABC, abstractmethod

_eBPF = None
try:
    import bcc as _eBPF  # type: ignore
except ImportError:
    pass

_fanotify = None
try:
    import fanotify as _fanotify  # type: ignore
except ImportError:
    pass

EBPF_AVAILABLE = _eBPF is not None
FANOTIFY_AVAILABLE = _fanotify is not None


class Collector(ABC):
    name: str = "base"

    def __init__(self, config):
        self.config = config
        self._prev = {}

    @abstractmethod
    def collect(self):
        """Return list of normalized event dicts."""
        ...

    def diff(self, current):
        """Return events that changed since last collect."""
        events = []
        key_fn = lambda e: e.get("key", e.get("pid", str(e)))
        curr_map = {key_fn(e): e for e in current}
        for k, e in curr_map.items():
            if k not in self._prev:
                events.append({"event_type": "new", **e})
            elif self._prev[k] != e:
                events.append({"event_type": "changed", **e})
        self._prev = curr_map
        return events


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


class ProcessCollector(Collector):
    name = "process"

    def collect(self):
        max_p = self.config.get("sampling", {}).get("max_processes", 4096)
        procs = []
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return procs

        for pid_str in pids[:max_p]:
            pid = int(pid_str)
            base = f"/proc/{pid}"
            stat = _read_file(f"{base}/stat")
            status = _read_file(f"{base}/status")
            comm = _read_file(f"{base}/comm").strip()
            exe = os.readlink(f"{base}/exe") if os.path.islink(f"{base}/exe") else ""
            exe_hash = _sha256_path(f"{base}/exe")

            # parse stat: pid (comm) state ppid ...
            m = re.match(r"^\d+\s+\((.+)\)\s+(\S)\s+(\d+)", stat)
            state = m.group(2) if m else "?"
            ppid = int(m.group(3)) if m else 0
            real_comm = m.group(1) if m else comm

            threads = 0
            for line in status.splitlines():
                if line.startswith("Threads:"):
                    threads = int(line.split()[1])
                    break

            procs.append({
                "collector": "process",
                "key": f"pid:{pid}",
                "pid": pid,
                "comm": comm,
                "stat_comm": real_comm,
                "exe": exe,
                "exe_hash": exe_hash,
                "state": state,
                "ppid": ppid,
                "threads": threads,
            })
        return procs


class NetworkCollector(Collector):
    name = "network"

    def collect(self):
        max_c = self.config.get("sampling", {}).get("max_connections", 8192)
        events = []
        for proto in ("tcp", "udp", "tcp6", "udp6"):
            path = f"/proc/net/{proto}"
            content = _read_file(path)
            if not content:
                continue
            lines = content.strip().split("\n")[1:]
            for line in lines[:max_c]:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local = parts[1]
                remote = parts[2]
                state_int = int(parts[3], 16)
                inode = parts[9]

                st_map = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
                          4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
                          7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
                          10: "LISTEN", 11: "CLOSING"}
                state = st_map.get(state_int, f"UNKNOWN({state_int})")

                events.append({
                    "collector": "network",
                    "key": f"{proto}:{inode}",
                    "proto": proto,
                    "local": _decode_addr(local),
                    "remote": _decode_addr(remote),
                    "state": state,
                    "inode": inode,
                })
        return events


def _decode_addr(hex_addr):
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:
        ip_int = int(ip_hex, 16)
        ip = f"{ip_int & 0xff}.{(ip_int >> 8) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 24) & 0xff}"
    else:
        ip = ip_hex
    return f"{ip}:{port}"


class FileCollector(Collector):
    name = "file"

    def __init__(self, config):
        super().__init__(config)
        self._open_counts = {}

    def collect(self):
        sensitive = self.config.get("sensitive_paths", [])
        threshold = self.config.get("alert_thresholds", {}).get("high_rate_open", 50)
        max_p = self.config.get("sampling", {}).get("max_processes", 4096)
        events = []
        now = time.time()

        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return events

        for pid_str in pids[:max_p]:
            fd_dir = f"/proc/{pid_str}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (OSError, PermissionError):
                continue

            open_sensitive = []
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except (OSError, PermissionError):
                    continue
                for sp in sensitive:
                    if link == sp or link.startswith(sp):
                        open_sensitive.append(sp)

            if open_sensitive:
                for sp in open_sensitive:
                    key = f"{pid_str}:{sp}"
                    self._open_counts[key] = self._open_counts.get(key, 0) + 1
                    if self._open_counts[key] >= threshold:
                        events.append({
                            "collector": "file",
                            "key": key,
                            "pid": int(pid_str),
                            "path": sp,
                            "open_count": self._open_counts[key],
                        })
        return events


class SyscallCollector(Collector):
    name = "syscall"

    def __init__(self, config):
        super().__init__(config)
        self._load_history = []

    def collect(self):
        spike_mult = self.config.get("alert_thresholds", {}).get("syscall_rate_spike", 3.0)
        events = []

        loadavg = _read_file("/proc/loadavg")
        if loadavg:
            parts = loadavg.split()
            load1 = float(parts[0])
            load5 = float(parts[1])
            self._load_history.append(load1)
            if len(self._load_history) > 60:
                self._load_history.pop(0)
            if len(self._load_history) > 10:
                mean = sum(self._load_history) / len(self._load_history)
                if mean > 0 and load1 > mean * spike_mult:
                    events.append({
                        "collector": "syscall",
                        "key": "load_spike",
                        "load1": load1,
                        "mean": round(mean, 2),
                        "spike_ratio": round(load1 / mean, 2),
                    })

        # io_uring / unusual syscall proxy via /proc/PID/syscall
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return events

        for pid_str in pids[:1024]:
            sc = _read_file(f"/proc/{pid_str}/syscall")
            if sc:
                parts = sc.split()
                if parts and parts[0] not in ("0", "1", "2", "3", "4", "5", "6", "7",
                                                "8", "9", "10", "56", "57", "59", "231"):
                    events.append({
                        "collector": "syscall",
                        "key": f"syscall:{pid_str}",
                        "pid": int(pid_str),
                        "syscall": parts[0],
                    })
        return events


ALL_COLLECTORS = [ProcessCollector, NetworkCollector, FileCollector, SyscallCollector]
