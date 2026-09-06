"""YAML config loader with defaults."""

import json
import os

_DEFAULTS = {
    "collection": {"interval": 2, "duration": None},
    "sensitive_paths": ["/etc/shadow", "/etc/sudoers"],
    "alert_thresholds": {
        "high_rate_open": 50,
        "syscall_rate_spike": 3.0,
        "hidden_pid_confidence": 0.8,
        "module_change_count": 1,
    },
    "sampling": {"max_processes": 4096, "max_connections": 8192, "max_file_events": 10000},
    "known_bad_binaries": [],
    "bind_shell_ports": [4444, 5555, 6666, 1337],
    "output": {"jsonl_path": "alerts/alerts.jsonl", "log_path": "logs/kmon.log"},
}


def _deep_merge(base, override):
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(path=None):
    """Load config from YAML if available, else use defaults. No YAML dep required."""
    cfg = dict(_DEFAULTS)
    if path and os.path.isfile(path):
        try:
            import yaml
            with open(path) as f:
                user = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, user)
        except ImportError:
            cfg = _load_yaml_fallback(path, cfg)
    return cfg


def _load_yaml_fallback(path, cfg):
    """Minimal key: value parser — no external deps."""
    import re
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(\w[\w_]*):\s*(.+)$", line)
            if m:
                key, val = m.group(1), m.group(2).strip()
                if val == "null":
                    val = None
                elif val.isdigit():
                    val = int(val)
                else:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
                if key in cfg and isinstance(cfg[key], dict) and isinstance(val, dict):
                    pass  # skip complex nesting in fallback
                else:
                    cfg[key] = val
    return cfg
