> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X7 — Linux Kernel & System Activity Monitor

Detection-tool-focused **kernel activity monitoring** with process, network,
file, and syscall collectors, MITRE-mapped anomaly flags, and optional eBPF
backends — for **endpoint detection research** and **blue-team** telemetry.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/x7-kernel-monitor)](https://github.com/5h4d0wn1k/x7-kernel-monitor)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/x7-kernel-monitor)](https://github.com/5h4d0wn1k/x7-kernel-monitor/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/x7-kernel-monitor)](https://github.com/5h4d0wn1k/x7-kernel-monitor)

## Why

Modern rootkits hide processes, preload libraries, swap binaries, and bind
shells — defeating naive detection. Kernel telemetry — `/proc/PID/*`, network
tables, file descriptors, syscall state — is where those activities surface
first. X7 is a stdlib-first monitoring tool that collects that telemetry,
optional eBPF/perf backends when the kernel supports them, and raises
MITRE ATT&CK-mapped flags (`T1014`, `T1574.006`, `T1059.004`) when an anomaly
fires. Because it is detection-only and runs against machines you own, it fits
cleanly into authorized incident-response research and blue-team labs, with an
offline synthetic self-test that proves a zero-false-positive baseline without
root.

## Features

- **Four collectors** — Process (`/proc/PID/*`), Network (`/proc/net/{tcp,udp,tcp6,udp6}`), File (`/proc/PID/fd`), Syscall (`/proc/loadavg`, `/proc/PID/syscall`)
- **Optional eBPF/awaken backends** — eBPF exec tracing and fanotify file monitoring where available (CAP_BPF/root + kernel ≥5.1)
- **Anomaly flags** — `known_bad_binary` (T1014), `shadow_read` (T1003.008), `bind_shell` (T1059.004), `hidden_process` (T1014), `rootkit_ld_preload` (T1574.006), `module_change` (T1547.006)
- **Live / collect / analyze / baseline** — session JSONL capture, baseline comparison, and unprivileged analysis
- **Offline self-test** — `kmon test` runs an in-memory synthetic test (<5s, no root)

## Quickstart

```bash
pip install -e .          # or: python -m kmon --help

# Live monitoring (root required for /proc fd access)
kmon live --interval 2

# Capture session data
kmon collect --duration 30s --out data/session.jsonl

# Capture a clean baseline, then analyze a session against it
kmon baseline --out data/baseline.jsonl
kmon analyze data/session.jsonl --baseline data/baseline.jsonl

# Offline self-test (no root, ~5s)
kmon test
```

Privilege notes: `live`/`collect` need root for `/proc/PID/fd`; `test` and
`analyze` run unprivileged; eBPF backends need `CAP_BPF`/root + kernel headers.

## Project structure

- `kmon/` — package (`cli.py`, `collector.py`, `analyzer.py`, `anomaly.py`, `test_harness.py`, `config.py`)
- `config/` — collector configuration
- `pyproject.toml` + `requirements.txt` — packaging and dependencies

## Legal & authorized use

For **educational and authorized security monitoring** on systems you own.
Rootkit simulation belongs in isolated lab environments only; never run it on
production systems. See [ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md),
[SECURITY.md](SECURITY.md), and [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).