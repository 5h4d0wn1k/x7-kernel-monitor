# X7 — Kernel/System Monitor

Production-grade Linux kernel/system monitoring tool. **Detection-only.** For
machines you own. stdlib-only core with optional eBPF/perf backends.

## Overview

| Collector | Data source | eBPF/fallback |
|-----------|-------------|---------------|
| Process   | `/proc/PID/*` scan | optional eBPF exec tracing; fallback: /proc |
| Network   | `/proc/net/{tcp,udp,tcp6,udp6}` | stdlib only |
| File      | `/proc/PID/fd` scan of sensitive paths | optional fanotify; fallback: periodic /proc |
| Syscall   | `/proc/loadavg`, `/proc/PID/syscall` | stdlib only |

## Installation

```bash
pip install -e .
# or
python -m kmon --help
```

## Usage

```bash
# Live monitoring (requires root for /proc fd access)
kmon live --interval 2

# Collect data to file
kmon collect --duration 30s --out data/session.jsonl

# Analyze against baseline
kmon analyze data/session.jsonl --baseline data/baseline.jsonl

# Capture clean baseline
kmon baseline --out data/baseline.jsonl

# Offline self-test (no root needed, ~5s)
kmon test
```

## Collector Matrix

| Collector | Root needed | eBPF available | Fallback |
|-----------|:-----------:|:--------------:|----------|
| Process   | Yes (fd)    | Optional       | /proc scan |
| Network   | No          | N/A            | /proc/net |
| File      | Yes (fd)    | Optional (fanotify) | /proc/PID/fd periodic |
| Syscall   | No          | N/A            | /proc/loadavg |

## Anomaly Flags

| Flag | Technique | Severity |
|------|-----------|----------|
| `known_bad_binary` | T1014 | HIGH/CRITICAL |
| `shadow_read` | T1003.008 | CRITICAL |
| `bind_shell` | T1059.004 | MEDIUM |
| `hidden_process` | T1014 | HIGH |
| `rootkit_ld_preload` | T1574.006 | CRITICAL |
| `module_change` | T1547.006 | HIGH |

## Metrics

- **False-positive rate on baseline**: 0 (verified by `kmon test`)
- **Detection count on test payloads**: 3 flags (known_bad_binary, hidden_process, bind_shell)
- Self-test passes in <5s on standard hardware

## Live Lab Test Plan

1. Start `kmon live` on lab machine (own hardware, own network).
2. Plant synthetic demo rootkit process in sandbox:
   - Process named `rootkit_test` in `/tmp`
   - Hidden process (comm mismatch via LD_PRELOAD trick in lab)
   - Bind shell on port 4444
3. Verify flags fire for each anomaly class.
4. Run stock workload (ssh, web server, database) for 10 minutes.
5. Verify zero false-positive alerts on clean baseline.
6. Record metric: FP rate on baseline; detection count on payloads.

**Note**: The `kmon test` command runs an in-memory synthetic self-test and is
NOT the same as the live lab test. The live test requires root and real /proc.

## Privilege Note

- `kmon live` and `kmon collect` read `/proc/PID/fd` which requires **root**.
- `kmon test` and `kmon analyze` work **unprivileged**.
- eBPF backends require `CAP_BPF` or root + kernel headers.
- fanotify requires kernel >= 5.1 and root.

## IMPORTANT: Read before use

This project is provided for **educational and authorized security testing
purposes only.**

### Authorization
- You MUST have explicit written permission before running on any system.
- This tool should ONLY be used on systems you own.
- Rootkit simulation should only be run in isolated lab environments.

### Legal
- **CFAA**: Unauthorized computer access is a federal crime.
- **Kernel monitoring** may be subject to additional regulations.
- Follow your organization's incident response procedures.

### Acceptable Use
- Monitoring your own systems for rootkit and kernel modifications.
- Authorized incident response with proper authorization.
- Academic research in controlled lab environments.

### Prohibited Use
- Running on systems without authorization.
- Using rootkit simulation on production systems.
- Any activity that violates applicable laws.

### No Warranty
AS IS without warranty. The author is not responsible for misuse.

### Responsible Disclosure
1. Contain the affected system immediately.
2. Report to the system owner privately.
3. Preserve forensic evidence.
4. Follow your organization's IR procedures.

## License

MIT — see [LICENSE](LICENSE).
