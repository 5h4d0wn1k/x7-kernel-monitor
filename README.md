# X7 — Kernel Integrity Monitor

Blue/offense pair: a userspace integrity monitor that detects syscall-table hooks, hidden PIDs, and unauthorized module loads by cross-referencing /proc views, plus an embedded pet rootkit simulation demonstrating the detector in action.

## Overview

This project implements kernel-level integrity checking from userspace:
- **Syscall Table Hook Detection**: Cross-references multiple views to find hooked syscalls
- **Hidden PID Detection**: Compares /proc, /proc/net/tcp, and process accounting to find concealed PIDs
- **Module Load Verification**: Validates loaded kernel modules against a trusted registry snapshot
- **Heartbeat Checker**: Periodic liveness monitoring with anomaly alerting
- **Alert Daemon**: Streaming alert output for integration with SIEM/SOC tools
- **eBPF Integration Points**: Clearly labeled stubs for real kernel tracing (works fully offline without them)

## Features

- **Multi-View PID Cross-Reference**: Detects PID hiding by comparing /proc, /proc/net, and ps output
- **Syscall Table Integrity**: Checks for unauthorized syscall table modifications
- **Module Registry Verification**: Compares loaded modules against known-good registry snapshot
- **Pet Rootkit Simulation**: Embedded mock process table with hidden PID for demonstration
- **Heartbeat Monitoring**: Continuous liveness check with configurable intervals
- **Streaming Alerts**: SIEM-compatible JSON alert output
- **eBPF Stubs**: Documented integration points for real kernel tracing (gracefully offline)

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 kernel_monitor.py
```

## Usage

```bash
# Run full demo with pet rootkit simulation
python3 kernel_monitor.py

# Programmatic usage
from kernel_monitor import KernelIntegrityMonitor, PetRootkitSim

monitor = KernelIntegrityMonitor()
results = monitor.full_scan()
alerts = monitor.get_alerts()
```

## Example Output

```
============================================================
  X7 — Kernel Integrity Monitor
============================================================

[*] Initializing kernel integrity monitor...
[*] Pet rootkit simulation loaded (hidden PID: 1337)

--- PID Cross-Reference Scan ---
  [!] HIDDEN PID DETECTED: PID 1337 (kworker/rcu/0 — hidden from /proc listing)
      Evidence: present in /proc/net/tcp but missing from /proc/
      Severity: HIGH | Technique: T1014 (Rootkit)

--- Syscall Table Integrity ---
  [OK] syscall read (0) — unmodified at 0xffffffff81234567
  [OK] syscall write (1) — unmodified at 0xffffffff81234570
  [WARN] syscall execve (59) — hook detected at 0xffff888012340000
      Severity: HIGH | Technique: T1014 (Rootkit)

--- Module Registry Check ---
  [OK] 142 modules verified against registry snapshot
  [!] UNAUTHORIZED MODULE: test_rootkit.ko (sha256 mismatch)
      Severity: CRITICAL | Technique: T1547.006 (Kernel Modules)

--- Heartbeat Monitor ---
  [*] Sending heartbeat every 5s (3 checks passed)

=== Summary ===
  Checks run:     3
  Alerts:         3 (2 HIGH, 1 CRITICAL)
  Hidden PIDs:    1
  Hooked calls:   1
  Rogue modules:  1

=== Alert Stream (SIEM JSON) ===
{"timestamp": "2026-09-04T12:00:00Z", "severity": "HIGH", "type": "hidden_pid", "detail": "PID 1337 hidden from /proc", "technique": "T1014"}
{"timestamp": "2026-09-04T12:00:00Z", "severity": "HIGH", "type": "syscall_hook", "detail": "execve hooked at 0xffff888012340000", "technique": "T1014"}
{"timestamp": "2026-09-04T12:00:00Z", "severity": "CRITICAL", "type": "rogue_module", "detail": "test_rootkit.ko sha256 mismatch", "technique": "T1547.006"}
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before running integrity checks
- Monitoring kernel state may require root/administrator privileges
- This tool should ONLY be used on systems you own or have written authorization to audit
- Rootkit simulation should only be run in isolated lab environments

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **CFAA Section 1030(a)(1)**: Transmitting information designed to damage a protected computer
- **State Laws**: Many states have additional computer crime and unauthorized access statutes
- **Kernel Access Laws**: Running kernel-level monitoring may be subject to additional regulations

### Acceptable Use
- Monitoring your own systems for rootkits and kernel modifications
- Authorized incident response and forensics investigations with proper authorization
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Running integrity checks on systems without authorization
- Using rootkit simulation on production systems
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you detect real rootkits or kernel compromises, follow responsible disclosure practices:
1. Contain the affected system immediately
2. Report to the system owner/security team privately
3. Preserve forensic evidence before remediation
4. Follow your organization's incident response procedures
5. Do not attempt to remove rootkits without proper expertise

## License

MIT
