"""CLI interface: kmon live | collect | analyze | baseline | test"""

import argparse
import json
import os
import signal
import sys
import time

from kmon import __version__
from kmon.collector import ALL_COLLECTORS, EBPF_AVAILABLE
from kmon.anomaly import run_all_flags
from kmon.analyzer import capture_baseline, compare_to_baseline, write_jsonl, read_jsonl
from kmon.config import load_config
from kmon.logging_setup import setup_logging
from kmon.test_harness import run_self_test


def cmd_live(args, config):
    logger = setup_logging(config["output"]["log_path"], verbose=args.verbose)
    logger.info("kmon live started — interval=%ds", config["collection"]["interval"])
    collectors = [cls(config) for cls in ALL_COLLECTORS]
    alerts_path = config["output"]["jsonl_path"]
    interval = config["collection"]["interval"]

    def handle_sigint(sig, frame):
        logger.info("kmon live stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    while True:
        all_events = []
        for c in collectors:
            events = c.collect()
            all_events.extend(events)

        flags = run_all_flags(all_events, config)
        for flag in flags:
            flag["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            print(json.dumps(flag))
            write_jsonl([flag], alerts_path)

        if flags:
            logger.info("cycle: %d events, %d alerts", len(all_events), len(flags))
        else:
            logger.debug("cycle: %d events, 0 alerts", len(all_events))

        time.sleep(interval)


def cmd_collect(args, config):
    logger = setup_logging(config["output"]["log_path"], verbose=args.verbose)
    duration = _parse_duration(args.duration)
    collectors = [cls(config) for cls in ALL_COLLECTORS]
    out = args.out or f"data/collect_{int(time.time())}.jsonl"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    logger.info("collecting for %ds -> %s", duration, out)
    start = time.time()
    count = 0

    while time.time() - start < duration:
        all_events = []
        for c in collectors:
            all_events.extend(c.collect())
        write_jsonl(all_events, out)
        count += len(all_events)
        time.sleep(config["collection"]["interval"])

    logger.info("collected %d events -> %s", count, out)
    print(f"Collected {count} events -> {out}")


def cmd_analyze(args, config):
    logger = setup_logging(config["output"]["log_path"], verbose=args.verbose)
    events = read_jsonl(args.jsonl)
    baseline = read_jsonl(args.baseline) if args.baseline else None

    baseline_data = None
    if baseline:
        baseline_data = baseline[0] if baseline else None

    diffs = compare_to_baseline(events, baseline_data)
    flags = run_all_flags(events, config)

    results = {"diffs": diffs, "flags": flags}
    print(json.dumps(results, indent=2))
    logger.info("analyze: %d diffs, %d flags", len(diffs), len(flags))


def cmd_baseline(args, config):
    logger = setup_logging(config["output"]["log_path"], verbose=args.verbose)
    collectors = [cls(config) for cls in ALL_COLLECTORS]
    all_events = []
    for c in collectors:
        all_events.extend(c.collect())

    proc_events = [e for e in all_events if e.get("collector") == "process"]
    net_events = [e for e in all_events if e.get("collector") == "network"]
    bl = capture_baseline(proc_events, net_events)

    out = args.out or "data/baseline.jsonl"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    write_jsonl([bl], out)
    logger.info("baseline captured -> %s (%d pids)", out, bl["pid_count"])
    print(f"Baseline captured -> {out} ({bl['pid_count']} pids)")


def cmd_test(args, config):
    return run_self_test()


def _parse_duration(s):
    s = s.strip().lower()
    if s.endswith("s"):
        return int(s[:-1])
    elif s.endswith("m"):
        return int(s[:-1]) * 60
    elif s.endswith("h"):
        return int(s[:-1]) * 3600
    return int(s)


def main():
    parser = argparse.ArgumentParser(
        prog="kmon",
        description="X7 — Kernel/System Monitor (detection-only, own-machines only)",
    )
    parser.add_argument("--version", action="version", version=f"kmon {__version__}")
    parser.add_argument("--config", default="config/kmon.yaml", help="config YAML path")
    parser.add_argument("--verbose", "-v", action="store_true")

    sub = parser.add_subparsers(dest="command")

    p_live = sub.add_parser("live", help="Live monitoring loop")
    p_live.add_argument("--interval", type=int, help="Override interval (seconds)")

    p_collect = sub.add_parser("collect", help="Collect data for a duration")
    p_collect.add_argument("--duration", required=True, help="Duration (e.g. 30s, 5m)")
    p_collect.add_argument("--out", help="Output JSONL path")

    p_analyze = sub.add_parser("analyze", help="Analyze collected JSONL")
    p_analyze.add_argument("jsonl", help="JSONL file to analyze")
    p_analyze.add_argument("--baseline", help="Baseline JSONL for comparison")

    p_baseline = sub.add_parser("baseline", help="Capture clean baseline")
    p_baseline.add_argument("--out", help="Output path")

    p_test = sub.add_parser("test", help="Offline self-test (synthetic, no root needed)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    config = load_config(args.config)
    if hasattr(args, "interval") and args.interval:
        config["collection"]["interval"] = args.interval

    cmd_map = {
        "live": cmd_live,
        "collect": cmd_collect,
        "analyze": cmd_analyze,
        "baseline": cmd_baseline,
        "test": cmd_test,
    }
    return cmd_map[args.command](args, config)
