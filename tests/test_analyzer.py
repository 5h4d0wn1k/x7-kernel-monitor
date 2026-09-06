"""Unit tests: baseline comparison."""

import unittest

from kmon import analyzer


class TestBaselineComparison(unittest.TestCase):
    def test_no_diff_on_same_data(self):
        procs = [
            {"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"},
        ]
        nets = [
            {"collector": "network", "local": "0.0.0.0:22", "remote": "1.2.3.4:5678"},
        ]
        bl = analyzer.capture_baseline(procs, nets)
        diffs = analyzer.compare_to_baseline(procs + nets, bl)
        self.assertEqual(len(diffs), 0)

    def test_detects_new_process(self):
        procs = [
            {"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"},
            {"collector": "process", "pid": 999, "exe": "/tmp/evil", "comm": "evil"},
        ]
        nets = []
        bl = analyzer.capture_baseline([procs[0]], nets)
        diffs = analyzer.compare_to_baseline(procs + nets, bl)
        self.assertTrue(any(d["type"] == "new_process" and d["pid"] == 999 for d in diffs))

    def test_detects_gone_process(self):
        procs = [
            {"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"},
        ]
        nets = []
        bl = analyzer.capture_baseline(
            [{"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"},
             {"collector": "process", "pid": 500, "exe": "/usr/bin/foo", "comm": "foo"}],
            nets)
        diffs = analyzer.compare_to_baseline(procs + nets, bl)
        self.assertTrue(any(d["type"] == "process_gone" and d["pid"] == 500 for d in diffs))

    def test_detects_new_connection(self):
        procs = [{"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"}]
        nets = [
            {"collector": "network", "local": "0.0.0.0:22", "remote": "1.2.3.4:5678"},
            {"collector": "network", "local": "0.0.0.0:8080", "remote": "5.6.7.8:9999"},
        ]
        bl = analyzer.capture_baseline(procs, [nets[0]])
        diffs = analyzer.compare_to_baseline(procs + nets, bl)
        self.assertTrue(any(d["type"] == "new_connection" for d in diffs))

    def test_empty_baseline_no_crash(self):
        procs = [{"collector": "process", "pid": 1, "exe": "/sbin/init", "comm": "systemd"}]
        diffs = analyzer.compare_to_baseline(procs, None)
        self.assertEqual(len(diffs), 0)


if __name__ == "__main__":
    unittest.main()
