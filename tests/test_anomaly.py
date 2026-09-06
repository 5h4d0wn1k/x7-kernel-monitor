"""Unit tests: anomaly flags match each planted class."""

import unittest

from kmon import anomaly


_CONFIG = {
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


class TestKnownBadBinary(unittest.TestCase):
    def test_flags_known_bad_name(self):
        events = [{
            "collector": "process", "key": "pid:666", "pid": 666,
            "comm": "rootkit_test", "stat_comm": "rootkit_test",
            "exe": "/tmp/rootkit_test", "exe_hash": "", "state": "S",
            "ppid": 1, "threads": 1,
        }]
        flags = anomaly.flag_known_bad_binaries(events, _CONFIG)
        self.assertTrue(any(f["type"] == "known_bad_binary" for f in flags))

    def test_clean_binary_no_flag(self):
        events = [{
            "collector": "process", "key": "pid:1", "pid": 1,
            "comm": "systemd", "stat_comm": "systemd",
            "exe": "/sbin/init", "exe_hash": "abc", "state": "S",
            "ppid": 0, "threads": 1,
        }]
        flags = anomaly.flag_known_bad_binaries(events, _CONFIG)
        self.assertEqual(len(flags), 0)


class TestHiddenProcess(unittest.TestCase):
    def test_comm_mismatch_detected(self):
        events = [{
            "collector": "process", "key": "pid:1337", "pid": 1337,
            "comm": "kworker/rcu/0", "stat_comm": "evil_root",
            "exe": "/usr/bin/evil", "exe_hash": "", "state": "S",
            "ppid": 2, "threads": 1,
        }]
        flags = anomaly.flag_hidden_process(events, _CONFIG)
        self.assertTrue(any(f["type"] == "hidden_process" for f in flags))

    def test_normal_comm_no_flag(self):
        events = [{
            "collector": "process", "key": "pid:1", "pid": 1,
            "comm": "systemd", "stat_comm": "systemd",
            "exe": "/sbin/init", "exe_hash": "abc", "state": "S",
            "ppid": 0, "threads": 1,
        }]
        flags = anomaly.flag_hidden_process(events, _CONFIG)
        self.assertEqual(len(flags), 0)


class TestBindShell(unittest.TestCase):
    def test_suspicious_port_detected(self):
        events = [{
            "collector": "network", "key": "tcp:999", "proto": "tcp",
            "local": "0.0.0.0:4444", "remote": "0.0.0.0:0",
            "state": "LISTEN", "inode": "999",
        }]
        flags = anomaly.flag_bind_shell(events, _CONFIG)
        self.assertTrue(any(f["type"] == "bind_shell" for f in flags))

    def test_normal_port_no_flag(self):
        events = [{
            "collector": "network", "key": "tcp:100", "proto": "tcp",
            "local": "0.0.0.0:22", "remote": "192.0.2.10:45678",
            "state": "LISTEN", "inode": "100",
        }]
        flags = anomaly.flag_bind_shell(events, _CONFIG)
        self.assertEqual(len(flags), 0)


class TestRunAllFlags(unittest.TestCase):
    def test_multi_flag(self):
        events = [
            {"collector": "process", "key": "pid:666", "pid": 666,
             "comm": "rootkit_test", "stat_comm": "rootkit_test",
             "exe": "/tmp/rootkit_test", "exe_hash": "", "state": "S",
             "ppid": 1, "threads": 1},
            {"collector": "process", "key": "pid:1337", "pid": 1337,
             "comm": "kworker/rcu/0", "stat_comm": "evil",
             "exe": "/usr/bin/evil", "exe_hash": "", "state": "S",
             "ppid": 2, "threads": 1},
            {"collector": "network", "key": "tcp:999", "proto": "tcp",
             "local": "0.0.0.0:4444", "remote": "0.0.0.0:0",
             "state": "LISTEN", "inode": "999"},
        ]
        flags = anomaly.run_all_flags(events, _CONFIG)
        types = {f["type"] for f in flags}
        self.assertIn("known_bad_binary", types)
        self.assertIn("hidden_process", types)
        self.assertIn("bind_shell", types)


if __name__ == "__main__":
    unittest.main()
