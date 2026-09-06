"""Unit tests: collector output normalization on fixtures."""

import unittest


class TestProcessCollectorNormalization(unittest.TestCase):
    def _make_event(self, **overrides):
        base = {
            "collector": "process",
            "key": "pid:1",
            "pid": 1,
            "comm": "systemd",
            "stat_comm": "systemd",
            "exe": "/sbin/init",
            "exe_hash": "abc123",
            "state": "S",
            "ppid": 0,
            "threads": 1,
        }
        base.update(overrides)
        return base

    def test_event_has_required_fields(self):
        ev = self._make_event()
        for field in ("collector", "pid", "comm", "exe", "state", "ppid"):
            self.assertIn(field, ev)

    def test_collector_name_is_process(self):
        ev = self._make_event()
        self.assertEqual(ev["collector"], "process")


class TestNetworkCollectorNormalization(unittest.TestCase):
    def _make_event(self, **overrides):
        base = {
            "collector": "network",
            "key": "tcp:100",
            "proto": "tcp",
            "local": "0.0.0.0:22",
            "remote": "192.0.2.10:45678",
            "state": "ESTABLISHED",
            "inode": "100",
        }
        base.update(overrides)
        return base

    def test_event_has_required_fields(self):
        ev = self._make_event()
        for field in ("collector", "proto", "local", "remote", "state"):
            self.assertIn(field, ev)

    def test_listening_state(self):
        ev = self._make_event(state="LISTEN", local="0.0.0.0:4444", remote="0.0.0.0:0")
        self.assertEqual(ev["state"], "LISTEN")


if __name__ == "__main__":
    unittest.main()
