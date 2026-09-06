"""Unit tests: config validation."""

import os
import tempfile
import unittest

from kmon.config import load_config


class TestConfigDefaults(unittest.TestCase):
    def test_defaults_load_without_file(self):
        cfg = load_config(None)
        self.assertIn("collection", cfg)
        self.assertIn("sensitive_paths", cfg)
        self.assertIn("alert_thresholds", cfg)
        self.assertEqual(cfg["collection"]["interval"], 2)

    def test_defaults_sensitive_paths(self):
        cfg = load_config(None)
        self.assertIn("/etc/shadow", cfg["sensitive_paths"])

    def test_defaults_thresholds(self):
        cfg = load_config(None)
        self.assertIsInstance(cfg["alert_thresholds"]["syscall_rate_spike"], float)


class TestConfigFromYAML(unittest.TestCase):
    def test_user_override_merge(self):
        content = "collection:\n  interval: 5\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(cfg["collection"]["interval"], 5)
            self.assertIn("sensitive_paths", cfg)
        finally:
            os.unlink(path)

    def test_missing_file_uses_defaults(self):
        cfg = load_config("/nonexistent/path.yaml")
        self.assertEqual(cfg["collection"]["interval"], 2)


if __name__ == "__main__":
    unittest.main()
