"""Structured logging: file + stdout."""

import json
import logging
import os
import sys
import time


class _JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "module": record.module,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def setup_logging(log_path=None, verbose=False):
    if log_path is None:
        log_path = "logs/kmon.log"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    root = logging.getLogger("kmon")
    root.setLevel(logging.DEBUG)

    fmt = _JSONFormatter()

    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    return root
