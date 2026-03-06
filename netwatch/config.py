"""Configuration constants and column layout."""

import logging
from pathlib import Path

REFRESH_INTERVAL = 2  # seconds
INPUT_TIMEOUT_MS = 200
SAVE_INTERVAL = 30  # seconds between periodic saves

DATA_DIR = Path.home() / ".netwatch"
CONFIG_FILE = DATA_DIR / "config.yaml"
LOG_FILE = DATA_DIR / "netwatch.log"

FILTER_STATES = ["all", "new", "known"]
FILTER_LABELS = {"all": "All", "new": "New Only", "known": "Known Only"}

SORT_KEYS = ["total", "process", "conns", "bytes_in", "bytes_out"]
SORT_LABELS = {"total": "TOTAL", "process": "PROCESS", "conns": "CONNS",
               "bytes_in": "IN", "bytes_out": "OUT"}

# Column positions for table layout
COL_PROC = 0
COL_STATUS = 21
COL_PROTO = 31
COL_DIR = 38
COL_HOST = 44
COL_PORT = 80
COL_CONNS = 86
COL_IN = 92
COL_OUT = 103
COL_TOTAL = 114
TABLE_WIDTH = COL_TOTAL + 11  # total rendered width


def load_config() -> dict:
    """Load config.yaml with PyYAML if available, otherwise a simple fallback parser."""
    if not CONFIG_FILE.exists():
        return {}
    text = CONFIG_FILE.read_text()
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        logging.getLogger(__name__).warning("PyYAML not installed, using fallback parser")
    # Fallback: parse simple YAML lists (key:\n  - "value")
    result = {}
    current_key = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith(":") and not stripped.startswith("-"):
            current_key = stripped[:-1].strip()
            result[current_key] = []
        elif stripped.startswith("- ") and current_key is not None:
            val = stripped[2:].strip().strip('"').strip("'")
            result[current_key].append(val)
    return result
