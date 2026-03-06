"""Persistent storage — SQLite backend with JSON auto-migration."""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..config import DATA_DIR

logger = logging.getLogger(__name__)

DB_FILE = DATA_DIR / "netwatch.db"
LEGACY_HISTORY_FILE = DATA_DIR / "known_connections.json"
LEGACY_WHOIS_FILE = DATA_DIR / "whois_cache.json"


def _migrate_legacy_json(conn: sqlite3.Connection):
    """Auto-migrate legacy JSON files to SQLite on first run."""
    if LEGACY_HISTORY_FILE.exists():
        try:
            data = json.loads(LEGACY_HISTORY_FILE.read_text())
            for key, entry in data.items():
                parts = key.split("|")
                if len(parts) == 4:
                    process, remote_host, remote_port, protocol = parts
                    conn.execute(
                        """INSERT OR IGNORE INTO connections
                           (process, remote_host, remote_port, protocol,
                            first_seen, last_seen, times_seen)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (process, remote_host, remote_port, protocol,
                         entry.get("first_seen", ""),
                         entry.get("last_seen", ""),
                         entry.get("times_seen", 1)),
                    )
            conn.commit()
            LEGACY_HISTORY_FILE.rename(LEGACY_HISTORY_FILE.with_suffix(".json.bak"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to migrate legacy history file %s", LEGACY_HISTORY_FILE, exc_info=True)

    if LEGACY_WHOIS_FILE.exists():
        try:
            data = json.loads(LEGACY_WHOIS_FILE.read_text())
            now = datetime.now(timezone.utc).isoformat()
            for ip, org in data.items():
                conn.execute(
                    """INSERT OR IGNORE INTO whois
                       (ip_address, org_name, cached_at)
                       VALUES (?, ?, ?)""",
                    (ip, org, now),
                )
            conn.commit()
            LEGACY_WHOIS_FILE.rename(LEGACY_WHOIS_FILE.with_suffix(".json.bak"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to migrate legacy whois file %s", LEGACY_WHOIS_FILE, exc_info=True)


class Storage:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._conn = sqlite3.connect(str(DB_FILE))
        if DB_FILE.exists():
            os.chmod(DB_FILE, 0o600)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        _migrate_legacy_json(self._conn)

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY,
                process TEXT NOT NULL,
                remote_host TEXT NOT NULL,
                remote_port TEXT NOT NULL,
                protocol TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1,
                UNIQUE(process, remote_host, remote_port, protocol)
            );

            CREATE TABLE IF NOT EXISTS whois (
                ip_address TEXT PRIMARY KEY,
                org_name TEXT,
                cached_at TEXT
            );

            CREATE TABLE IF NOT EXISTS excluded (
                process_name TEXT PRIMARY KEY,
                added_at TEXT NOT NULL
            );
        """)
        self._conn.commit()

    # --- Connection history ---

    def load_history(self) -> dict[str, dict]:
        """Load all connection history as a dict keyed by fingerprint."""
        cursor = self._conn.execute(
            "SELECT process, remote_host, remote_port, protocol, "
            "first_seen, last_seen, times_seen FROM connections"
        )
        data = {}
        for row in cursor:
            key = f"{row[0]}|{row[1]}|{row[2]}|{row[3]}"
            data[key] = {
                "first_seen": row[4],
                "last_seen": row[5],
                "times_seen": row[6],
            }
        return data

    def save_history(self, data: dict[str, dict]):
        """Upsert connection history entries."""
        for key, entry in data.items():
            parts = key.split("|")
            if len(parts) != 4:
                continue
            process, remote_host, remote_port, protocol = parts
            self._conn.execute(
                """INSERT INTO connections
                   (process, remote_host, remote_port, protocol,
                    first_seen, last_seen, times_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(process, remote_host, remote_port, protocol)
                   DO UPDATE SET
                       last_seen = excluded.last_seen,
                       times_seen = excluded.times_seen""",
                (process, remote_host, remote_port, protocol,
                 entry.get("first_seen", ""),
                 entry.get("last_seen", ""),
                 entry.get("times_seen", 1)),
            )
        self._conn.commit()

    # --- Whois cache ---

    def load_whois(self) -> dict[str, str]:
        """Load whois cache as {ip: org_name}."""
        cursor = self._conn.execute(
            "SELECT ip_address, org_name FROM whois"
        )
        return {row[0]: row[1] for row in cursor}

    def save_whois(self, data: dict[str, str]):
        """Upsert whois cache entries."""
        now = datetime.now(timezone.utc).isoformat()
        for ip, org in data.items():
            self._conn.execute(
                """INSERT INTO whois (ip_address, org_name, cached_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(ip_address)
                   DO UPDATE SET org_name = excluded.org_name,
                                 cached_at = excluded.cached_at""",
                (ip, org, now),
            )
        self._conn.commit()

    # --- Excluded processes ---

    def load_excluded(self) -> set[str]:
        cursor = self._conn.execute(
            "SELECT process_name FROM excluded"
        )
        return {row[0] for row in cursor}

    def add_excluded_process(self, process_name: str):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT OR IGNORE INTO excluded (process_name, added_at)
               VALUES (?, ?)""",
            (process_name, now),
        )
        self._conn.commit()

    def remove_excluded_process(self, process_name: str):
        self._conn.execute(
            "DELETE FROM excluded WHERE process_name = ?",
            (process_name,),
        )
        self._conn.commit()

    def clear_excluded(self):
        self._conn.execute("DELETE FROM excluded")
        self._conn.commit()

    def close(self):
        self._conn.close()
