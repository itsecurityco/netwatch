"""Connection aggregation, sorting, and row tracking."""

import time

from ..domain.entities import Connection, TrafficRow
from .resolver import DNSCache, WhoisResolver, format_display_name
from .traffic_collector import ProcessNameCache
from .history import ConnectionHistory


def _is_excluded(pname: str, excluded: set[str]) -> bool:
    """Check if process matches any exclusion (exact or base-name match)."""
    if pname in excluded:
        return True
    base = pname.split(" (")[0]
    return base in excluded


def aggregate_connections(
    connections: list[Connection],
    dns: DNSCache,
    whois: WhoisResolver,
    proc_cache: ProcessNameCache,
    show_loopback: bool,
    excluded_processes: set[str] | None = None,
) -> list[TrafficRow]:
    """Aggregate connections into TrafficRow objects."""
    groups: dict[tuple, TrafficRow] = {}

    for c in connections:
        if not show_loopback:
            if c.remote_addr.startswith("127.") or c.remote_addr == "::1":
                continue

        dns.resolve(c.remote_addr)
        display_name = format_display_name(c.remote_addr, dns, whois)
        pname = proc_cache.resolve(c.pid, c.process)

        if excluded_processes and _is_excluded(pname, excluded_processes):
            continue

        key = (pname, c.remote_addr, c.remote_port, c.proto)
        if key not in groups:
            groups[key] = TrafficRow(
                process=pname, proto=c.proto,
                remote_host=display_name, remote_port=c.remote_port,
                raw_remote_addr=c.remote_addr,
            )
        row = groups[key]
        row.conns += 1
        row.bytes_in += c.bytes_in
        row.bytes_out += c.bytes_out
        # Update display name in case it resolved since row creation
        row.remote_host = display_name

    return list(groups.values())


def enrich_with_history(rows: list[TrafficRow], history: ConnectionHistory) -> None:
    """Stamp each row with its NEW / known status from connection history."""
    for row in rows:
        fp = ConnectionHistory.fingerprint(
            row.process, row.remote_host, row.remote_port, row.proto
        )
        history.update(fp)
        row.status = history.get_status(fp)


def human_bytes(n: int) -> str:
    """Format byte count in human-readable form."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.1f} GB"


def sort_rows(rows: list[TrafficRow], sort_key: str, reverse: bool) -> list[TrafficRow]:
    if sort_key == "process":
        return sorted(rows, key=lambda r: r.process.lower(), reverse=reverse)
    elif sort_key == "conns":
        return sorted(rows, key=lambda r: r.conns, reverse=reverse)
    elif sort_key == "bytes_in":
        return sorted(rows, key=lambda r: r.bytes_in, reverse=reverse)
    elif sort_key == "bytes_out":
        return sorted(rows, key=lambda r: r.bytes_out, reverse=reverse)
    else:  # total
        return sorted(rows, key=lambda r: r.total, reverse=reverse)


class RowTracker:
    """Keeps rows alive with a TTL so idle connections don't vanish instantly."""

    def __init__(self, stale_ttl: float = 86400.0):
        self._rows: dict[tuple, TrafficRow] = {}
        self._last_seen: dict[tuple, float] = {}
        self._stale_ttl = stale_ttl

    def update(self, new_rows: list[TrafficRow]) -> list[TrafficRow]:
        """Merge fresh rows in, mark missing ones stale, expire old ones."""
        now = time.time()
        fresh_keys = set()

        for row in new_rows:
            key = row.row_key
            fresh_keys.add(key)
            row.stale = False
            self._rows[key] = row
            self._last_seen[key] = now

        # Mark missing rows as stale, remove expired
        expired = []
        for key in list(self._rows):
            if key not in fresh_keys:
                age = now - self._last_seen.get(key, 0)
                if age > self._stale_ttl:
                    expired.append(key)
                else:
                    self._rows[key].stale = True

        for key in expired:
            del self._rows[key]
            self._last_seen.pop(key, None)

        return list(self._rows.values())

    def clear(self):
        """Reset tracker (e.g. on loopback toggle)."""
        self._rows.clear()
        self._last_seen.clear()
