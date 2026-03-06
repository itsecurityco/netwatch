"""Linux traffic collection via psutil + /proc."""

import logging
import socket
import threading
from pathlib import Path

import psutil

from ..domain.entities import Connection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-PID network byte deltas via /proc/{pid}/net/dev
# ---------------------------------------------------------------------------

_pid_io_prev: dict[int, int] = {}
_pid_io_lock = threading.Lock()


def _read_proc_net_bytes(pid: int) -> int:
    """Read total rx+tx bytes from /proc/{pid}/net/dev (all interfaces)."""
    try:
        lines = Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
    except (OSError, IndexError):
        return 0
    total = 0
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        iface = parts[0].rstrip(":")
        if iface == "lo":
            continue
        rx = int(parts[1])
        tx = int(parts[9])
        total += rx + tx
    return total


def _sample_pid_net_bytes(pids: set[int]) -> dict[int, tuple[int, int]]:
    """Return {pid: (delta_rx, delta_tx)} for every supplied PID since last poll."""
    deltas: dict[int, tuple[int, int]] = {}
    with _pid_io_lock:
        for pid in pids:
            try:
                lines = Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
            except (OSError, IndexError):
                deltas[pid] = (0, 0)
                continue
            rx_total = tx_total = 0
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                iface = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                rx_total += int(parts[1])
                tx_total += int(parts[9])
            current = rx_total + tx_total
            prev = _pid_io_prev.get(pid, current)
            delta = max(0, current - prev)
            _pid_io_prev[pid] = current
            # Split delta proportionally based on current rx/tx ratio
            if rx_total + tx_total > 0:
                rx_frac = rx_total / (rx_total + tx_total)
            else:
                rx_frac = 0.5
            deltas[pid] = (int(delta * rx_frac), int(delta * (1 - rx_frac)))
        # Prune entries for PIDs no longer active to prevent unbounded growth
        stale = _pid_io_prev.keys() - pids
        for pid in stale:
            del _pid_io_prev[pid]
    return deltas


# ---------------------------------------------------------------------------
# Process name resolution
# ---------------------------------------------------------------------------

def get_process_name(pid: int) -> str:
    # Fast path: read directly from /proc
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        pass
    # Fallback: psutil
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Connection collection
# ---------------------------------------------------------------------------

def _collect_global() -> list:
    """Try psutil.net_connections(); returns only entries with a pid."""
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("psutil.net_connections failed: %s", exc)
        return []
    return [c for c in raw if c.pid is not None]


def _collect_per_process() -> list:
    """Fallback: iterate processes and call net_connections() on each.

    Works without root for the current user's own processes.
    """
    results = []
    for proc in psutil.process_iter(["pid"]):
        try:
            conns = proc.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
        for c in conns:
            results.append(c)
    return results


def collect() -> list[Connection]:
    """Collect connections on Linux using psutil + /proc."""
    raw_with_pid = _collect_global()
    if not raw_with_pid:
        raw_with_pid = _collect_per_process()

    valid = []
    for c in raw_with_pid:
        if c.pid is None or not c.raddr:
            continue
        if c.raddr.ip in ("0.0.0.0", "::", ""):
            continue
        if c.type == socket.SOCK_STREAM and c.status != "ESTABLISHED":
            continue
        valid.append(c)

    active_pids = {c.pid for c in valid}
    pid_deltas = _sample_pid_net_bytes(active_pids)

    pid_conn_count: dict[int, int] = {}
    for c in valid:
        pid_conn_count[c.pid] = pid_conn_count.get(c.pid, 0) + 1

    connections: list[Connection] = []
    for c in valid:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        count = pid_conn_count.get(c.pid, 1)
        rx, tx = pid_deltas.get(c.pid, (0, 0))
        per_rx = rx // count if count else 0
        per_tx = tx // count if count else 0
        connections.append(Connection(
            process="",
            pid=c.pid,
            proto=proto,
            remote_addr=c.raddr.ip,
            remote_port=str(c.raddr.port),
            bytes_in=per_rx,
            bytes_out=per_tx,
        ))

    return connections


# ---------------------------------------------------------------------------
# Local IP detection
# ---------------------------------------------------------------------------

def get_local_ip(_interface: str) -> str:
    """Probe outbound route to determine local IP (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError as exc:
        logger.warning("Could not determine local IP: %s", exc)
        return "?"
