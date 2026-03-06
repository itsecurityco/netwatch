"""Windows traffic collection via psutil."""

import logging
import socket
import subprocess
import threading

import psutil

from ..domain.entities import Connection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-PID network byte deltas via psutil io_counters.other_bytes
# ---------------------------------------------------------------------------

_pid_io_prev: dict[int, int] = {}
_pid_io_lock = threading.Lock()


def _sample_pid_net_bytes(pids: set[int]) -> dict[int, int]:
    """Return {pid: delta_bytes} for every supplied PID since last poll."""
    deltas: dict[int, int] = {}
    with _pid_io_lock:
        for pid in pids:
            try:
                ioc = psutil.Process(pid).io_counters()
                # other_bytes == network I/O on Windows
                net = getattr(ioc, "other_bytes", 0)
                prev = _pid_io_prev.get(pid, net)
                deltas[pid] = max(0, net - prev)
                _pid_io_prev[pid] = net
            except Exception:
                deltas[pid] = 0
        # Prune entries for PIDs no longer active to prevent unbounded growth
        stale = _pid_io_prev.keys() - pids
        for pid in stale:
            del _pid_io_prev[pid]
    return deltas


# ---------------------------------------------------------------------------
# Process name resolution
# ---------------------------------------------------------------------------

def _strip_exe(name: str) -> str:
    return name[:-4] if name.lower().endswith(".exe") else name


def get_process_name(pid: int) -> str:
    # Try psutil first (fast path)
    try:
        return _strip_exe(psutil.Process(pid).name())
    except Exception:
        pass
    # Fallback: tasklist /FO CSV
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=2,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                return _strip_exe(parts[0])
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


# ---------------------------------------------------------------------------
# Connection collection
# ---------------------------------------------------------------------------

def collect() -> list[Connection]:
    """Collect connections on Windows using psutil."""
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("psutil.net_connections failed: %s", exc)
        return []

    valid = []
    for c in raw:
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
        per_conn = pid_deltas.get(c.pid, 0) // count if count else 0
        connections.append(Connection(
            process="",
            pid=c.pid,
            proto=proto,
            remote_addr=c.raddr.ip,
            remote_port=str(c.raddr.port),
            # psutil gives per-process totals, not per-connection direction;
            # 40/60 is a rough heuristic since most traffic is download-heavy
            bytes_in=int(per_conn * 0.4),
            bytes_out=int(per_conn * 0.6),
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
