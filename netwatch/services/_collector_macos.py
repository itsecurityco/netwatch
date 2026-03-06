"""macOS traffic collection via nettop + lsof + ps."""

import logging
import os
import re
import subprocess

from ..domain.entities import Connection
from .traffic_collector import parse_endpoint

logger = logging.getLogger(__name__)


def get_process_name(pid: int) -> str:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True, text=True, timeout=1,
        )
        name = result.stdout.strip()
        return os.path.basename(name) if name else ""
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("ps failed for pid %d: %s", pid, exc)
        return ""


def get_local_ip(interface: str) -> str:
    try:
        result = subprocess.run(
            ["ipconfig", "getifaddr", interface],
            capture_output=True, text=True, timeout=2,
        )
        ip = result.stdout.strip()
        if not ip:
            logger.warning("No IP address found for interface %s", interface)
            return "?"
        return ip
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Failed to get local IP for interface %s: %s", interface, exc)
        return "?"


def _parse_nettop() -> list[Connection]:
    """Run nettop and parse output — byte counts (macOS only)."""
    try:
        result = subprocess.run(
            ["nettop", "-m", "tcp", "-m", "udp", "-L", "1", "-n",
             "-J", "bytes_in,bytes_out"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("nettop failed: %s", exc)
        return []

    connections = []
    current_process = ""
    current_pid = 0
    proc_re = re.compile(r"^(.+)\.(\d+)$")

    for line in result.stdout.splitlines():
        if not line or line.startswith(","):
            continue

        parts = line.split(",")
        first = parts[0].strip()

        conn_match = re.match(r"^(tcp[46]|udp[46])\s+(.+)<->(.+)$", first)
        if conn_match:
            proto_raw = conn_match.group(1)
            local_ep = conn_match.group(2)
            remote_ep = conn_match.group(3)

            if remote_ep in ("*:*", "*.*") or local_ep in ("*:*", "*.*"):
                continue

            remote_addr, remote_port = parse_endpoint(remote_ep)
            if remote_addr == "*":
                continue

            proto = proto_raw[:3].upper()
            bytes_in = int(parts[1]) if len(parts) > 1 and parts[1].strip() else 0
            bytes_out = int(parts[2]) if len(parts) > 2 and parts[2].strip() else 0

            connections.append(Connection(
                process=current_process,
                pid=current_pid,
                proto=proto,
                remote_addr=remote_addr,
                remote_port=remote_port,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
            ))
        else:
            m = proc_re.match(first)
            if m:
                current_process = m.group(1)
                current_pid = int(m.group(2))
                current_process = current_process.replace(" H", "")

    return connections


def _parse_lsof() -> list[Connection]:
    """Run lsof -i to discover all connections including idle TCP (macOS)."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("lsof failed: %s", exc)
        return []

    connections = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue

        process = parts[0].replace("\\x20", " ")
        try:
            pid = int(parts[1])
        except ValueError:
            continue

        proto_col = parts[7]
        name_col = parts[8]
        state = parts[9] if len(parts) > 9 else ""

        if proto_col == "TCP" and state != "(ESTABLISHED)":
            continue
        if "->" not in name_col:
            continue

        local_part, remote_part = name_col.split("->", 1)

        if remote_part.startswith("["):
            bracket_end = remote_part.rfind("]")
            if bracket_end == -1:
                continue
            remote_addr = remote_part[1:bracket_end]
            remote_port = remote_part[bracket_end + 2:]
        else:
            last_colon = remote_part.rfind(":")
            if last_colon == -1:
                continue
            remote_addr = remote_part[:last_colon]
            remote_port = remote_part[last_colon + 1:]

        if remote_addr in ("*", "0.0.0.0", "::"):
            continue

        connections.append(Connection(
            process=process,
            pid=pid,
            proto=proto_col[:3].upper(),
            remote_addr=remote_addr,
            remote_port=remote_port,
            bytes_in=0,
            bytes_out=0,
        ))

    return connections


def collect() -> list[Connection]:
    """Combine nettop (byte counts) with lsof (full connection list)."""
    nettop_conns = _parse_nettop()
    lsof_conns = _parse_lsof()

    nettop_index: dict[tuple, Connection] = {}
    addr_port_index: dict[tuple[str, str], Connection] = {}
    for c in nettop_conns:
        key = (c.remote_addr, c.remote_port, c.pid)
        if key in nettop_index:
            nettop_index[key].bytes_in += c.bytes_in
            nettop_index[key].bytes_out += c.bytes_out
        else:
            nettop_index[key] = c
        ap = (c.remote_addr, c.remote_port)
        if ap not in addr_port_index:
            addr_port_index[ap] = c

    seen: set[tuple] = set()
    merged: list[Connection] = []

    for c in nettop_conns:
        key = (c.remote_addr, c.remote_port, c.pid)
        if key not in seen:
            seen.add(key)
            merged.append(c)

    for c in lsof_conns:
        key = (c.remote_addr, c.remote_port, c.pid)
        if key not in seen:
            seen.add(key)
            alt = addr_port_index.get((c.remote_addr, c.remote_port))
            if alt:
                c.bytes_in = alt.bytes_in
                c.bytes_out = alt.bytes_out
            merged.append(c)

    return merged
