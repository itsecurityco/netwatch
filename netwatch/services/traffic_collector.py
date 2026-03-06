"""Cross-platform traffic collection (macOS + Windows + Linux).

Platform-specific implementations live in _collector_macos, _collector_windows,
and _collector_linux. This module re-exports the public API and shared utilities.
"""

import logging
import sys

from ..domain.entities import Connection

logger = logging.getLogger(__name__)

_PLATFORM = sys.platform  # 'darwin', 'win32', 'linux'


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def parse_endpoint(endpoint: str) -> tuple[str, str]:
    """Parse an endpoint string into (addr, port).

    IPv4: 10.0.0.1:443
    IPv6: 2803:c600:...:cb5.443 (port after last dot)
    """
    if endpoint in ("*:*", "*.*"):
        return ("*", "*")

    last_dot = endpoint.rfind(".")
    if last_dot != -1:
        port_part = endpoint[last_dot + 1:]
        if port_part.isdigit() or port_part == "*":
            addr = endpoint[:last_dot]
            if ":" in addr:
                return (addr, port_part)

    last_colon = endpoint.rfind(":")
    if last_colon != -1:
        return (endpoint[:last_colon], endpoint[last_colon + 1:])

    return (endpoint, "?")


# ---------------------------------------------------------------------------
# Platform dispatch
# ---------------------------------------------------------------------------

if _PLATFORM == "win32":
    from ._collector_windows import collect as _collect
    from ._collector_windows import get_local_ip as _get_local_ip
    from ._collector_windows import get_process_name as _get_process_name
elif _PLATFORM == "linux":
    from ._collector_linux import collect as _collect
    from ._collector_linux import get_local_ip as _get_local_ip
    from ._collector_linux import get_process_name as _get_process_name
else:
    from ._collector_macos import collect as _collect
    from ._collector_macos import get_local_ip as _get_local_ip
    from ._collector_macos import get_process_name as _get_process_name


class ProcessNameCache:
    def __init__(self):
        self._cache: dict[int, str] = {}

    def resolve(self, pid: int, fallback: str) -> str:
        if pid in self._cache:
            return self._cache[pid]
        name = _get_process_name(pid) or fallback
        self._cache[pid] = name
        return name


def parse_nettop_output() -> list[Connection]:
    """Collect active connections — cross-platform entry point."""
    return _collect()


def get_local_ip(interface: str) -> str:
    """Return the primary outbound local IP address."""
    return _get_local_ip(interface)
