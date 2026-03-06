"""DNS and whois resolution service."""

import ipaddress
import logging
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class WhoisResolver:
    """Handles whois lookups and caching."""

    def __init__(self, data: dict[str, str] | None = None):
        self._cache: dict[str, str] = data or {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def get(self, ip: str) -> str:
        return self._cache.get(ip, "")

    def get_cache(self) -> dict[str, str]:
        return dict(self._cache)

    def schedule(self, ip: str, pool: ThreadPoolExecutor):
        with self._lock:
            if ip not in self._cache and ip not in self._pending:
                self._pending.add(ip)
                pool.submit(self._do_lookup, ip)

    def _do_lookup(self, ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self._cache[ip] = ""
            self._pending.discard(ip)
            return
        try:
            result = subprocess.run(
                ["whois", "--", ip],
                capture_output=True, text=True, timeout=5
            )
            org = self._parse_org(result.stdout)
            with self._lock:
                self._cache[ip] = org
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Whois lookup failed for %s: %s", ip, exc)
            with self._lock:
                self._cache[ip] = ""
        finally:
            with self._lock:
                self._pending.discard(ip)

    @staticmethod
    def _parse_org(text: str) -> str:
        for line in text.splitlines():
            line = line.strip()
            for prefix in ("OrgName:", "org-name:", "Organisation:", "organization:"):
                if line.lower().startswith(prefix.lower()):
                    org = line[len(prefix):].strip()
                    if org and org.lower() not in ("", "n/a"):
                        return org
        return ""


class DNSCache:
    """Asynchronous DNS resolution with whois fallback."""

    def __init__(self, whois: WhoisResolver, max_workers=4):
        self._cache: dict[str, str] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._whois = whois

    def resolve(self, ip: str) -> None:
        if ip in self._cache:
            return
        with self._lock:
            if ip not in self._pending:
                self._pending.add(ip)
                self._pool.submit(self._do_resolve, ip)

    def get(self, ip: str) -> str:
        return self._cache.get(ip, "")

    def _do_resolve(self, ip: str):
        try:
            host = socket.gethostbyaddr(ip)[0]
            with self._lock:
                self._cache[ip] = host
        except (socket.herror, socket.gaierror, OSError):
            with self._lock:
                self._cache[ip] = ip
            self._whois.schedule(ip, self._pool)
        finally:
            with self._lock:
                self._pending.discard(ip)

    def shutdown(self):
        self._pool.shutdown(wait=False)


def format_display_name(ip: str, dns: DNSCache, whois: WhoisResolver) -> str:
    """Format an IP for display: hostname > ip (org) > raw ip."""
    hostname = dns.get(ip)
    if hostname and hostname != ip:
        if len(hostname) > 40:
            hostname = hostname[:37] + "..."
        return hostname
    org = whois.get(ip)
    if org:
        if len(org) > 30:
            org = org[:27] + "..."
        display_ip = ip
        if len(display_ip) > 24:
            display_ip = display_ip[:21] + "..."
        return f"{display_ip} ({org})"
    return ip
