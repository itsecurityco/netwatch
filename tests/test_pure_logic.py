"""Tests for pure logic across the netwatch codebase."""

import curses
import os
import sys

import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netwatch.domain.entities import TrafficRow
from netwatch.services.traffic_collector import parse_endpoint
from netwatch.services.resolver import WhoisResolver, format_display_name
from netwatch.services.aggregator import _is_excluded, human_bytes, sort_rows
from netwatch.services.history import ConnectionHistory
from netwatch.ui.input_handler import handle_key, KeyAction
from netwatch.ui.state import ApplicationState
from netwatch.config import load_config


# ---------------------------------------------------------------------------
# domain/entities.py — TrafficRow
# ---------------------------------------------------------------------------

class TestTrafficRowTotal:
    def test_total_sums_bytes(self):
        row = TrafficRow(process="p", proto="TCP", remote_host="h", remote_port="443",
                         bytes_in=100, bytes_out=200)
        assert row.total == 300


class TestTrafficRowDirection:
    def test_direction_out(self):
        row = TrafficRow(process="p", proto="TCP", remote_host="h", remote_port="443",
                         bytes_in=10, bytes_out=100)
        assert row.direction == "OUT"

    def test_direction_in(self):
        row = TrafficRow(process="p", proto="TCP", remote_host="h", remote_port="443",
                         bytes_in=100, bytes_out=10)
        assert row.direction == "IN"

    def test_direction_both(self):
        row = TrafficRow(process="p", proto="TCP", remote_host="h", remote_port="443",
                         bytes_in=100, bytes_out=100)
        assert row.direction == "BOTH"


class TestTrafficRowKey:
    def test_row_key_uses_raw_addr(self):
        row = TrafficRow(process="Safari", proto="TCP", remote_host="example.com",
                         remote_port="443", raw_remote_addr="93.184.216.34")
        assert row.row_key == ("Safari", "93.184.216.34", "443", "TCP")

    def test_row_key_fallback_to_remote_host(self):
        row = TrafficRow(process="Safari", proto="TCP", remote_host="example.com",
                         remote_port="443", raw_remote_addr="")
        assert row.row_key == ("Safari", "example.com", "443", "TCP")


# ---------------------------------------------------------------------------
# services/traffic_collector.py — parse_endpoint
# ---------------------------------------------------------------------------

class TestParseEndpoint:
    def test_ipv4(self):
        assert parse_endpoint("10.0.0.1:443") == ("10.0.0.1", "443")

    def test_ipv6_dot_port(self):
        addr, port = parse_endpoint("2803:c600::cb5.443")
        assert addr == "2803:c600::cb5"
        assert port == "443"

    def test_wildcard_colon(self):
        assert parse_endpoint("*:*") == ("*", "*")

    def test_wildcard_dot(self):
        assert parse_endpoint("*.*") == ("*", "*")

    def test_no_port_separator(self):
        assert parse_endpoint("somehost") == ("somehost", "?")

    def test_ipv6_port_after_last_dot(self):
        addr, port = parse_endpoint("fe80::1%lo0.8080")
        assert port == "8080"
        assert addr == "fe80::1%lo0"


# ---------------------------------------------------------------------------
# services/resolver.py — WhoisResolver._parse_org & format_display_name
# ---------------------------------------------------------------------------

class TestParseOrg:
    def test_orgname_prefix(self):
        text = "OrgName:        Amazon Technologies Inc."
        assert WhoisResolver._parse_org(text) == "Amazon Technologies Inc."

    def test_org_name_prefix_case_insensitive(self):
        text = "org-name:       Cloudflare, Inc."
        assert WhoisResolver._parse_org(text) == "Cloudflare, Inc."

    def test_no_match(self):
        text = "NetRange: 10.0.0.0 - 10.255.255.255\nCIDR: 10.0.0.0/8"
        assert WhoisResolver._parse_org(text) == ""

    def test_na_value(self):
        text = "OrgName:        N/A"
        assert WhoisResolver._parse_org(text) == ""


class TestFormatDisplayName:
    """Tests format_display_name using minimal stub objects instead of full DNS/Whois."""

    class _StubDNS:
        def __init__(self, mapping):
            self._m = mapping
        def get(self, ip):
            return self._m.get(ip, "")

    class _StubWhois:
        def __init__(self, mapping):
            self._m = mapping
        def get(self, ip):
            return self._m.get(ip, "")

    def test_hostname_available(self):
        dns = self._StubDNS({"1.2.3.4": "myhost.example.com"})
        whois = self._StubWhois({})
        assert format_display_name("1.2.3.4", dns, whois) == "myhost.example.com"

    def test_hostname_truncated_at_40(self):
        long_host = "a" * 50 + ".example.com"
        dns = self._StubDNS({"1.2.3.4": long_host})
        whois = self._StubWhois({})
        result = format_display_name("1.2.3.4", dns, whois)
        assert len(result) == 40
        assert result.endswith("...")

    def test_hostname_equals_ip_uses_org(self):
        dns = self._StubDNS({"1.2.3.4": "1.2.3.4"})
        whois = self._StubWhois({"1.2.3.4": "Cloudflare"})
        assert format_display_name("1.2.3.4", dns, whois) == "1.2.3.4 (Cloudflare)"

    def test_no_hostname_no_org(self):
        dns = self._StubDNS({})
        whois = self._StubWhois({})
        assert format_display_name("1.2.3.4", dns, whois) == "1.2.3.4"


# ---------------------------------------------------------------------------
# services/aggregator.py — _is_excluded, human_bytes, sort_rows
# ---------------------------------------------------------------------------

class TestIsExcluded:
    def test_exact_match(self):
        assert _is_excluded("Safari", {"Safari", "Firefox"}) is True

    def test_base_name_match(self):
        assert _is_excluded("Safari (42)", {"Safari"}) is True

    def test_no_match(self):
        assert _is_excluded("Chrome", {"Safari", "Firefox"}) is False


class TestHumanBytes:
    def test_bytes(self):
        assert human_bytes(512) == "512 B"

    def test_kilobytes(self):
        assert human_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert human_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert human_bytes(3 * 1024 * 1024 * 1024) == "3.0 GB"


class TestSortRows:
    @pytest.fixture()
    def rows(self):
        return [
            TrafficRow(process="Zebra", proto="TCP", remote_host="h", remote_port="80",
                       conns=1, bytes_in=100, bytes_out=50),
            TrafficRow(process="alpha", proto="UDP", remote_host="h", remote_port="53",
                       conns=5, bytes_in=10, bytes_out=500),
        ]

    def test_sort_by_process(self, rows):
        result = sort_rows(rows, "process", False)
        assert result[0].process == "alpha"

    def test_sort_by_conns(self, rows):
        result = sort_rows(rows, "conns", True)
        assert result[0].conns == 5

    def test_sort_by_bytes_in(self, rows):
        result = sort_rows(rows, "bytes_in", True)
        assert result[0].bytes_in == 100

    def test_sort_by_bytes_out(self, rows):
        result = sort_rows(rows, "bytes_out", True)
        assert result[0].bytes_out == 500

    def test_sort_by_total(self, rows):
        result = sort_rows(rows, "total", True)
        assert result[0].total == 510


# ---------------------------------------------------------------------------
# services/history.py — ConnectionHistory
# ---------------------------------------------------------------------------

class TestConnectionHistory:
    def test_fingerprint_format(self):
        fp = ConnectionHistory.fingerprint("Safari", "example.com", "443", "TCP")
        assert fp == "Safari|example.com|443|TCP"

    def test_first_seen_is_new(self):
        hist = ConnectionHistory()
        key = "p|h|443|TCP"
        hist.update(key)
        assert hist.get_status(key) == "NEW"

    def test_seen_across_sessions(self):
        # Simulate loading persisted data with times_seen=1, then re-init new session
        seed = {"p|h|443|TCP": {"first_seen": "t0", "last_seen": "t0", "times_seen": 1}}
        hist = ConnectionHistory(data=seed)
        hist.update("p|h|443|TCP")
        assert hist.get_status("p|h|443|TCP") == "SEEN 2x"

    def test_get_data_round_trip(self):
        hist = ConnectionHistory()
        hist.update("a|b|c|d")
        data = hist.get_data()
        assert "a|b|c|d" in data
        assert data["a|b|c|d"]["times_seen"] == 1


# ---------------------------------------------------------------------------
# ui/input_handler.py — handle_key
# ---------------------------------------------------------------------------

class TestHandleKey:
    @pytest.fixture()
    def env(self):
        """Provide a state, sample display rows, and max_rows."""
        state = ApplicationState()
        rows = [
            TrafficRow(process="Safari", proto="TCP", remote_host="h",
                       remote_port="443", bytes_in=100, bytes_out=200),
            TrafficRow(process="Chrome", proto="TCP", remote_host="h",
                       remote_port="443", bytes_in=50, bytes_out=50),
        ]
        state.rows = rows
        return state, rows, 20  # max_rows

    def test_quit(self, env):
        state, rows, max_rows = env
        assert handle_key(ord("q"), state, max_rows, rows) == KeyAction.QUIT

    def test_sort_cycles(self, env):
        state, rows, max_rows = env
        assert state.sort_key == "total"
        handle_key(ord("s"), state, max_rows, rows)
        assert state.sort_key == "process"

    def test_filter_cycles(self, env):
        state, rows, max_rows = env
        assert state.filter_state == "all"
        handle_key(ord("f"), state, max_rows, rows)
        assert state.filter_state == "new"
        handle_key(ord("f"), state, max_rows, rows)
        assert state.filter_state == "known"

    def test_arrow_down(self, env):
        state, rows, max_rows = env
        assert state.selected_row == 0
        handle_key(curses.KEY_DOWN, state, max_rows, rows)
        assert state.selected_row == 1

    def test_arrow_up_at_zero(self, env):
        state, rows, max_rows = env
        handle_key(curses.KEY_UP, state, max_rows, rows)
        assert state.selected_row == 0

    def test_exclude_process(self, env):
        state, rows, max_rows = env
        action = handle_key(ord("x"), state, max_rows, rows)
        assert action == KeyAction.EXCLUDE_PROCESS
        assert state.last_excluded_process == "Safari"

    def test_clear_tracker(self, env):
        state, rows, max_rows = env
        action = handle_key(ord("l"), state, max_rows, rows)
        assert action == KeyAction.CLEAR_TRACKER


# ---------------------------------------------------------------------------
# config.py — load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_missing_file_returns_empty(self, monkeypatch, tmp_path):
        monkeypatch.setattr("netwatch.config.CONFIG_FILE", tmp_path / "nope.yaml")
        assert load_config() == {}

    def test_fallback_parser(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text('excluded_processes:\n  - "Safari"\n  - "Firefox"\n')
        monkeypatch.setattr("netwatch.config.CONFIG_FILE", cfg)
        # Force fallback parser by hiding yaml
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fake_import)
        result = load_config()
        assert result["excluded_processes"] == ["Safari", "Firefox"]


# ---------------------------------------------------------------------------
# storage/database.py — Storage round-trip
# ---------------------------------------------------------------------------

class TestStorageRoundTrip:
    def test_history_and_whois(self, monkeypatch, tmp_path):
        # Point Storage at a temp directory so it doesn't touch real data
        monkeypatch.setattr("netwatch.storage.database.DATA_DIR", tmp_path)
        monkeypatch.setattr("netwatch.storage.database.DB_FILE", tmp_path / "test.db")
        monkeypatch.setattr("netwatch.storage.database.LEGACY_HISTORY_FILE",
                            tmp_path / "nope1.json")
        monkeypatch.setattr("netwatch.storage.database.LEGACY_WHOIS_FILE",
                            tmp_path / "nope2.json")

        from netwatch.storage.database import Storage

        store = Storage()
        try:
            # History round-trip
            hist_data = {
                "Safari|example.com|443|TCP": {
                    "first_seen": "2025-01-01T00:00:00",
                    "last_seen": "2025-06-01T00:00:00",
                    "times_seen": 5,
                },
            }
            store.save_history(hist_data)
            loaded = store.load_history()
            assert "Safari|example.com|443|TCP" in loaded
            assert loaded["Safari|example.com|443|TCP"]["times_seen"] == 5

            # Whois round-trip
            whois_data = {"1.2.3.4": "Cloudflare", "5.6.7.8": "Amazon"}
            store.save_whois(whois_data)
            loaded_whois = store.load_whois()
            assert loaded_whois["1.2.3.4"] == "Cloudflare"
            assert loaded_whois["5.6.7.8"] == "Amazon"
        finally:
            store.close()
