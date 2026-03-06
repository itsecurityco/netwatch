# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Netwatch — a real-time terminal dashboard that monitors per-process network connections on macOS, Windows, and Linux. Uses platform-specific tools (`nettop`/`lsof` on macOS, `psutil` on Windows/Linux, `/proc` on Linux) to discover connections, resolves hostnames via DNS/whois, and displays traffic in a curses-based top-like interface.

## Running

```bash
# Default: interface en0
python3 netwatch.py

# Via module
python3 -m netwatch

# Custom interface
python3 netwatch.py en1
```

## Testing

```bash
python3 -m pytest tests/ -v
```

## Architecture

Layered Python package (`netwatch/`):

- **`__main__.py`** — Orchestrator: initializes services, runs the curses main loop (refresh data every 2s, render every 200ms, handle input).
- **`config.py`** — Constants (intervals, column positions, sort/filter keys) and YAML config loader. Data stored in `~/.netwatch/`.
- **`domain/entities.py`** — Dataclasses: `Connection` (raw nettop/lsof row), `TrafficRow` (aggregated display row with computed `total`, `direction`, `row_key`).
- **`services/traffic_collector.py`** — Cross-platform dispatcher and shared utilities (`parse_endpoint()`, `ProcessNameCache`). Delegates to platform-specific collectors.
- **`services/_collector_macos.py`** — macOS: `nettop` (byte counts) + `lsof` (connection list) + `ps` (process names).
- **`services/_collector_windows.py`** — Windows: `psutil` for connections + `io_counters().other_bytes` for approximate byte deltas.
- **`services/_collector_linux.py`** — Linux: `psutil` for connections + `/proc/{pid}/net/dev` for per-process network byte deltas + `/proc/{pid}/comm` for process names.
- **`services/resolver.py`** — Async DNS resolution (`DNSCache`) with whois fallback (`WhoisResolver`). `format_display_name()` picks the best label (hostname > ip+org > raw ip).
- **`services/aggregator.py`** — Groups connections into `TrafficRow`s, enriches with history status, provides `sort_rows()` / `human_bytes()`. `RowTracker` keeps stale rows visible for 24h.
- **`services/history.py`** — `ConnectionHistory`: fingerprint-based tracking of NEW vs SEEN connections across sessions.
- **`storage/database.py`** — SQLite persistence for connection history, whois cache, and excluded processes. Auto-migrates legacy JSON files.
- **`ui/renderer.py`** — Curses drawing: header bar, table header, rows, footer.
- **`ui/input_handler.py`** — Keyboard dispatch: sort/filter cycling, scroll, pause, exclude, quit.
- **`ui/state.py`** — `ApplicationState` dataclass holding all mutable UI state.
