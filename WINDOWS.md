# Netwatch — Windows Setup

## Requirements

- Python 3.11+
- A terminal that supports ANSI / VT sequences (Windows Terminal recommended; legacy `cmd.exe` may have display issues)
- **Administrator privileges** — `psutil.net_connections()` requires elevated rights to see all processes

## Install dependencies

```powershell
pip install -r requirements-windows.txt
```

## Run

```powershell
# In an elevated (Administrator) terminal:
python -m netwatch
```

The interface argument is ignored on Windows; the local IP is detected automatically.

## Known differences vs macOS

| Feature | macOS | Windows |
|---|---|---|
| Connection list | `lsof` (exact) | `psutil.net_connections()` (exact) |
| Process names | `ps` | `psutil` / `tasklist` |
| Byte counts | `nettop` per-connection | `psutil` per-process delta (approximate) |
| Loopback filter | ✅ | ✅ |
| `whois` enrichment | ✅ (built-in) | ⚠️ requires [whois for Windows](https://learn.microsoft.com/en-us/sysinternals/downloads/whois) in PATH |

### Byte count note

On Windows, `psutil` exposes per-**process** network I/O (via `io_counters().other_bytes`) rather than per-connection counters. Netwatch distributes the process delta evenly across all of that process's active connections, using a 40 % in / 60 % out heuristic. The numbers are approximate but correct in order of magnitude.

If you need precise per-connection byte counts, consider running netwatch via [Wireshark](https://www.wireshark.org/) in parallel, or implement an ETW-based collector (see the project analysis doc for guidance).

## Troubleshooting

**Empty connection list** — Run the terminal as Administrator.

**`ModuleNotFoundError: No module named 'curses'`** — Run `pip install windows-curses`.

**Display looks garbled** — Use Windows Terminal instead of the legacy console host.
