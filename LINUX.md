# Netwatch — Linux Setup

## Requirements

- Python 3.11+
- `psutil` (`pip install psutil`)
- **Root or CAP_NET_ADMIN** — `psutil.net_connections()` needs elevated rights to see all processes

## Install dependencies

```bash
pip install psutil
```

## Run

```bash
# As root or with sudo:
sudo python3 -m netwatch

# Custom interface (default: eth0, used for display only)
sudo python3 -m netwatch eth0
```

The interface argument is used for display only; the local IP is detected automatically via outbound route probing.

## Known differences vs macOS

| Feature | macOS | Linux |
|---|---|---|
| Connection list | `lsof` (exact) | `psutil.net_connections()` (exact) |
| Process names | `ps` | `/proc/{pid}/comm` (fast, no subprocess) |
| Byte counts | `nettop` per-connection (precise) | `/proc/{pid}/net/dev` per-process (approximate) |
| Loopback filter | Supported | Supported |
| `whois` enrichment | Built-in | Requires `whois` package (`apt install whois`) |

### Byte count note

On Linux, netwatch reads `/proc/{pid}/net/dev` to get per-process rx/tx byte counters across all non-loopback interfaces. The delta between polls is distributed evenly across all of that process's active connections. Unlike Windows (which uses a fixed 40/60 split), Linux preserves the actual rx/tx ratio from `/proc`.

The numbers are still approximate since they are per-process, not per-connection.

## Troubleshooting

**Empty connection list** — Run with `sudo` or as root.

**`ModuleNotFoundError: No module named 'psutil'`** — Run `pip install psutil`.

**`whois` lookups not working** — Install the whois package: `apt install whois` (Debian/Ubuntu) or `dnf install whois` (Fedora).
