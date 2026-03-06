#!/usr/bin/env python3
"""Netwatch — real-time network traffic dashboard for macOS.

Uses nettop to show per-process network connections with byte counts
in a top-like curses interface.

Usage:
    python3 netwatch.py [interface]   # default: en0
    python3 -m netwatch [interface]
"""

from netwatch.__main__ import run

if __name__ == "__main__":
    run()
