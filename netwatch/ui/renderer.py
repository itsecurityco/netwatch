"""Curses rendering functions."""

import curses
import time

from ..config import (
    REFRESH_INTERVAL, SORT_LABELS, FILTER_LABELS, TABLE_WIDTH,
    COL_PROC, COL_STATUS, COL_PROTO, COL_DIR, COL_HOST,
    COL_PORT, COL_CONNS, COL_IN, COL_OUT, COL_TOTAL,
)
from ..domain.entities import Connection, TrafficRow
from ..services.aggregator import human_bytes


def draw_header(stdscr, interface: str, local_ip: str, paused: bool,
                start_time: float = 0.0):
    h, w = stdscr.getmaxyx()
    now = time.strftime("%H:%M:%S")
    pause_str = " PAUSED" if paused else ""
    elapsed = int(time.time() - start_time) if start_time else 0
    hours, rem = divmod(elapsed, 3600)
    mins, secs = divmod(rem, 60)
    uptime = f"{hours:02d}:{mins:02d}:{secs:02d}"
    title = (f" Netwatch \u2500\u2500 {interface} \u2500\u2500 {local_ip} \u2500\u2500 "
             f"Refresh: {REFRESH_INTERVAL}s \u2500\u2500 {now} \u2500\u2500 Up: {uptime}{pause_str} ")
    title = title[:w - 1]

    try:
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(0, 0, title.ljust(w - 1))
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
    except curses.error:
        pass


def draw_table_header(stdscr, row: int, sort_key: str, sort_desc: bool):
    h, w = stdscr.getmaxyx()
    if row >= h:
        return

    headers = [
        (COL_PROC, "PROCESS"),
        (COL_STATUS, "STATUS"),
        (COL_PROTO, "PROTO"),
        (COL_DIR, "DIR"),
        (COL_HOST, "REMOTE HOST"),
        (COL_PORT, "PORT"),
        (COL_CONNS, "CONNS"),
        (COL_IN, "IN"),
        (COL_OUT, "OUT"),
        (COL_TOTAL, "TOTAL"),
    ]

    try:
        stdscr.attron(curses.A_BOLD | curses.A_UNDERLINE)
        stdscr.addstr(row, 0, " " * min(w - 1, TABLE_WIDTH))
        for col, name in headers:
            if col < w - 1:
                label = name
                key_for_col = name.lower().replace(" ", "_")
                if key_for_col == "in":
                    key_for_col = "bytes_in"
                elif key_for_col == "out":
                    key_for_col = "bytes_out"
                if key_for_col == sort_key:
                    arrow = " \u25bc" if sort_desc else " \u25b2"
                    label = name + arrow
                stdscr.addstr(row, col + 1, label[:w - col - 2])
        stdscr.attroff(curses.A_BOLD | curses.A_UNDERLINE)
    except curses.error:
        pass


def draw_row(stdscr, y: int, row: TrafficRow, bold: bool, delta_mode: bool,
             prev_totals: dict, elapsed: float, selected: bool = False):
    h, w = stdscr.getmaxyx()
    if y >= h - 1:
        return

    is_new = row.status == "NEW"

    if row.stale:
        color = curses.color_pair(4) | curses.A_DIM
    elif is_new:
        color = curses.color_pair(5)
    elif row.direction == "OUT":
        color = curses.color_pair(2)
    elif row.direction == "IN":
        color = curses.color_pair(3)
    else:
        color = curses.color_pair(4)  # white on default bg — safe on all terminals

    if bold and not row.stale:
        color |= curses.A_BOLD

    if selected:
        color |= curses.A_REVERSE

    def bytes_display(val: int, key: str) -> str:
        if delta_mode and elapsed > 0:
            prev = prev_totals.get(key, 0)
            delta = max(0, val - prev)
            rate = delta / elapsed
            return human_bytes(int(rate)) + "/s"
        return human_bytes(val)

    row_key = (row.process, row.remote_host, row.remote_port, row.proto)

    fields = [
        (COL_PROC, row.process[:COL_STATUS - COL_PROC - 1]),
        (COL_STATUS, row.status[:9]),
        (COL_PROTO, row.proto),
        (COL_DIR, row.direction),
        (COL_HOST, row.remote_host[:34]),
        (COL_PORT, str(row.remote_port)[:5]),
        (COL_CONNS, str(row.conns)),
        (COL_IN, bytes_display(row.bytes_in, (*row_key, "in"))),
        (COL_OUT, bytes_display(row.bytes_out, (*row_key, "out"))),
        (COL_TOTAL, bytes_display(row.total, (*row_key, "total"))),
    ]

    try:
        stdscr.attron(color)
        stdscr.addstr(y, 0, " " * min(w - 1, TABLE_WIDTH))
        for col, text in fields:
            if col < w - 1:
                if col >= COL_CONNS:
                    pad = 9 - len(text)
                    stdscr.addstr(y, col + 1 + max(0, pad), text[:w - col - 2])
                else:
                    stdscr.addstr(y, col + 1, text[:w - col - 2])
        stdscr.attroff(color)
    except curses.error:
        pass


def draw_footer(stdscr, rows: list[TrafficRow], connections: list[Connection],
                sort_key: str, show_loopback: bool, delta_mode: bool, paused: bool,
                filter_state: str = "all", excluded_count: int = 0):
    h, w = stdscr.getmaxyx()
    if h < 4:
        return

    n_conns = sum(r.conns for r in rows)
    n_procs = len(set(r.process for r in rows))
    n_stale = sum(1 for r in rows if r.stale)

    sort_label = SORT_LABELS.get(sort_key, sort_key.upper())
    lb_str = "shown" if show_loopback else "hidden"
    mode_str = "delta" if delta_mode else "cumulative"
    filter_label = FILTER_LABELS.get(filter_state, "All")

    stale_str = f" ({n_stale} stale)" if n_stale else ""
    excl_str = f" \u2502 Excluded: {excluded_count}" if excluded_count else ""
    status = (f"  {n_conns} connections from {n_procs} processes{stale_str} \u2502 "
              f"Sort: {sort_label} \u2502 Loopback: {lb_str} \u2502 Mode: {mode_str} \u2502 "
              f"Filter: {filter_label}{excl_str}")
    keys = "  q:quit  s:sort  r:reverse  l:loopback  p:pause  d:delta  f:filter  x:exclude  X:clear excl"
    author = "github.com/itsecurityco"

    try:
        y = h - 3
        stdscr.attron(curses.color_pair(4) | curses.A_DIM)
        stdscr.addstr(y, 0, "\u2500" * min(w - 1, TABLE_WIDTH))
        stdscr.attroff(curses.color_pair(4) | curses.A_DIM)

        y = h - 2
        stdscr.attron(curses.color_pair(4))
        stdscr.addstr(y, 0, status[:w - 1].ljust(w - 1))
        stdscr.attroff(curses.color_pair(4))

        y = h - 1
        stdscr.attron(curses.color_pair(4))
        stdscr.addstr(y, 0, keys[:w - 1].ljust(w - 1))
        stdscr.attroff(curses.color_pair(4))

        author_x = w - len(author) - 2
        if author_x > len(keys):
            stdscr.attron(curses.color_pair(4) | curses.A_DIM)
            stdscr.addstr(y, author_x, author)
            stdscr.attroff(curses.color_pair(4) | curses.A_DIM)
    except curses.error:
        pass
