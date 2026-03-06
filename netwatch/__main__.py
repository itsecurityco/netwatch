"""Entry point — slim orchestrator for netwatch."""

import logging
import os
import random
import re
import sys
import time

# windows-curses provides a drop-in curses replacement on Windows.
# Install with:  pip install windows-curses
if sys.platform == "win32":
    try:
        import curses  # noqa: F401  (windows-curses registers itself here)
    except ImportError:
        print(
            "ERROR: 'windows-curses' is required on Windows.\n"
            "Install it with:  pip install windows-curses",
            file=sys.stderr,
        )
        sys.exit(1)

import curses

from .config import REFRESH_INTERVAL, INPUT_TIMEOUT_MS, SAVE_INTERVAL, DATA_DIR, LOG_FILE, load_config
from .services.traffic_collector import parse_nettop_output, get_local_ip
from .services.aggregator import aggregate_connections, enrich_with_history, sort_rows, RowTracker
from .services.resolver import DNSCache, WhoisResolver
from .services.traffic_collector import ProcessNameCache
from .services.history import ConnectionHistory
from .storage.database import Storage
from .ui.state import ApplicationState
from .ui.renderer import draw_header, draw_table_header, draw_row, draw_footer
from .ui.input_handler import handle_key, KeyAction


class Application:

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        logging.basicConfig(
            filename=str(LOG_FILE),
            level=logging.WARNING,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
        if LOG_FILE.exists():
            os.chmod(LOG_FILE, 0o600)

        if sys.platform == "win32":
            default_iface = "auto"
        elif sys.platform == "linux":
            default_iface = "eth0"
        else:
            default_iface = "en0"
        iface = sys.argv[1] if len(sys.argv) > 1 else default_iface
        if not re.match(r'^[a-zA-Z0-9]+$', iface):
            print(f"Invalid interface name: {iface}", file=sys.stderr)
            sys.exit(1)
        self._interface = iface
        self._local_ip = get_local_ip(self._interface)

        self._storage = Storage()
        self._whois = WhoisResolver(data=self._storage.load_whois())
        self._dns = DNSCache(whois=self._whois)
        self._proc_cache = ProcessNameCache()
        self._history = ConnectionHistory(data=self._storage.load_history())
        self._row_tracker = RowTracker()

        self._config_exclusions = set(load_config().get("excluded_processes", []))
        db_exclusions = self._storage.load_excluded()
        initial_exclusions = self._config_exclusions | db_exclusions

        self._state = ApplicationState(last_save=time.time(),
                                       excluded_processes=initial_exclusions)
        self._start_time = time.time()
        self._display_cache = None
        self._display_cache_key = None

    def _init_curses(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(INPUT_TIMEOUT_MS)
        curses.use_default_colors()

        header_colors = [
            (curses.COLOR_BLACK, curses.COLOR_CYAN),
            (curses.COLOR_BLACK, curses.COLOR_GREEN),
            (curses.COLOR_WHITE, curses.COLOR_MAGENTA),
            (curses.COLOR_BLACK, curses.COLOR_YELLOW),
            (curses.COLOR_BLACK, curses.COLOR_WHITE),
            (curses.COLOR_WHITE, curses.COLOR_RED),
        ]
        fg, bg = random.choice(header_colors)
        curses.init_pair(1, fg, bg)                    # header bar
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # OUT
        curses.init_pair(3, curses.COLOR_CYAN, -1)     # IN
        curses.init_pair(4, curses.COLOR_WHITE, -1)    # footer / stale
        curses.init_pair(5, curses.COLOR_YELLOW, -1)   # NEW connections

    def _save(self):
        self._storage.save_history(self._history.get_data())
        self._storage.save_whois(self._whois.get_cache())

    def _refresh_data(self):
        now = time.time()
        state = self._state
        state.elapsed = (now - state.last_refresh
                         if state.last_refresh > 0 else REFRESH_INTERVAL)
        state.connections = parse_nettop_output()

        new_rows = aggregate_connections(
            state.connections, self._dns, self._whois, self._proc_cache,
            state.show_loopback,
            excluded_processes=state.excluded_processes,
        )
        enrich_with_history(new_rows, self._history)

        # Save previous totals for delta mode
        if state.rows:
            for r in state.rows:
                key = (r.process, r.remote_host, r.remote_port, r.proto)
                state.prev_totals[(*key, "in")] = r.bytes_in
                state.prev_totals[(*key, "out")] = r.bytes_out
                state.prev_totals[(*key, "total")] = r.total

        merged = self._row_tracker.update(new_rows)
        state.rows = sort_rows(merged, state.sort_key, state.sort_desc)
        state.last_refresh = now

    def _get_display_rows(self):
        state = self._state
        key = (state.filter_state, id(state.rows))
        if key != self._display_cache_key:
            if state.filter_state == "new":
                self._display_cache = [r for r in state.rows if r.status == "NEW"]
            elif state.filter_state == "known":
                self._display_cache = [r for r in state.rows if r.status != "NEW"]
            else:
                self._display_cache = state.rows
            self._display_cache_key = key
        return self._display_cache

    def _render(self, stdscr, display_rows):
        state = self._state
        stdscr.erase()
        draw_header(stdscr, self._interface, self._local_ip, state.paused, self._start_time)

        h, w = stdscr.getmaxyx()
        table_start = 2
        max_rows = h - 5

        draw_table_header(stdscr, 1, state.sort_key, state.sort_desc)

        # Clamp scroll and cursor
        state.scroll_offset = max(0, min(state.scroll_offset,
                                         len(display_rows) - max_rows))
        if display_rows:
            state.selected_row = max(0, min(state.selected_row,
                                            len(display_rows) - 1))
        else:
            state.selected_row = 0

        visible = display_rows[state.scroll_offset:state.scroll_offset + max_rows]
        for i, row in enumerate(visible):
            is_bold = (i + state.scroll_offset < 3
                       if state.sort_desc else False)
            is_selected = (i + state.scroll_offset == state.selected_row)
            draw_row(stdscr, table_start + i, row, is_bold,
                     state.delta_mode, state.prev_totals, state.elapsed,
                     selected=is_selected)

        draw_footer(stdscr, display_rows, state.connections, state.sort_key,
                    state.show_loopback, state.delta_mode, state.paused,
                    state.filter_state,
                    excluded_count=len(state.excluded_processes))

        stdscr.refresh()
        return max_rows

    def _handle_action(self, action):
        state = self._state
        if action is KeyAction.CLEAR_TRACKER:
            self._row_tracker.clear()
        elif action is KeyAction.EXCLUDE_PROCESS:
            self._storage.add_excluded_process(state.last_excluded_process)
            self._row_tracker.clear()
            state.last_refresh = 0
        elif action is KeyAction.CLEAR_EXCLUSIONS:
            self._storage.clear_excluded()
            state.excluded_processes = set(self._config_exclusions)
            self._row_tracker.clear()
            state.last_refresh = 0

    def _cleanup(self):
        self._save()
        self._storage.close()
        self._dns.shutdown()

    def run(self, stdscr):
        self._init_curses(stdscr)
        state = self._state

        try:
            while True:
                now = time.time()

                # Periodic save
                if now - state.last_save >= SAVE_INTERVAL:
                    self._save()
                    state.last_save = now

                # Refresh data
                if not state.paused and now - state.last_refresh >= REFRESH_INTERVAL:
                    self._refresh_data()

                display_rows = self._get_display_rows()
                max_rows = self._render(stdscr, display_rows)

                # Handle input
                try:
                    key = stdscr.getch()
                except curses.error:
                    key = -1

                if key != -1:
                    action = handle_key(key, state, max_rows, display_rows)
                    if action is KeyAction.QUIT:
                        break
                    self._handle_action(action)
        finally:
            self._cleanup()


def main(stdscr):
    Application().run(stdscr)


def run():
    curses.wrapper(main)


if __name__ == "__main__":
    run()
