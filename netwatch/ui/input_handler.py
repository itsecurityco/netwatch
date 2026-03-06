"""Keyboard input handling."""

import curses
from enum import Enum, auto

from ..config import SORT_KEYS, FILTER_STATES
from .state import ApplicationState
from ..services.aggregator import sort_rows


class KeyAction(Enum):
    """Actions that handle_key can return to the caller."""
    CONTINUE = auto()
    QUIT = auto()
    CLEAR_TRACKER = auto()
    EXCLUDE_PROCESS = auto()
    CLEAR_EXCLUSIONS = auto()


def handle_key(key: int, state: ApplicationState, max_rows: int,
               display_rows: list) -> KeyAction:
    """Process a keypress, mutate state, return a KeyAction.

    Returns:
        KeyAction.CONTINUE — normal loop iteration
        KeyAction.QUIT — exit the application
        KeyAction.CLEAR_TRACKER — caller should reset the RowTracker
        KeyAction.EXCLUDE_PROCESS — caller should persist the exclusion
        KeyAction.CLEAR_EXCLUSIONS — caller should clear interactive exclusions
    """
    display_row_count = len(display_rows)

    if key == ord("q") or key == 27:
        return KeyAction.QUIT
    elif key == ord("s"):
        idx = SORT_KEYS.index(state.sort_key)
        state.sort_key = SORT_KEYS[(idx + 1) % len(SORT_KEYS)]
        state.rows = sort_rows(state.rows, state.sort_key, state.sort_desc)
        state.scroll_offset = 0
        state.selected_row = 0
    elif key == ord("r"):
        state.sort_desc = not state.sort_desc
        state.rows = sort_rows(state.rows, state.sort_key, state.sort_desc)
    elif key == ord("l"):
        state.show_loopback = not state.show_loopback
        state.last_refresh = 0  # force refresh
        return KeyAction.CLEAR_TRACKER
    elif key == ord("p"):
        state.paused = not state.paused
    elif key == ord("d"):
        state.delta_mode = not state.delta_mode
    elif key == ord("f"):
        idx = FILTER_STATES.index(state.filter_state)
        state.filter_state = FILTER_STATES[(idx + 1) % len(FILTER_STATES)]
        state.scroll_offset = 0
        state.selected_row = 0
    elif key == ord("x"):
        if display_rows and state.selected_row < len(display_rows):
            target = display_rows[state.selected_row]
            base_name = target.process.split(" (")[0]
            state.last_excluded_process = base_name
            state.excluded_processes.add(base_name)
            state.last_refresh = 0  # force refresh
            return KeyAction.EXCLUDE_PROCESS
    elif key == ord("X"):
        return KeyAction.CLEAR_EXCLUSIONS
    elif key == curses.KEY_DOWN:
        if display_row_count > 0:
            state.selected_row = min(state.selected_row + 1,
                                     display_row_count - 1)
            # Auto-scroll down if cursor goes below visible area
            if state.selected_row >= state.scroll_offset + max_rows:
                state.scroll_offset = state.selected_row - max_rows + 1
    elif key == curses.KEY_UP:
        state.selected_row = max(state.selected_row - 1, 0)
        # Auto-scroll up if cursor goes above visible area
        if state.selected_row < state.scroll_offset:
            state.scroll_offset = state.selected_row

    return KeyAction.CONTINUE
