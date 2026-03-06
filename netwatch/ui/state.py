"""Application state consolidation."""

from dataclasses import dataclass, field

from ..domain.entities import Connection, TrafficRow


@dataclass
class ApplicationState:
    sort_key: str = "total"
    sort_desc: bool = True
    show_loopback: bool = False
    paused: bool = False
    delta_mode: bool = False
    filter_state: str = "all"
    scroll_offset: int = 0
    selected_row: int = 0
    prev_totals: dict = field(default_factory=dict)
    rows: list[TrafficRow] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    elapsed: float = 2.0
    last_refresh: float = 0.0
    last_save: float = 0.0
    excluded_processes: set = field(default_factory=set)
    last_excluded_process: str = ""
