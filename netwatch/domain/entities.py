"""Core domain entities."""

from dataclasses import dataclass


@dataclass
class Connection:
    process: str
    pid: int
    proto: str
    remote_addr: str
    remote_port: str
    bytes_in: int
    bytes_out: int


@dataclass
class TrafficRow:
    process: str
    proto: str
    remote_host: str
    remote_port: str
    raw_remote_addr: str = ""
    conns: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    status: str = ""
    stale: bool = False

    @property
    def total(self):
        return self.bytes_in + self.bytes_out

    @property
    def direction(self):
        if self.bytes_out > self.bytes_in * 2:
            return "OUT"
        if self.bytes_in > self.bytes_out * 2:
            return "IN"
        return "BOTH"

    @property
    def row_key(self) -> tuple:
        """Stable key using raw IP address, not display name."""
        return (self.process, self.raw_remote_addr or self.remote_host,
                self.remote_port, self.proto)
