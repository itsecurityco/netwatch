"""Connection history tracking (business logic only, no file I/O)."""

from datetime import datetime, timezone


class ConnectionHistory:
    """Tracks connection fingerprints across sessions."""

    def __init__(self, data: dict[str, dict] | None = None):
        self._data: dict[str, dict] = data or {}
        self._seen_this_session: set[str] = set()

    def get_data(self) -> dict[str, dict]:
        return self._data

    @staticmethod
    def fingerprint(process: str, remote_host: str, port: str, proto: str) -> str:
        return f"{process}|{remote_host}|{port}|{proto}"

    def update(self, key: str):
        now = datetime.now(timezone.utc).isoformat()
        if key not in self._data:
            self._data[key] = {
                "first_seen": now,
                "last_seen": now,
                "times_seen": 1,
            }
        elif key not in self._seen_this_session:
            self._data[key]["last_seen"] = now
            self._data[key]["times_seen"] += 1
        self._seen_this_session.add(key)

    def get_status(self, key: str) -> str:
        entry = self._data.get(key)
        if not entry or entry["times_seen"] <= 1:
            return "NEW"
        return f"SEEN {entry['times_seen']}x"
