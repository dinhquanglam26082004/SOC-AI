"""Small SQLite-backed snapshot store for dashboard runtime data."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class RuntimeStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_state (id INTEGER PRIMARY KEY CHECK(id = 1), payload TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def load(self) -> dict[str, Any]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT payload FROM runtime_state WHERE id = 1").fetchone()
        if not row:
            return {}
        try:
            value = json.loads(row[0])
            return value if isinstance(value, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def save(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO runtime_state(id, payload) VALUES(1, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (encoded,),
            )
