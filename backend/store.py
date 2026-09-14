from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class SQLiteStore:
    """Small durable store with an append-only, hash-chained audit log."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock, self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS audit_investigation_idx ON audit_events(investigation_id, sequence);
                """
            )

    def save_investigation(self, investigation: dict[str, Any]) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        investigation["updated_at"] = now
        with self.lock, self.connection:
            self.connection.execute(
                """INSERT INTO investigations(id,status,created_at,updated_at,payload)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, payload=excluded.payload""",
                (investigation["id"], investigation["status"], investigation["created_at"], now, json.dumps(investigation, separators=(",", ":"))),
            )

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute("SELECT payload FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_investigations(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT payload FROM investigations ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def append_audit(self, investigation_id: str, event_type: str, actor: str, payload: dict[str, Any]) -> dict[str, Any]:
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.lock, self.connection:
            previous = self.connection.execute("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else "GENESIS"
            canonical = json.dumps({"investigation_id": investigation_id, "event_type": event_type, "actor": actor, "created_at": created_at, "payload": payload, "previous_hash": previous_hash}, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            self.connection.execute(
                "INSERT INTO audit_events(investigation_id,event_type,actor,created_at,payload,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                (investigation_id, event_type, actor, created_at, json.dumps(payload, separators=(",", ":")), previous_hash, event_hash),
            )
        return {"investigation_id": investigation_id, "event_type": event_type, "actor": actor, "created_at": created_at, "payload": payload, "previous_hash": previous_hash, "event_hash": event_hash}

    def audit_events(self, investigation_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT * FROM audit_events WHERE investigation_id = ? ORDER BY sequence", (investigation_id,)).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]

    def close(self) -> None:
        with self.lock:
            self.connection.close()
