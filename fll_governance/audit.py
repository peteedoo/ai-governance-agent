"""Tamper-evident audit trail: every evaluation is hash-chained and persisted.

Each event includes the SHA-256 of the previous event, so any edit or
deletion in the log invalidates the chain — a key requirement for
compliance-grade auditability in legal/insurance contexts.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

_GENESIS = "0" * 64


class AuditLogger:
    def __init__(self, db_path: str | Path = "audit.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    output_hash TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
            """)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _last_hash(self) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else _GENESIS

    def record(self, *, output: str, verdict, context: dict) -> str:
        event_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        prev_hash = self._last_hash()
        payload = {
            "event_id": event_id,
            "ts": ts,
            "decision": verdict.decision.value,
            "input_hash": hashlib.sha256(output.encode()).hexdigest(),
            "output_hash": hashlib.sha256(verdict.output.encode()).hexdigest(),
            "findings": [
                {"check": f.check, "decision": f.decision.value, "detail": f.detail}
                for f in verdict.findings
            ],
            "context": context,
            "prev_hash": prev_hash,
        }
        event_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
                (event_id, ts, verdict.decision.value,
                 payload["input_hash"], payload["output_hash"],
                 json.dumps(payload["findings"]), json.dumps(context),
                 prev_hash, event_hash),
            )
        return event_id

    def verify_chain(self) -> bool:
        """Recompute every hash; returns False if any event was tampered with."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT event_id, ts, decision, input_hash, output_hash,"
                " findings_json, context_json, prev_hash, event_hash FROM events ORDER BY rowid"
            ).fetchall()
        prev = _GENESIS
        for row in rows:
            payload = {
                "event_id": row[0], "ts": row[1], "decision": row[2],
                "input_hash": row[3], "output_hash": row[4],
                "findings": json.loads(row[5]), "context": json.loads(row[6]),
                "prev_hash": row[7],
            }
            if row[7] != prev:
                return False
            if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != row[8]:
                return False
            prev = row[8]
        return True

    def tail(self, n: int = 10) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT event_id, ts, decision, findings_json FROM events"
                " ORDER BY rowid DESC LIMIT ?", (n,),
            ).fetchall()
        return [
            {"event_id": r[0], "ts": r[1], "decision": r[2], "findings": json.loads(r[3])}
            for r in rows
        ]
