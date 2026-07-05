"""
store/incidents.py — Incident persistence layer.

Wraps Redis operations and provides an optional SQLite export for
post-incident forensics or offline reporting.

Usage:
  from store.incidents import IncidentStore
  store = IncidentStore()
  store.save(inc_dict)
  all_incs = store.all()
  store.export_sqlite("incidents.db")
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time

import redis

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
_WINDOW    = int(os.getenv("CORRELATION_WINDOW_SEC", "900"))


class IncidentStore:
    """Thin wrapper around Redis incident keys with optional SQLite export."""

    def __init__(self):
        self.r = redis.from_url(_REDIS_URL)

    # ── CRUD ──────────────────────────────────────────────────────────────

    def save(self, inc: dict) -> None:
        """Persist or update an incident."""
        key = f"incident:{inc['incident_id']}"
        self.r.set(key, json.dumps(inc))

    def get(self, inc_id: str) -> dict | None:
        raw = self.r.get(f"incident:{inc_id}")
        return json.loads(raw) if raw else None

    def all(self, active_only: bool = False) -> list[dict]:
        """Return all incidents, optionally filtering out stale ones."""
        result = []
        now = time.time()
        for key in self.r.scan_iter("incident:*"):
            raw = self.r.get(key)
            if not raw:
                continue
            try:
                inc = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if active_only and now - inc.get("last_seen", 0) > _WINDOW:
                continue
            result.append(inc)
        return sorted(result, key=lambda i: i.get("last_seen", 0), reverse=True)

    def delete(self, inc_id: str) -> None:
        self.r.delete(f"incident:{inc_id}")

    # ── Analytics ─────────────────────────────────────────────────────────

    def metrics(self) -> dict:
        incs    = self.all()
        sev_map: dict[str, int] = {}
        type_map: dict[str, int] = {}

        for key in self.r.scan_iter("alert:*"):
            raw = self.r.get(key)
            if not raw:
                continue
            try:
                a = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            sev  = a.get("severity", "Info")
            typ  = a.get("event_type", "Other")
            sev_map[sev]  = sev_map.get(sev, 0)  + 1
            type_map[typ] = type_map.get(typ, 0) + 1

        return {
            "open_incidents": len(incs),
            "by_severity":    sev_map,
            "by_type":        type_map,
            "p1": sum(1 for i in incs if i.get("priority") == "P1"),
            "p2": sum(1 for i in incs if i.get("priority") == "P2"),
        }

    # ── Export ────────────────────────────────────────────────────────────

    def export_sqlite(self, db_path: str = "incidents.db") -> None:
        """Export all incidents to a SQLite database for offline analysis."""
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                priority TEXT,
                max_risk INTEGER,
                asset TEXT,
                campaign_name TEXT,
                tactics TEXT,
                alert_count INTEGER,
                created REAL,
                last_seen REAL,
                summary TEXT,
                recommended_action TEXT,
                raw_json TEXT
            )
        """)
        incs = self.all()
        for inc in incs:
            cur.execute("""
                INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                inc.get("incident_id"),
                inc.get("priority"),
                inc.get("max_risk"),
                inc.get("asset"),
                inc.get("campaign_name"),
                json.dumps(inc.get("tactics", [])),
                len(inc.get("alert_ids", [])),
                inc.get("created"),
                inc.get("last_seen"),
                inc.get("summary"),
                inc.get("recommended_action"),
                json.dumps(inc),
            ))
        conn.commit()
        conn.close()
        logger.info("Exported %d incidents to %s", len(incs), db_path)
