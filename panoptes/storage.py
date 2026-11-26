"""Case storage (Recon-ng-style workspaces): every investigation is saved to a local SQLite DB."""
from __future__ import annotations

import json
import sqlite3
import time

from panoptes.config import DATA_DIR
from panoptes.models import Report

DB = DATA_DIR / "cases.db"


def _conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, targets TEXT, notes TEXT,
        created REAL, findings INTEGER, report TEXT)""")
    return c


def save_case(report: Report, name: str | None = None, notes: str = "") -> int:
    name = name or report.meta.get("case") or ", ".join(t.value for t in report.targets)[:120]
    notes = notes or report.meta.get("notes", "")
    with _conn() as c:
        cur = c.execute("INSERT INTO cases (name, targets, notes, created, findings, report) VALUES (?,?,?,?,?,?)",
                        (name, json.dumps([str(t) for t in report.targets]), notes, time.time(),
                         len(report.findings), json.dumps(report.to_dict(), default=str)))
        return cur.lastrowid


def list_cases(limit: int = 100) -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT id, name, targets, notes, created, findings FROM cases ORDER BY id DESC LIMIT ?",
                         (limit,)).fetchall()
    return [{"id": r[0], "name": r[1], "targets": json.loads(r[2]), "notes": r[3], "created": r[4], "findings": r[5]}
            for r in rows]


def load_case(case_id: int) -> Report | None:
    with _conn() as c:
        row = c.execute("SELECT report FROM cases WHERE id = ?", (case_id,)).fetchone()
    return Report.from_dict(json.loads(row[0])) if row else None


def delete_case(case_id: int) -> bool:
    with _conn() as c:
        return c.execute("DELETE FROM cases WHERE id = ?", (case_id,)).rowcount > 0


def update_case(case_id: int, report: Report) -> None:
    """Rewrite a saved case after it was extended (transforms / added pivots)."""
    with _conn() as c:
        c.execute("UPDATE cases SET findings = ?, report = ?, targets = ? WHERE id = ?",
                  (len(report.findings), json.dumps(report.to_dict(), default=str),
                   json.dumps([str(t) for t in report.targets]), case_id))
