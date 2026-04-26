from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _managed_connection(db_path: str | Path):
    connection = _connect(db_path)
    try:
        yield connection
    finally:
        connection.close()


def ensure_database(db_path: str | Path, demo_username: str, demo_password_hash: str) -> None:
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    with _managed_connection(db_file) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                code_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                issue_count INTEGER NOT NULL,
                severity_summary TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        existing_user = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (demo_username,),
        ).fetchone()
        if existing_user is None:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (demo_username, demo_password_hash, _utc_now()),
            )
        connection.commit()


def fetch_user(db_path: str | Path, username: str) -> dict | None:
    with _managed_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    return dict(row) if row else None


def record_scan(
    db_path: str | Path,
    source_type: str,
    target_name: str,
    code: str,
    status: str,
    findings: list[dict],
    severity_breakdown: dict,
) -> int:
    payload = json.dumps(findings)
    severity_payload = json.dumps(severity_breakdown)
    checksum = hashlib.sha256(code.encode("utf-8")).hexdigest()

    with _managed_connection(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (
                source_type,
                target_name,
                code_sha256,
                status,
                issue_count,
                severity_summary,
                findings_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_type,
                target_name,
                checksum,
                status,
                len(findings),
                severity_payload,
                payload,
                _utc_now(),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_scan_runs(db_path: str | Path, limit: int = 25) -> list[dict]:
    with _managed_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, source_type, target_name, code_sha256, status, issue_count,
                   severity_summary, created_at
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "source_type": row["source_type"],
            "target_name": row["target_name"],
            "code_sha256": row["code_sha256"],
            "status": row["status"],
            "issue_count": row["issue_count"],
            "severity_breakdown": json.loads(row["severity_summary"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_scan_run(db_path: str | Path, run_id: int) -> dict | None:
    with _managed_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, source_type, target_name, code_sha256, status, issue_count,
                   severity_summary, findings_json, created_at
            FROM scan_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "source_type": row["source_type"],
        "target_name": row["target_name"],
        "code_sha256": row["code_sha256"],
        "status": row["status"],
        "issue_count": row["issue_count"],
        "severity_breakdown": json.loads(row["severity_summary"]),
        "findings": json.loads(row["findings_json"]),
        "created_at": row["created_at"],
    }


def get_metrics(db_path: str | Path) -> dict:
    with _managed_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT status, issue_count, findings_json
            FROM scan_runs
            """
        ).fetchall()

    status_breakdown: dict[str, int] = {}
    rule_breakdown: dict[str, int] = {}
    total_findings = 0

    for row in rows:
        status_breakdown[row["status"]] = status_breakdown.get(row["status"], 0) + 1
        total_findings += int(row["issue_count"])
        for finding in json.loads(row["findings_json"]):
            rule_id = finding["id"]
            rule_breakdown[rule_id] = rule_breakdown.get(rule_id, 0) + 1

    return {
        "total_scans": len(rows),
        "total_findings": total_findings,
        "status_breakdown": status_breakdown,
        "rule_breakdown": rule_breakdown,
    }
