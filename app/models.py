from __future__ import annotations

import json
from datetime import UTC, datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)


class ScanRecord(db.Model):
    __tablename__ = 'scan_records'

    id = db.Column(db.Integer, primary_key=True)
    target_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(32), nullable=False)
    finding_count = db.Column(db.Integer, nullable=False, default=0)
    findings_json = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)

    @property
    def findings(self) -> list[dict]:
        try:
            return json.loads(self.findings_json or "[]")
        except json.JSONDecodeError:
            return []

    def set_findings(self, findings: list[dict]) -> None:
        self.findings_json = json.dumps(findings)
