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


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_records.id"), nullable=True, index=True)
    rule_id = db.Column(db.String(80), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(32), nullable=False, index=True)
    cwe = db.Column(db.String(64))
    cvss = db.Column(db.Float, nullable=False, default=0.0)
    filename = db.Column(db.String(255))
    line = db.Column(db.Integer)
    message = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    excerpt = db.Column(db.Text)
    status = db.Column(db.String(32), nullable=False, default="open")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    format = db.Column(db.String(16), nullable=False)
    file_path = db.Column(db.String(500))
    summary_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(32), nullable=False, default="info")
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class Policy(db.Model):
    __tablename__ = "policies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    block_on_critical = db.Column(db.Boolean, nullable=False, default=True)
    block_on_high_count = db.Column(db.Integer, nullable=False, default=3)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class Threat(db.Model):
    __tablename__ = "threats"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(120), nullable=False, index=True)
    severity = db.Column(db.String(32), nullable=False, index=True)
    source = db.Column(db.String(120), nullable=False, default="scanner")
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class GitHubRepository(db.Model):
    __tablename__ = "github_repositories"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False, unique=True)
    default_branch = db.Column(db.String(120))
    private = db.Column(db.Boolean, nullable=False, default=False)
    html_url = db.Column(db.String(500))
    last_scan_status = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
