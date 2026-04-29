from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import Employee, ScanRecord, User, db


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _serialize_scan(
    scan_id: str,
    target_name: str,
    status: str,
    finding_count: int,
    findings: list[dict[str, Any]],
    created_at: datetime,
) -> dict[str, Any]:
    timestamp = created_at.replace(microsecond=0)
    return {
        "id": str(scan_id),
        "target_name": target_name,
        "status": status,
        "finding_count": int(finding_count),
        "issue_count": int(finding_count),
        "findings": findings,
        "timestamp": timestamp.isoformat(),
        "created_at": timestamp.isoformat(),
        "display_timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_type": "manual",
    }


def _build_scan_stats(scans: list[dict[str, Any]]) -> dict[str, Any]:
    total_scans = len(scans)
    passed_scans = sum(1 for scan in scans if scan["status"] == "passed")
    needs_attention_scans = sum(1 for scan in scans if scan["status"] == "needs_attention")
    failed_scans = sum(1 for scan in scans if scan["status"] == "failed")
    total_findings = sum(int(scan["finding_count"]) for scan in scans)
    success_rate = round((passed_scans / total_scans) * 100, 1) if total_scans else 0.0

    return {
        "total_scans": total_scans,
        "passed_scans": passed_scans,
        "needs_attention_scans": needs_attention_scans,
        "failed_scans": failed_scans,
        "total_findings": total_findings,
        "success_rate": success_rate,
        "last_updated": _utc_now().replace(microsecond=0).isoformat(),
    }


def _build_chart_data(scans: list[dict[str, Any]], days: int = 7) -> dict[str, Any]:
    today = _utc_now().date()
    start_day = today - timedelta(days=days - 1)
    bucket = {
        day: {"findings": 0, "scans": 0, "passed": 0}
        for day in (start_day + timedelta(days=offset) for offset in range(days))
    }

    for scan in scans:
        scan_day = datetime.fromisoformat(scan["timestamp"]).date()
        if scan_day in bucket:
            bucket[scan_day]["findings"] += int(scan["finding_count"])
            bucket[scan_day]["scans"] += 1
            if scan["status"] == "passed":
                bucket[scan_day]["passed"] += 1

    ordered_days = sorted(bucket)
    return {
        "labels": [day.strftime("%d %b") for day in ordered_days],
        "findings": [bucket[day]["findings"] for day in ordered_days],
        "scans": [bucket[day]["scans"] for day in ordered_days],
        "passed": [bucket[day]["passed"] for day in ordered_days],
    }


def _build_dashboard_metrics(scans: list[dict[str, Any]]) -> dict[str, Any]:
    stats = _build_scan_stats(scans)
    rule_breakdown: dict[str, int] = {}
    severity_breakdown: dict[str, int] = {}
    status_breakdown: dict[str, int] = {}

    for scan in scans:
        status_breakdown[scan["status"]] = status_breakdown.get(scan["status"], 0) + 1
        for finding in scan.get("findings", []):
            rule_breakdown[finding["id"]] = rule_breakdown.get(finding["id"], 0) + 1
            severity = finding.get("severity", "unknown")
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

    stats["rule_breakdown"] = rule_breakdown
    stats["severity_breakdown"] = severity_breakdown
    stats["status_breakdown"] = status_breakdown
    return stats


@dataclass
class MongoUser(UserMixin):
    id: str
    username: str
    password_hash: str

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "MongoUser":
        return cls(
            id=str(document["_id"]),
            username=document["username"],
            password_hash=document["password_hash"],
        )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@dataclass
class MongoEmployee:
    id: str
    name: str
    role: str
    department: str

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "MongoEmployee":
        return cls(
            id=str(document["_id"]),
            name=document["name"],
            role=document["role"],
            department=document["department"],
        )


class SQLStorage:
    backend_name = "sql"

    def init_app(self, app) -> None:
        db.init_app(app)
        with app.app_context():
            db.create_all()

    def get_user_by_id(self, user_id: str) -> User | None:
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    def get_user_by_username(self, username: str) -> User | None:
        return User.query.filter_by(username=username).first()

    def create_user(self, username: str, password: str) -> User:
        if self.get_user_by_username(username):
            raise ValueError("Username already exists")

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def list_employees(self) -> list[Employee]:
        return Employee.query.order_by(Employee.name.asc()).all()

    def create_scan_record(self, filename: str, result: dict[str, Any]) -> dict[str, Any]:
        record = ScanRecord(
            target_name=filename,
            status=result["status"],
            finding_count=int(result["finding_count"]),
        )
        record.set_findings(result.get("findings", []))
        db.session.add(record)
        db.session.commit()
        return self._serialize_record(record)

    def list_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        query = ScanRecord.query.order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
        return [self._serialize_record(record) for record in query.limit(limit).all()]

    def get_scan_by_id(self, scan_id: str) -> dict[str, Any] | None:
        try:
            record = db.session.get(ScanRecord, int(scan_id))
        except (TypeError, ValueError):
            return None
        return self._serialize_record(record) if record else None

    def get_scan_stats(self) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_scan_stats(scans)

    def get_dashboard_metrics(self) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_dashboard_metrics(scans)

    def get_scan_chart_data(self, days: int = 7) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_chart_data(scans, days=days)

    def ensure_demo_user(
        self,
        username: str,
        *,
        password: str | None = None,
        password_hash: str | None = None,
    ) -> User:
        existing_user = self.get_user_by_username(username)
        if existing_user:
            return existing_user

        user = User(username=username)
        if password_hash:
            user.password_hash = password_hash
        else:
            user.set_password(password or "password")

        db.session.add(user)
        db.session.commit()
        return user

    def healthcheck(self) -> dict[str, Any]:
        return {"backend": self.backend_name, "connected": True}

    @staticmethod
    def _serialize_record(record: ScanRecord) -> dict[str, Any]:
        return _serialize_scan(
            scan_id=str(record.id),
            target_name=record.target_name,
            status=record.status,
            finding_count=record.finding_count,
            findings=record.findings,
            created_at=record.created_at,
        )


class MongoStorage:
    backend_name = "mongo"

    def __init__(self) -> None:
        self.client = None
        self.database = None
        self.users = None
        self.employees = None
        self.scans = None

    def init_app(self, app) -> None:
        uri = app.config.get("MONGODB_URI")
        if not uri:
            raise RuntimeError("MONGODB_URI is required when DATA_BACKEND is set to 'mongo'.")

        database_name = app.config.get("MONGODB_DB_NAME") or self._database_name_from_uri(uri)
        timeout_ms = int(app.config.get("MONGODB_TIMEOUT_MS", 2000))

        if uri.startswith("mongomock://"):
            import mongomock

            self.client = mongomock.MongoClient()
        else:
            from pymongo import MongoClient

            self.client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
            try:
                self.client.admin.command("ping")
            except Exception as exc:
                raise RuntimeError(f"MongoDB connection failed: {exc}") from exc

        self.database = self.client[database_name]
        self.users = self.database["users"]
        self.employees = self.database["employees"]
        self.scans = self.database["scans"]
        self.users.create_index("username", unique=True)
        self.scans.create_index("created_at")

    def get_user_by_id(self, user_id: str) -> MongoUser | None:
        object_id = self._object_id(user_id)
        if object_id is None:
            return None

        document = self.users.find_one({"_id": object_id})
        return MongoUser.from_document(document) if document else None

    def get_user_by_username(self, username: str) -> MongoUser | None:
        document = self.users.find_one({"username": username})
        return MongoUser.from_document(document) if document else None

    def create_user(self, username: str, password: str) -> MongoUser:
        if self.get_user_by_username(username):
            raise ValueError("Username already exists")

        inserted = self.users.insert_one(
            {"username": username, "password_hash": generate_password_hash(password)}
        )
        return self.get_user_by_id(str(inserted.inserted_id))

    def list_employees(self) -> list[MongoEmployee]:
        return [MongoEmployee.from_document(document) for document in self.employees.find().sort("name", 1)]

    def create_scan_record(self, filename: str, result: dict[str, Any]) -> dict[str, Any]:
        created_at = _utc_now()
        inserted = self.scans.insert_one(
            {
                "target_name": filename,
                "status": result["status"],
                "finding_count": int(result["finding_count"]),
                "findings": result.get("findings", []),
                "created_at": created_at,
            }
        )
        return _serialize_scan(
            scan_id=str(inserted.inserted_id),
            target_name=filename,
            status=result["status"],
            finding_count=int(result["finding_count"]),
            findings=result.get("findings", []),
            created_at=created_at,
        )

    def list_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        documents = self.scans.find().sort("created_at", -1).limit(limit)
        return [self._serialize_document(document) for document in documents]

    def get_scan_by_id(self, scan_id: str) -> dict[str, Any] | None:
        object_id = self._object_id(scan_id)
        if object_id is None:
            return None

        document = self.scans.find_one({"_id": object_id})
        return self._serialize_document(document) if document else None

    def get_scan_stats(self) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_scan_stats(scans)

    def get_dashboard_metrics(self) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_dashboard_metrics(scans)

    def get_scan_chart_data(self, days: int = 7) -> dict[str, Any]:
        scans = self.list_recent_scans(limit=1000)
        return _build_chart_data(scans, days=days)

    def ensure_demo_user(
        self,
        username: str,
        *,
        password: str | None = None,
        password_hash: str | None = None,
    ) -> MongoUser:
        existing_user = self.get_user_by_username(username)
        if existing_user:
            return existing_user

        inserted = self.users.insert_one(
            {
                "username": username,
                "password_hash": password_hash or generate_password_hash(password or "password"),
            }
        )
        return self.get_user_by_id(str(inserted.inserted_id))

    def healthcheck(self) -> dict[str, Any]:
        try:
            self.client.admin.command("ping")
            connected = True
        except Exception:
            connected = False

        return {"backend": self.backend_name, "connected": connected}

    @staticmethod
    def _database_name_from_uri(uri: str) -> str:
        parsed = urlparse(uri)
        database_name = parsed.path.lstrip("/")
        if database_name:
            return database_name.split("/", 1)[0]
        return "devsecops"

    @staticmethod
    def _object_id(value: str):
        from bson import ObjectId
        from bson.errors import InvalidId

        try:
            return ObjectId(str(value))
        except (InvalidId, TypeError, ValueError):
            return None

    @staticmethod
    def _serialize_document(document: dict[str, Any]) -> dict[str, Any]:
        return _serialize_scan(
            scan_id=str(document["_id"]),
            target_name=document["target_name"],
            status=document["status"],
            finding_count=document["finding_count"],
            findings=document.get("findings", []),
            created_at=document["created_at"],
        )


def create_storage(app_config) -> SQLStorage | MongoStorage:
    backend = str(app_config.get("DATA_BACKEND", "auto")).lower()
    mongodb_uri = app_config.get("MONGODB_URI")

    if backend == "mongo" or (backend == "auto" and mongodb_uri):
        return MongoStorage()

    return SQLStorage()


def get_storage() -> SQLStorage | MongoStorage:
    return current_app.extensions["storage"]
