from __future__ import annotations

import logging
import secrets
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if __package__ in {None, ""} and str(PROJECT_ROOT) not in sys.path:
    # Prefer the repository root so `python app/app.py` resolves the package correctly.
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, request, render_template
from prometheus_flask_exporter import PrometheusMetrics
from werkzeug.security import check_password_hash

from app.ai_service import generate_fix
from app.config import load_config
from app.scanner import get_rule_catalog, scan_code
from app.storage import ensure_database, fetch_user, get_metrics, get_scan_run, list_scan_runs, record_scan


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        recent_attempts = [
            timestamp
            for timestamp in self._attempts.get(key, [])
            if now - timestamp < self.window_seconds
        ]
        self._attempts[key] = recent_attempts
        if len(recent_attempts) >= self.max_attempts:
            retry_after = max(1, int(self.window_seconds - (now - recent_attempts[0])))
            return False, retry_after
        recent_attempts.append(now)
        self._attempts[key] = recent_attempts
        return True, 0

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


def _configure_logging(app: Flask) -> None:
    if app.config.get("TESTING"):
        return

    log_path = Path(app.config["LOG_PATH"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if not any(
        isinstance(handler, logging.FileHandler)
        and Path(getattr(handler, "baseFilename", "")).resolve() == log_path.resolve()
        for handler in app.logger.handlers
    ):
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)


def _error(message: str, status_code: int):
    return jsonify({"status": "error", "message": message}), status_code


def _resolve_scan_payload(app: Flask, payload: dict) -> tuple[str, str, str]:
    code = (payload.get("code") or "").strip()
    file_path = (payload.get("file_path") or "").strip()

    if not code and not file_path:
        raise ValueError("Provide either 'code' or 'file_path'.")

    if code:
        if len(code) > app.config["MAX_SCAN_LENGTH"]:
            raise ValueError("Submitted code exceeds MAX_SCAN_LENGTH.")
        return "inline", payload.get("filename") or "snippet.py", code

    scan_root = Path(app.config["SCAN_ROOT"]).resolve()
    candidate = (scan_root / file_path).resolve()
    if scan_root not in candidate.parents and candidate != scan_root:
        raise ValueError("file_path must stay inside SCAN_ROOT.")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"Unable to read file: {file_path}")

    code = candidate.read_text(encoding="utf-8")
    if len(code) > app.config["MAX_SCAN_LENGTH"]:
        raise ValueError("Requested file exceeds MAX_SCAN_LENGTH.")
    return "file", str(candidate.relative_to(scan_root)), code


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config(overrides))
    _configure_logging(app)
    ensure_database(
        app.config["DATABASE_PATH"],
        app.config["DEMO_USERNAME"],
        app.config["DEMO_PASSWORD_HASH"],
    )
    app.rate_limiter = RateLimiter(
        app.config["LOGIN_ATTEMPT_LIMIT"],
        app.config["LOGIN_WINDOW_SECONDS"],
    )

    # Initialize Prometheus Metrics Exporter
    metrics_exporter = PrometheusMetrics(app)
    metrics_exporter.info("app_info", "Application info", version="1.0.0")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def api_status():
        return jsonify(
            {
                "service": app.config["APP_NAME"],
                "status": "ok",
                "endpoints": [
                    "/health",
                    "/rules",
                    "/scan",
                    "/scans",
                    "/metrics",
                    "/fix",
                    "/login",
                ],
            }
        )

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "service": app.config["APP_NAME"],
                "database_path": app.config["DATABASE_PATH"],
                "scan_root": app.config["SCAN_ROOT"],
                "openai_enabled": bool(app.config["OPENAI_API_KEY"]),
            }
        )

    @app.get("/rules")
    def rules():
        return jsonify({"status": "ok", "rules": get_rule_catalog()})

    @app.post("/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        if not username or not password:
            return _error("Both username and password are required.", 400)

        limiter_key = f"{request.remote_addr}:{username.lower()}"
        allowed, retry_after = app.rate_limiter.allow(limiter_key)
        if not allowed:
            response = jsonify(
                {
                    "status": "error",
                    "message": "Too many login attempts. Try again later.",
                    "retry_after_seconds": retry_after,
                }
            )
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response

        user = fetch_user(app.config["DATABASE_PATH"], username)
        app.logger.info("Login attempt for username=%s from ip=%s", username, request.remote_addr)

        if not user or not check_password_hash(user["password_hash"], password):
            app.logger.warning("Login failed for username=%s", username)
            return _error("Invalid credentials.", 401)

        app.rate_limiter.reset(limiter_key)
        token = secrets.token_urlsafe(24)
        app.logger.info("Login succeeded for username=%s", username)
        return jsonify(
            {
                "status": "ok",
                "message": "Login successful.",
                "session_token": token,
                "user": {"username": username},
            }
        )

    @app.post("/scan")
    def scan():
        payload = request.get_json(silent=True) or {}
        try:
            source_type, target_name, code = _resolve_scan_payload(app, payload)
        except FileNotFoundError as exc:
            return _error(str(exc), 404)
        except ValueError as exc:
            return _error(str(exc), 400)
        except UnicodeDecodeError:
            return _error("Only UTF-8 text files can be scanned.", 400)

        scan_result = scan_code(code, target_name=target_name)
        scan_id = record_scan(
            app.config["DATABASE_PATH"],
            source_type=source_type,
            target_name=target_name,
            code=code,
            status=scan_result["status"],
            findings=scan_result["findings"],
            severity_breakdown=scan_result["severity_breakdown"],
        )
        app.logger.info(
            "Recorded scan id=%s target=%s findings=%s",
            scan_id,
            target_name,
            scan_result["finding_count"],
        )
        return jsonify(
            {
                "status": "ok",
                "scan_id": scan_id,
                "source_type": source_type,
                **scan_result,
            }
        )

    @app.get("/scans")
    def scans():
        try:
            limit = min(
                max(int(request.args.get("limit", app.config["SCAN_RESULT_LIMIT"])), 1),
                100,
            )
        except ValueError:
            return _error("limit must be an integer.", 400)
        return jsonify(
            {
                "status": "ok",
                "scans": list_scan_runs(app.config["DATABASE_PATH"], limit=limit),
            }
        )

    @app.get("/scans/<int:run_id>")
    def scan_detail(run_id: int):
        run = get_scan_run(app.config["DATABASE_PATH"], run_id)
        if run is None:
            return _error("Scan result not found.", 404)
        return jsonify({"status": "ok", "scan": run})

    @app.get("/metrics")
    def metrics():
        metrics_payload = get_metrics(app.config["DATABASE_PATH"])
        metrics_payload["openai_enabled"] = bool(app.config["OPENAI_API_KEY"])
        return jsonify({"status": "ok", "metrics": metrics_payload})

    @app.post("/fix")
    def fix():
        payload = request.get_json(silent=True) or {}
        title = (payload.get("title") or "").strip()
        description = (payload.get("description") or "").strip()
        finding_id = payload.get("finding_id")
        code = payload.get("code") or ""

        if code and not title:
            scan_result = scan_code(code, target_name=payload.get("filename") or "snippet.py")
            if scan_result["findings"]:
                primary = scan_result["findings"][0]
                finding_id = finding_id or primary["id"]
                title = primary["title"]
                description = description or primary["description"]

        if not title:
            return _error("Provide a title or a code snippet to analyze.", 400)

        fix_payload = generate_fix(
            finding_id=finding_id,
            title=title,
            description=description or "Provide secure remediation guidance.",
            code=code,
            api_key=app.config["OPENAI_API_KEY"],
            model=app.config["OPENAI_MODEL"],
        )
        return jsonify(
            {
                "status": "ok",
                "finding_id": finding_id,
                "title": title,
                "description": description,
                **fix_payload,
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
