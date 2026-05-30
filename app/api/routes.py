from __future__ import annotations

from io import BytesIO
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request, send_file
from flask_login import login_required
from werkzeug.utils import secure_filename

from app.realtime import emit_event
from app.services.github_service import list_repositories, repository_snapshot
from app.services.reports import build_report_summary, render_csv, render_json, render_pdf
from app.services.threats import classify_text, highest_severity
from app.storage import get_storage
from security.ai_remediation import generate_remediation
from security.scanner import is_safe_filename, scan_code, scan_repository_path

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _json_required() -> dict:
    if not request.is_json:
        raise ValueError("JSON request required.")
    return request.get_json() or {}


def _store_scan(target_name: str, result: dict) -> dict:
    storage = get_storage()
    scan = storage.create_scan_record(target_name, result)
    gate = storage.evaluate_policy_gate(scan)
    scan["policy_gate"] = gate
    severity = highest_severity(scan.get("findings", []))

    if scan.get("findings"):
        emit_event(
            "new_vulnerability",
            {
                "scan_id": scan["id"],
                "target_name": target_name,
                "finding_count": scan["finding_count"],
                "severity": severity,
            },
        )
    if gate["blocked"]:
        storage.create_notification(
            "blocked_deployment",
            "critical",
            "Deployment blocked",
            f"{target_name} failed the release policy gate.",
        )
        emit_event("blocked_deployment", gate | {"target_name": target_name})
    return scan


@api_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    try:
        if request.content_type and request.content_type.startswith("multipart/form-data"):
            uploaded = request.files.get("file")
            if not uploaded:
                return jsonify(status="error", message="file is required."), 400
            filename = secure_filename(uploaded.filename or "")
            if not filename or not is_safe_filename(filename):
                return jsonify(status="error", message="Invalid filename."), 400
            code = uploaded.read().decode("utf-8", errors="replace")
            return jsonify(_store_scan(filename, scan_code(code, filename)))

        data = _json_required()
        repo_path = (data.get("repo_path") or "").strip()
        if repo_path:
            root = Path(current_app.config["SCAN_ROOT"]).resolve()
            candidate = Path(repo_path).resolve()
            if root not in candidate.parents and candidate != root:
                return jsonify(status="error", message="Repository path is outside SCAN_ROOT."), 400
            return jsonify(_store_scan(candidate.name, scan_repository_path(str(candidate))))

        filename = (data.get("filename") or data.get("file_path") or "").strip()
        code = data.get("code") or ""
        if not filename or not code:
            return jsonify(status="error", message="Missing code or filename."), 400
        if not is_safe_filename(filename):
            return jsonify(status="error", message="Invalid filename."), 400
        return jsonify(_store_scan(filename, scan_code(code, filename)))
    except Exception as exc:
        emit_event("failed_scan", {"message": str(exc)})
        return jsonify(status="error", message=str(exc)), 500


@api_bp.route("/remediation", methods=["POST"])
@login_required
def remediation():
    try:
        data = _json_required()
    except ValueError as exc:
        return jsonify(status="error", message=str(exc)), 400

    finding_id = data.get("finding_id") or data.get("vulnerability_type")
    if not finding_id:
        return jsonify(status="error", message="finding_id is required."), 400

    return jsonify(
        generate_remediation(
            code=data.get("code") or data.get("excerpt") or "",
            vulnerability_type=finding_id,
            title=data.get("title"),
            description=data.get("description"),
            recommendation=data.get("recommendation"),
            config=current_app.config,
        )
    )


@api_bp.route("/github", methods=["GET", "POST"])
@login_required
def github():
    storage = get_storage()
    if request.method == "GET":
        try:
            repos = list_repositories(limit=int(request.args.get("limit", 30)))
            stored = [storage.upsert_github_repo(repo) for repo in repos]
            return jsonify(status="ok", repositories=stored)
        except Exception as exc:
            return jsonify(status="error", message=str(exc), repositories=[]), 503

    data = request.get_json() or {}
    full_name = (data.get("repository") or data.get("full_name") or "").strip()
    if not full_name:
        return jsonify(status="error", message="repository is required."), 400
    try:
        snapshot = repository_snapshot(full_name)
        stored = storage.upsert_github_repo(snapshot)
        emit_event("github_repository_connected", stored)
        return jsonify(status="ok", repository=stored, snapshot=snapshot)
    except Exception as exc:
        return jsonify(status="error", message=str(exc)), 503


@api_bp.route("/reports", methods=["GET"])
@login_required
def reports():
    summary = build_report_summary(get_storage())
    return jsonify(status="ok", report=summary)


@api_bp.route("/reports/<report_format>", methods=["GET"])
@login_required
def download_report(report_format: str):
    renderers = {"json": render_json, "csv": render_csv, "pdf": render_pdf}
    renderer = renderers.get(report_format.lower())
    if not renderer:
        return jsonify(status="error", message="Unsupported report format."), 400

    summary = build_report_summary(get_storage())
    payload, mimetype = renderer(summary)
    get_storage().create_report_record("SecureGPT Security Report", report_format.lower(), summary)
    filename = f"securegpt-security-report.{report_format.lower()}"
    return send_file(BytesIO(payload), mimetype=mimetype, as_attachment=True, download_name=filename)


@api_bp.route("/analytics", methods=["GET"])
@login_required
def analytics():
    storage = get_storage()
    metrics = storage.get_dashboard_metrics()
    return jsonify(
        status="ok",
        metrics=metrics,
        chart_data=storage.get_scan_chart_data(days=int(request.args.get("days", 7))),
        policy_gate=storage.evaluate_policy_gate(),
    )


@api_bp.route("/threats", methods=["GET", "POST"])
@login_required
def threats():
    storage = get_storage()
    if request.method == "GET":
        return jsonify(status="ok", threats=storage.list_threats(limit=50))

    data = request.get_json() or {}
    text = (data.get("text") or data.get("question") or "").strip()
    if not text:
        return jsonify(status="error", message="text is required."), 400
    classification = classify_text(text)
    threat = storage.create_threat(
        classification["category"],
        classification["severity"],
        f"{classification['category']} classified from analyst input",
        text,
        source="analyst",
    )
    emit_event("critical_threat", threat) if threat["severity"] == "critical" else None
    return jsonify(status="ok", classification=classification, threat=threat)


@api_bp.route("/policies", methods=["GET", "POST"])
@login_required
def policies():
    storage = get_storage()
    if request.method == "GET":
        return jsonify(status="ok", policies=storage.list_policies(), gate=storage.evaluate_policy_gate())
    return jsonify(status="ok", gate=storage.evaluate_policy_gate())


@api_bp.route("/notifications", methods=["GET"])
@login_required
def notifications():
    return jsonify(status="ok", notifications=get_storage().list_notifications(limit=50))
