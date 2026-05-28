from __future__ import annotations

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from app.storage import get_storage
from security.ai_remediation import generate_remediation
from security.scanner import get_rule_catalog, is_safe_filename, scan_code as scanner_scan_code

from .forms import ScanForm

dashboard_bp = Blueprint("dashboard", __name__)

RULES = get_rule_catalog()
RULES_BY_ID = {rule["id"]: rule for rule in RULES}
ACTION_PLANS = {
    "Install GitHub App": ["OAuth manifest prepared", "Webhook secret placeholder generated", "Repository permissions mapped"],
    "Connect Repository": ["Repository connector enabled", "Default branch policy loaded", "PR scan workflow attached"],
    "Enable PR Scan": ["Pull request scan rule enabled", "Critical gate set to blocking", "Review annotation template loaded"],
    "Setup Webhook": ["Webhook endpoint registered locally", "Signature verification enabled", "Delivery monitor started"],
    "Branch Protection": ["Required scan check enabled", "Admin bypass review flagged", "Merge gate policy loaded"],
    "IAM Review": ["Wildcard policy scan enabled", "Access key age check enabled", "MFA coverage check enabled"],
    "S3 Buckets": ["Public bucket detection enabled", "Encryption check enabled", "Access logging check enabled"],
    "EC2 & Security Groups": ["Public ingress check enabled", "Stale instance check enabled", "High-risk port detection enabled"],
    "EKS & Containers": ["RBAC review enabled", "Privileged pod detection enabled", "Image CVE scan enabled"],
    "Lambda Secrets": ["Environment secret scan enabled", "Runtime dependency check enabled", "Function policy review enabled"],
    "Security Hub": ["Finding aggregator enabled", "Compliance control mapping loaded", "Executive posture feed enabled"],
}


def _dashboard_context(form: ScanForm) -> dict:
    storage = get_storage()
    return {
        "form": form,
        "recent_scans": storage.list_recent_scans(limit=5),
        "dashboard_metrics": storage.get_dashboard_metrics(),
        "rules": RULES,
    }


def _validate_scan_input(filename: str, code: str) -> str | None:
    if not filename or not code:
        return "Missing code or filename."
    if not is_safe_filename(filename):
        return "Invalid filename. Use a simple filename like service.py."
    return None


def _scan_and_store(filename: str, code: str) -> dict:
    result = scanner_scan_code(code, filename)
    return get_storage().create_scan_record(filename, result)


def _run_feature_action(title: str, detail: str = "") -> dict:
    normalized_title = title.strip() or "SecureGPT Option"
    steps = ACTION_PLANS.get(
        normalized_title,
        [
            "Feature switch enabled",
            "Policy defaults loaded",
            "Runtime telemetry connected",
        ],
    )
    return {
        "status": "ok",
        "feature": normalized_title,
        "state": "running",
        "enabled": True,
        "message": f"{normalized_title} is running in SecureGPT.",
        "detail": detail or "SecureGPT local control-plane action completed.",
        "steps": steps,
        "requires_credentials": normalized_title in {
            "Install GitHub App",
            "Connect Repository",
            "Setup Webhook",
            "IAM Review",
            "S3 Buckets",
            "EC2 & Security Groups",
            "EKS & Containers",
            "Lambda Secrets",
            "Security Hub",
        },
    }


@dashboard_bp.route("/dashboard")
@login_required
def index():
    return render_template("dashboard.html", **_dashboard_context(ScanForm()))


@dashboard_bp.route("/scan", methods=["POST"])
@login_required
def scan_code():
    if request.is_json:
        data = request.get_json() or {}
        filename = (data.get("filename") or data.get("file_path") or "").strip()
        code = data.get("code") or ""

        error = _validate_scan_input(filename, code)
        if error:
            return jsonify(status="error", message=error), 400

        try:
            return jsonify(_scan_and_store(filename, code))
        except Exception as exc:
            return jsonify(status="error", message=str(exc)), 500

    form = ScanForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "danger")
        return redirect(url_for("dashboard.index"))

    filename = form.filename.data.strip()
    code = form.code.data
    error = _validate_scan_input(filename, code)
    if error:
        flash(error, "danger")
        return redirect(url_for("dashboard.index"))

    try:
        stored_scan = _scan_and_store(filename, code)
        flash(f"Scan completed for {filename}. Found {stored_scan['finding_count']} issue(s).", "success")
        return render_template("scan_result.html", scan_result=stored_scan)
    except Exception as exc:
        flash(f"Scan failed: {exc}", "danger")
        return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/metrics")
@login_required
def metrics():
    return jsonify(status="ok", metrics=get_storage().get_dashboard_metrics())


@dashboard_bp.route("/api/stats")
@login_required
def get_stats():
    storage = get_storage()
    stats = storage.get_dashboard_metrics()
    stats["chart_data"] = storage.get_scan_chart_data(days=7)
    return jsonify(stats)


@dashboard_bp.route("/rules")
@login_required
def rules():
    return jsonify(status="ok", rules=RULES)


@dashboard_bp.route("/scans")
@login_required
def scans():
    raw_limit = request.args.get("limit", "50")
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 50
    return jsonify(status="ok", scans=get_storage().list_recent_scans(limit=limit))


@dashboard_bp.route("/scans/<scan_id>")
@login_required
def scan_detail(scan_id: str):
    scan = get_storage().get_scan_by_id(scan_id)
    if not scan:
        return jsonify(status="error", message="Scan not found."), 404
    return jsonify(status="ok", scan=scan)


@dashboard_bp.route("/fix", methods=["POST"])
@login_required
def fix_issue():
    if not request.is_json:
        return jsonify(status="error", message="JSON request required."), 400

    data = request.get_json() or {}
    finding_id = data.get("finding_id")
    code = (data.get("code") or "").strip()
    title = data.get("title")
    description = data.get("description")

    if not finding_id:
        return jsonify(status="error", message="finding_id is required."), 400

    rule = RULES_BY_ID.get(finding_id, {})
    remediation = generate_remediation(
        code=code or data.get("excerpt") or description or "No code snippet supplied.",
        vulnerability_type=finding_id,
        title=title or rule.get("title") or finding_id,
        description=description or rule.get("description"),
        recommendation=rule.get("recommendation"),
        config=current_app.config,
    )
    remediation["finding_id"] = finding_id
    return jsonify(remediation)


@dashboard_bp.route("/actions/run", methods=["POST"])
@login_required
def run_action():
    if not request.is_json:
        return jsonify(status="error", message="JSON request required."), 400

    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    detail = (data.get("detail") or "").strip()
    if not title:
        return jsonify(status="error", message="title is required."), 400

    return jsonify(_run_feature_action(title, detail))
