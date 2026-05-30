from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any


def build_report_summary(storage) -> dict[str, Any]:
    metrics = storage.get_dashboard_metrics()
    scans = storage.list_recent_scans(limit=200)
    gate = storage.evaluate_policy_gate()
    return {
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "project": "SecureGPT - AI Powered DevSecOps Pipeline",
        "metrics": metrics,
        "policy_gate": gate,
        "recent_scans": scans,
        "threats": storage.list_threats(limit=50),
    }


def render_json(summary: dict[str, Any]) -> tuple[bytes, str]:
    return json.dumps(summary, indent=2, default=str).encode("utf-8"), "application/json"


def render_csv(summary: dict[str, Any]) -> tuple[bytes, str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["scan_id", "target", "status", "finding_id", "severity", "line", "message"])
    for scan in summary.get("recent_scans", []):
        findings = scan.get("findings") or [{}]
        for finding in findings:
            writer.writerow(
                [
                    scan.get("id"),
                    scan.get("target_name"),
                    scan.get("status"),
                    finding.get("id", ""),
                    finding.get("severity", ""),
                    finding.get("line", ""),
                    finding.get("message", ""),
                ]
            )
    return buffer.getvalue().encode("utf-8"), "text/csv"


def render_pdf(summary: dict[str, Any]) -> tuple[bytes, str]:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        text = _plain_report(summary)
        return text.encode("utf-8"), "application/pdf"

    buffer = io.BytesIO()
    page = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 48
    page.setFont("Helvetica-Bold", 16)
    page.drawString(48, y, "SecureGPT Security Report")
    y -= 28
    page.setFont("Helvetica", 10)
    for line in _plain_report(summary).splitlines():
        if y < 48:
            page.showPage()
            y = height - 48
            page.setFont("Helvetica", 10)
        page.drawString(48, y, line[:110])
        y -= 15
    page.save()
    return buffer.getvalue(), "application/pdf"


def _plain_report(summary: dict[str, Any]) -> str:
    metrics = summary.get("metrics", {})
    gate = summary.get("policy_gate", {})
    lines = [
        f"Project: {summary.get('project')}",
        f"Generated: {summary.get('generated_at')}",
        f"Total scans: {metrics.get('total_scans', 0)}",
        f"Total findings: {metrics.get('total_findings', 0)}",
        f"Critical/high gate: {gate.get('status', 'unknown')}",
        "",
        "Recent scans:",
    ]
    for scan in summary.get("recent_scans", [])[:25]:
        lines.append(f"- {scan.get('target_name')} | {scan.get('status')} | {scan.get('finding_count')} finding(s)")
    return "\n".join(lines)
