from __future__ import annotations


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def classify_text(text: str) -> dict:
    value = text.lower()
    category = "Security Best Practice"
    severity = "low"

    rules = [
        ("sql", "SQL Injection", "high"),
        ("injection", "Injection", "high"),
        ("eval", "Dynamic Code Execution", "critical"),
        ("exec", "Dynamic Code Execution", "critical"),
        ("shell=true", "Command Injection", "critical"),
        ("command", "Command Injection", "high"),
        ("pickle", "Unsafe Deserialization", "high"),
        ("yaml.load", "Unsafe Deserialization", "high"),
        ("secret", "Credential Exposure", "medium"),
        ("token", "Credential Exposure", "medium"),
        ("api key", "Credential Exposure", "medium"),
        ("critical", "Critical Vulnerability", "critical"),
        ("cve", "Known CVE", "high"),
    ]

    for marker, detected_category, detected_severity in rules:
        if marker in value and SEVERITY_ORDER[detected_severity] > SEVERITY_ORDER[severity]:
            category = detected_category
            severity = detected_severity

    guidance = {
        "critical": "Block deployment, isolate the affected path, and require security review before merge.",
        "high": "Prioritize remediation in the current sprint and add regression tests for the exploit class.",
        "medium": "Plan remediation, rotate exposed credentials when needed, and monitor for recurrence.",
        "low": "Track as hardening work and document the accepted risk if deferred.",
    }[severity]

    return {
        "category": category,
        "severity": severity,
        "guidance": guidance,
    }


def highest_severity(findings: list[dict]) -> str:
    severities = [finding.get("severity", "info") for finding in findings]
    return max(severities or ["info"], key=lambda item: SEVERITY_ORDER.get(item, 0))
