from __future__ import annotations

import json
import re
import subprocess
import sys

RULE_CATALOG = [
    {
        "id": "SQLI001",
        "title": "SQL Injection",
        "severity": "high",
        "cwe": "CWE-89",
        "description": "Untrusted input is interpolated directly into a SQL query.",
        "recommendation": "Use parameterized queries and pass user input separately from the SQL string.",
    },
    {
        "id": "CMDI001",
        "title": "Command Injection",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "User-controlled input is reaching a shell command or shell-enabled subprocess call.",
        "recommendation": "Avoid shell=True and os.system. Validate input and pass command arguments as a list.",
    },
    {
        "id": "EXEC001",
        "title": "Dynamic Code Execution",
        "severity": "critical",
        "cwe": "CWE-94",
        "description": "Dangerous dynamic execution function is invoked on potentially untrusted data.",
        "recommendation": "Remove eval or exec on untrusted data. Use structured parsing instead.",
    },
    {
        "id": "DESER001",
        "title": "Unsafe Deserialization",
        "severity": "high",
        "cwe": "CWE-502",
        "description": "Unsafe deserialization function can execute attacker-controlled payloads.",
        "recommendation": "Avoid pickle.loads and unsafe yaml.load. Prefer safe, schema-validated formats.",
    },
    {
        "id": "SECRET001",
        "title": "Hardcoded Secret",
        "severity": "medium",
        "cwe": "CWE-798",
        "description": "Secret-like value appears to be hardcoded in source code.",
        "recommendation": "Move secrets to environment variables or a secrets manager and rotate exposed values.",
    },
]

RULE_INDEX = {rule["id"]: rule for rule in RULE_CATALOG}


def run_bandit():
    print("Running Bandit SAST...")
    cmd = [sys.executable, "-m", "bandit", "-r", "app/", "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error parsing Bandit output")
        return {}


def run_semgrep():
    print("Running Semgrep SAST...")
    cmd = ["semgrep", "--config", "auto", "app/", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error parsing Semgrep output")
        return {}


def get_rule_catalog():
    return RULE_CATALOG


def is_safe_filename(filename: str) -> bool:
    if not filename or not filename.strip():
        return False

    candidate = filename.strip()
    if ".." in candidate or "/" in candidate or "\\" in candidate:
        return False
    return True


def _build_finding(rule_id: str, filename: str, line: int, message: str, excerpt: str | None = None):
    rule = RULE_INDEX[rule_id]
    return {
        "id": rule["id"],
        "title": rule["title"],
        "name": rule["title"],
        "severity": rule["severity"],
        "cwe": rule["cwe"],
        "description": rule["description"],
        "recommendation": rule["recommendation"],
        "message": message,
        "filename": filename,
        "line": line,
        "excerpt": excerpt or "",
    }


def _has_unsafe_yaml_load(line: str) -> bool:
    if "yaml.load(" not in line:
        return False
    return "SafeLoader" not in line


def scan_code(code, filename):
    findings = []
    seen = set()
    lines = code.splitlines()

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        matches = []
        if re.search(r"cursor\.execute\(\s*f['\"]", line) or re.search(r"cursor\.execute\([^)]*['\"][^'\"]*['\"]\s*\+", line):
            matches.append(
                (
                    "SQLI001",
                    "SQL query appears to be built using interpolation or string concatenation.",
                )
            )

        if re.search(r"subprocess\.(run|call|Popen|check_call|check_output)\([^)]*shell\s*=\s*True", line) or "os.system(" in line:
            matches.append(
                (
                    "CMDI001",
                    "Shell-enabled command execution detected.",
                )
            )

        if re.search(r"\b(eval|exec)\s*\(", line):
            matches.append(
                (
                    "EXEC001",
                    "Dynamic code execution detected.",
                )
            )

        if "pickle.loads(" in line or _has_unsafe_yaml_load(line):
            matches.append(
                (
                    "DESER001",
                    "Potentially unsafe deserialization call detected.",
                )
            )

        if re.search(
            r"\b(password|passwd|secret|secret_key|api_key|access_key|token)\b\s*=\s*['\"][^'\"]{6,}['\"]",
            line,
            flags=re.IGNORECASE,
        ):
            matches.append(
                (
                    "SECRET001",
                    "Hardcoded secret-like value detected in source code.",
                )
            )

        for rule_id, message in matches:
            key = (rule_id, line_no, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_build_finding(rule_id, filename, line_no, message, excerpt=line))

    findings.sort(key=lambda item: (item["line"], item["id"]))
    return {
        "status": "needs_attention" if findings else "passed",
        "finding_count": len(findings),
        "findings": findings,
    }


if __name__ == "__main__":
    bandit_results = run_bandit()
    semgrep_results = run_semgrep()

    with open("bandit_report.json", "w") as f:
        json.dump(bandit_results, f, indent=2)

    with open("semgrep_report.json", "w") as f:
        json.dump(semgrep_results, f, indent=2)

    print("Security scans completed. Reports saved.")
