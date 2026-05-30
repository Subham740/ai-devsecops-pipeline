from __future__ import annotations

import ast
import json
import os
import re
import shutil
import site
import subprocess
import sys
import sysconfig
from pathlib import Path

RULE_CATALOG = [
    {
        "id": "SYNTAX001",
        "title": "Python Syntax Error",
        "severity": "high",
        "cwe": "N/A",
        "cvss": 6.5,
        "risk_weight": 7,
        "description": "The submitted Python code cannot be parsed because it contains invalid syntax.",
        "recommendation": "Fix the Python syntax error before relying on security scan results.",
    },
    {
        "id": "SQLI001",
        "title": "SQL Injection",
        "severity": "high",
        "cwe": "CWE-89",
        "cvss": 8.8,
        "risk_weight": 9,
        "description": "Untrusted input is interpolated directly into a SQL query.",
        "recommendation": "Use parameterized queries and pass user input separately from the SQL string.",
    },
    {
        "id": "CMDI001",
        "title": "Command Injection",
        "severity": "critical",
        "cwe": "CWE-78",
        "cvss": 9.8,
        "risk_weight": 10,
        "description": "User-controlled input is reaching a shell command or shell-enabled subprocess call.",
        "recommendation": "Avoid shell=True and os.system. Validate input and pass command arguments as a list.",
    },
    {
        "id": "EXEC001",
        "title": "Dynamic Code Execution",
        "severity": "critical",
        "cwe": "CWE-94",
        "cvss": 9.8,
        "risk_weight": 10,
        "description": "Dangerous dynamic execution function is invoked on potentially untrusted data.",
        "recommendation": "Remove eval or exec on untrusted data. Use structured parsing instead.",
    },
    {
        "id": "DESER001",
        "title": "Unsafe Deserialization",
        "severity": "high",
        "cwe": "CWE-502",
        "cvss": 8.1,
        "risk_weight": 8,
        "description": "Unsafe deserialization function can execute attacker-controlled payloads.",
        "recommendation": "Avoid pickle.loads and unsafe yaml.load. Prefer safe, schema-validated formats.",
    },
    {
        "id": "SECRET001",
        "title": "Hardcoded Secret",
        "severity": "medium",
        "cwe": "CWE-798",
        "cvss": 7.5,
        "risk_weight": 6,
        "description": "Secret-like value appears to be hardcoded in source code.",
        "recommendation": "Move secrets to environment variables or a secrets manager and rotate exposed values.",
    },
    {
        "id": "BANDIT001",
        "title": "Bandit SAST Finding",
        "severity": "medium",
        "cwe": "CWE-693",
        "cvss": 6.0,
        "risk_weight": 6,
        "description": "Bandit reported a Python security issue.",
        "recommendation": "Review the Bandit finding and replace risky APIs with secure alternatives.",
    },
    {
        "id": "DEPS001",
        "title": "Dependency Vulnerability",
        "severity": "high",
        "cwe": "CWE-1104",
        "cvss": 8.0,
        "risk_weight": 8,
        "description": "A dependency scanner reported a vulnerable package.",
        "recommendation": "Upgrade to a patched package version and rebuild the artifact.",
    },
]

RULE_INDEX = {rule["id"]: rule for rule in RULE_CATALOG}


def _script_directories() -> list[Path]:
    candidates: list[Path] = []
    script_path = sysconfig.get_path("scripts")
    if script_path:
        candidates.append(Path(script_path))

    user_base = site.getuserbase()
    if user_base:
        candidates.append(Path(user_base) / ("Scripts" if sys.platform.startswith("win") else "bin"))

    user_site = site.getusersitepackages()
    if user_site:
        user_site_parent = Path(user_site).resolve().parent
        candidates.append(user_site_parent / ("Scripts" if sys.platform.startswith("win") else "bin"))

    executable_dir = Path(sys.executable).resolve().parent
    candidates.append(executable_dir)
    candidates.append(executable_dir / ("Scripts" if sys.platform.startswith("win") else "bin"))

    unique_candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        unique_candidates.append(candidate)
    return unique_candidates


def _resolve_cli(tool_name: str) -> str:
    resolved = shutil.which(tool_name)
    if resolved:
        return resolved

    names = [tool_name]
    if sys.platform.startswith("win"):
        names = [f"{tool_name}.exe", f"{tool_name}.cmd", f"{tool_name}.bat", tool_name]

    for directory in _script_directories():
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return str(candidate)

    raise FileNotFoundError(
        f"Required CLI tool '{tool_name}' was not found. Install it and ensure its scripts directory is available."
    )


def _run_json_command(label: str, cmd: list[str]) -> dict:
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    if result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    error_message = result.stderr.strip() or result.stdout.strip() or f"{label} produced no JSON output."
    print(f"{label} scan error: {error_message}")
    return {"status": "error", "tool": label.lower(), "error": error_message}


def _normalize_bandit_findings(payload: dict, filename: str) -> list[dict]:
    findings: list[dict] = []
    for issue in payload.get("results", []) or []:
        severity = str(issue.get("issue_severity", "medium")).lower()
        finding = _build_finding(
            "BANDIT001",
            issue.get("filename") or filename,
            int(issue.get("line_number") or 1),
            issue.get("issue_text") or "Bandit security issue detected.",
            excerpt=issue.get("code"),
        )
        if severity in {"low", "medium", "high"}:
            finding["severity"] = severity
        findings.append(finding)
    return findings


def run_bandit():
    print("Running Bandit SAST...")
    try:
        cmd = [_resolve_cli("bandit"), "-r", "app/", "-f", "json"]
    except FileNotFoundError as exc:
        print(str(exc))
        return {"status": "error", "tool": "bandit", "error": str(exc)}
    return _run_json_command("Bandit", cmd)


def run_bandit_path(path: str) -> dict:
    try:
        cmd = [_resolve_cli("bandit"), "-r", path, "-f", "json"]
    except FileNotFoundError as exc:
        return {"status": "error", "tool": "bandit", "error": str(exc)}
    return _run_json_command("Bandit", cmd)


def run_dependency_scan(requirements_path: str = "requirements.txt") -> dict:
    path = Path(requirements_path)
    if not path.is_file():
        return {"status": "skipped", "tool": "dependencies", "error": "requirements.txt not found."}

    try:
        audit_cli = _resolve_cli("pip-audit")
        return _run_json_command("pip-audit", [audit_cli, "-r", str(path), "-f", "json"])
    except FileNotFoundError:
        try:
            safety_cli = _resolve_cli("safety")
            return _run_json_command("Safety", [safety_cli, "check", "-r", str(path), "--json"])
        except FileNotFoundError as exc:
            return {"status": "error", "tool": "dependencies", "error": str(exc)}


def run_semgrep():
    print("Running Semgrep SAST...")
    try:
        try:
            semgrep_cli = _resolve_cli("pysemgrep")
        except FileNotFoundError:
            semgrep_cli = _resolve_cli("semgrep")
        config_path = "semgrep.yml" if Path("semgrep.yml").is_file() else "auto"
        targets = ["app/"]
        if Path("sample-java-spring-boot").is_dir():
            targets.append("sample-java-spring-boot/")
        cmd = [semgrep_cli, "--config", config_path, *targets, "--json"]
    except FileNotFoundError as exc:
        print(str(exc))
        return {"status": "error", "tool": "semgrep", "error": str(exc)}
    return _run_json_command("Semgrep", cmd)


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
        "cvss": rule["cvss"],
        "risk_weight": rule["risk_weight"],
        "description": rule["description"],
        "recommendation": rule["recommendation"],
        "message": message,
        "filename": filename,
        "line": line,
        "excerpt": excerpt or "",
    }


def _syntax_finding(code: str, filename: str) -> dict | None:
    try:
        ast.parse(code, filename=filename)
    except SyntaxError as exc:
        line_no = exc.lineno or 1
        lines = code.splitlines()
        excerpt = exc.text.strip() if exc.text else ""
        if not excerpt and 1 <= line_no <= len(lines):
            excerpt = lines[line_no - 1].strip()

        detail = exc.msg or "Invalid Python syntax."
        if exc.offset:
            detail = f"{detail} at column {exc.offset}."

        return _build_finding(
            "SYNTAX001",
            filename,
            line_no,
            f"Python syntax error: {detail}",
            excerpt=excerpt,
        )
    return None


def _has_unsafe_yaml_load(line: str) -> bool:
    if "yaml.load(" not in line:
        return False
    return "SafeLoader" not in line


def scan_code(code, filename):
    findings = []
    seen = set()
    lines = code.splitlines()

    syntax_issue = _syntax_finding(code, filename)
    if syntax_issue:
        findings.append(syntax_issue)

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


def scan_repository_path(repo_path: str, *, max_files: int = 250) -> dict:
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Repository path does not exist or is not a directory.")

    allowed_extensions = {".py", ".js", ".ts", ".java", ".go", ".sh", ".yml", ".yaml", ".json", ".txt"}
    findings: list[dict] = []
    scanned_files = 0

    for path in root.rglob("*"):
        if scanned_files >= max_files:
            break
        if path.is_dir() or path.suffix.lower() not in allowed_extensions:
            continue
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
            continue

        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        relative_name = str(path.relative_to(root))
        result = scan_code(code[:200000], relative_name)
        findings.extend(result.get("findings", []))
        scanned_files += 1

    bandit_payload = run_bandit_path(str(root))
    findings.extend(_normalize_bandit_findings(bandit_payload, str(root)))

    dependency_payload = run_dependency_scan(str(root / "requirements.txt"))
    if isinstance(dependency_payload, list):
        dependency_findings = dependency_payload
        dependency_status = "ok"
    else:
        dependency_findings = dependency_payload.get("dependencies") or dependency_payload.get("vulnerabilities") or []
        dependency_status = dependency_payload.get("status", "ok")
    for item in dependency_findings[:100]:
        package = item.get("name") or item.get("package") or item.get("dependency", "dependency")
        findings.append(
            _build_finding(
                "DEPS001",
                "requirements.txt",
                1,
                f"Dependency vulnerability detected in {package}.",
                excerpt=json.dumps(item, default=str)[:1000],
            )
        )

    findings.sort(key=lambda item: (item.get("filename", ""), item.get("line", 0), item.get("id", "")))
    return {
        "status": "needs_attention" if findings else "passed",
        "finding_count": len(findings),
        "findings": findings,
        "scanned_files": scanned_files,
        "tool_status": {
            "bandit": bandit_payload.get("status", "ok"),
            "dependencies": dependency_status,
        },
    }


if __name__ == "__main__":
    bandit_results = run_bandit()
    semgrep_results = run_semgrep()

    with open("bandit_report.json", "w") as f:
        json.dump(bandit_results, f, indent=2)

    with open("semgrep_report.json", "w") as f:
        json.dump(semgrep_results, f, indent=2)

    print("Security scans completed. Reports saved.")
