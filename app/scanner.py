from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Callable


Detector = Callable[[str], bool]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    detector: Detector


def _line_has_sql_injection(line: str) -> bool:
    normalized = line.replace(" ", "")
    if "execute(" not in line:
        return False
    risky_tokens = ('f"', "f'", ".format(", '"+', "'+")
    return any(token in normalized or token in line for token in risky_tokens)


def _line_has_hardcoded_secret(line: str) -> bool:
    pattern = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password)\b\s*=\s*['\"][^'\"]{8,}['\"]"
    )
    return bool(pattern.search(line))


def _line_has_eval(line: str) -> bool:
    return bool(re.search(r"\b(eval|exec)\s*\(", line))


def _line_has_shell_true(line: str) -> bool:
    return "subprocess." in line and "shell=True" in line


def _line_has_flask_debug(line: str) -> bool:
    normalized = line.replace(" ", "")
    return ".run(" in line and "debug=True" in normalized


def _line_has_pickle_load(line: str) -> bool:
    return bool(re.search(r"\bpickle\.loads?\s*\(", line))


RULES: list[Rule] = [
    Rule(
        id="SQLI001",
        title="Possible SQL injection",
        severity="critical",
        description="Dynamic SQL query construction was detected near a database execute call.",
        recommendation="Use parameterized queries and keep untrusted input out of SQL strings.",
        detector=_line_has_sql_injection,
    ),
    Rule(
        id="SECR001",
        title="Possible hardcoded secret",
        severity="high",
        description="A literal value appears to be assigned to a secret-like variable.",
        recommendation="Load secrets from environment variables or a secrets manager instead of source code.",
        detector=_line_has_hardcoded_secret,
    ),
    Rule(
        id="EXEC001",
        title="Dangerous dynamic execution",
        severity="high",
        description="eval/exec can execute attacker-controlled code if fed untrusted input.",
        recommendation="Replace eval/exec with explicit parsing or a safe dispatch table.",
        detector=_line_has_eval,
    ),
    Rule(
        id="CMDI001",
        title="Command injection risk",
        severity="critical",
        description="subprocess with shell=True can execute injected shell metacharacters.",
        recommendation="Pass argument lists to subprocess without shell=True and validate all inputs.",
        detector=_line_has_shell_true,
    ),
    Rule(
        id="FLASK001",
        title="Flask debug mode enabled",
        severity="medium",
        description="Debug mode can expose internals and interactive consoles in deployed environments.",
        recommendation="Keep debug disabled outside local development and drive behavior through configuration.",
        detector=_line_has_flask_debug,
    ),
    Rule(
        id="DESER001",
        title="Unsafe deserialization",
        severity="high",
        description="pickle loads can execute arbitrary code when parsing untrusted data.",
        recommendation="Prefer safe serialization formats such as JSON for untrusted payloads.",
        detector=_line_has_pickle_load,
    ),
]


def get_rule_catalog() -> list[dict]:
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "recommendation": rule.recommendation,
        }
        for rule in RULES
    ]


def scan_code(code: str, target_name: str = "snippet.py") -> dict:
    findings: list[dict] = []
    severity_breakdown: dict[str, int] = {}
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule in RULES:
            if not rule.detector(line):
                continue
            key = (rule.id, line_number)
            if key in seen:
                continue
            seen.add(key)
            severity_breakdown[rule.severity] = severity_breakdown.get(rule.severity, 0) + 1
            findings.append(
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "line": line_number,
                    "description": rule.description,
                    "recommendation": rule.recommendation,
                    "excerpt": stripped[:160],
                }
            )

    return {
        "target_name": target_name,
        "status": "passed" if not findings else "needs_attention",
        "finding_count": len(findings),
        "severity_breakdown": severity_breakdown,
        "checksum": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "findings": findings,
    }
