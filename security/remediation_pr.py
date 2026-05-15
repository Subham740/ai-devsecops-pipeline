from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


REMEDIATION_PATH = Path("docs/remediation-pr-summary.md")


def write_remediation_summary() -> str:
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    body = f"""# Automated Remediation PR

Generated at: `{generated_at}`

This branch is created automatically by the remediation workflow when maintainers request a remediation PR.

## Proposed Remediation Scope

- Review scanner findings from `bandit_report.json`, `semgrep_report.json`, `safety_report.json`, and `zap_report.html`.
- Apply code-level fixes for validated security findings.
- Keep generated secrets out of source control and use GitHub Actions secrets or runtime environment variables.
- Re-run unit tests, Semgrep, Trivy, and OWASP ZAP before merging.

## Validation Target

The repository includes `sample-java-spring-boot/` as a representative Spring Boot target for CI validation.
"""
    REMEDIATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    REMEDIATION_PATH.write_text(body, encoding="utf-8")
    return str(REMEDIATION_PATH)


if __name__ == "__main__":
    print(f"Remediation summary written to {write_remediation_summary()}")
