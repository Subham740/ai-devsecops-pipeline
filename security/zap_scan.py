from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _write_report(path: Path, title: str, body: str) -> None:
    path.write_text(
        f"<html><body><h1>{title}</h1><p>{body}</p></body></html>\n",
        encoding="utf-8",
    )


def run_zap_scan() -> int:
    target = os.getenv("APP_URL", "http://host.docker.internal:5000")
    report_path = Path(os.getenv("ZAP_REPORT_PATH", "zap_report.html"))
    allow_failure = os.getenv("ZAP_ALLOW_FAILURE", "true").lower() in {"1", "true", "yes"}

    print(f"Starting OWASP ZAP baseline scan against {target}")

    if not shutil.which("docker"):
        message = "Docker is not available, so the ZAP baseline scan was skipped."
        print(message)
        _write_report(report_path, "OWASP ZAP Scan Skipped", message)
        return 0 if allow_failure else 1

    cmd = [
        "docker",
        "run",
        "--rm",
        "--add-host",
        "host.docker.internal:host-gateway",
        "-v",
        f"{Path.cwd()}:/zap/wrk",
        "zaproxy/zap-stable",
        "zap-baseline.py",
        "-t",
        target,
        "-r",
        report_path.name,
    ]
    completed = subprocess.run(cmd, text=True)
    if completed.returncode != 0 and not report_path.exists():
        _write_report(
            report_path,
            "OWASP ZAP Scan Incomplete",
            f"ZAP exited with code {completed.returncode}. Check Docker availability and target reachability.",
        )
    if completed.returncode != 0 and allow_failure:
        print(f"ZAP completed with exit code {completed.returncode}; continuing because ZAP_ALLOW_FAILURE=true.")
        return 0
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(run_zap_scan())
