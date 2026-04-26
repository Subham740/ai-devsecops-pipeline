from __future__ import annotations

import argparse
import json

from app.ai_service import generate_fix
from app.config import load_config
from app.scanner import scan_code


DEFAULT_VULNERABILITY = "SQL injection caused by string-built login queries"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate secure remediation guidance for a vulnerability or code snippet."
    )
    parser.add_argument("--vulnerability", help="Plain-English description of the issue.")
    parser.add_argument("--description", help="Optional extra context about the issue.")
    parser.add_argument("--finding-id", help="Known local finding id, for example SQLI001.")
    parser.add_argument("--code", help="Optional code snippet to analyze before suggesting a fix.")
    parser.add_argument("--filename", default="snippet.py", help="Logical filename for the code snippet.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = load_config()

    finding_id = args.finding_id
    title = args.vulnerability or DEFAULT_VULNERABILITY
    description = args.description or "Return secure Python remediation guidance and a safer example."

    if args.code:
        scan_result = scan_code(args.code, args.filename)
        if scan_result["findings"]:
            primary_finding = scan_result["findings"][0]
            finding_id = finding_id or primary_finding["id"]
            title = args.vulnerability or primary_finding["title"]
            description = args.description or primary_finding["description"]

    fix = generate_fix(
        finding_id=finding_id,
        title=title,
        description=description,
        code=args.code or "",
        api_key=config["OPENAI_API_KEY"],
        model=config["OPENAI_MODEL"],
    )

    payload = {
        "finding_id": finding_id,
        "title": title,
        "description": description,
        "provider": fix["provider"],
        "model": fix.get("model"),
        "recommendation": fix["recommendation"],
        "secure_example": fix["secure_example"],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Title: {payload['title']}")
    if payload["finding_id"]:
        print(f"Finding ID: {payload['finding_id']}")
    print(f"Provider: {payload['provider']}")
    if payload["model"]:
        print(f"Model: {payload['model']}")
    print("\nRecommendation:\n")
    print(payload["recommendation"])
    print("\nSecure Example:\n")
    print(payload["secure_example"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
