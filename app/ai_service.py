from __future__ import annotations

from textwrap import dedent

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - exercised when openai is not installed
    OpenAI = None


FALLBACK_FIXES = {
    "SQLI001": {
        "recommendation": (
            "Replace string-built SQL with parameterized placeholders and pass user input "
            "as a separate argument tuple."
        ),
        "secure_example": dedent(
            """
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            cursor.execute(query, (username, password))
            """
        ).strip(),
    },
    "SECR001": {
        "recommendation": "Move secrets to environment variables or a dedicated secrets manager.",
        "secure_example": dedent(
            """
            import os

            api_key = os.getenv("SERVICE_API_KEY")
            if not api_key:
                raise RuntimeError("SERVICE_API_KEY is required")
            """
        ).strip(),
    },
    "EXEC001": {
        "recommendation": "Avoid eval/exec and replace them with explicit parsing or whitelisted handlers.",
        "secure_example": dedent(
            """
            allowed_actions = {"sum": lambda a, b: a + b}
            result = allowed_actions[action](left, right)
            """
        ).strip(),
    },
    "CMDI001": {
        "recommendation": "Pass a list of arguments to subprocess and keep shell=False.",
        "secure_example": dedent(
            """
            import subprocess

            subprocess.run(["python", "worker.py", task_id], check=True, shell=False)
            """
        ).strip(),
    },
    "FLASK001": {
        "recommendation": "Drive debug mode from environment-aware config and default it to disabled.",
        "secure_example": dedent(
            """
            import os

            debug = os.getenv("APP_DEBUG", "").lower() == "true"
            app.run(host="127.0.0.1", port=5000, debug=debug)
            """
        ).strip(),
    },
    "DESER001": {
        "recommendation": "Avoid pickle for untrusted data and switch to JSON or another safe format.",
        "secure_example": dedent(
            """
            import json

            payload = json.loads(raw_payload)
            """
        ).strip(),
    },
}


def _fallback_payload(finding_id: str | None, title: str, description: str) -> dict:
    template = FALLBACK_FIXES.get(
        finding_id,
        {
            "recommendation": (
                "Validate all external input, use least privilege defaults, and choose explicit "
                "safe APIs instead of dynamic behavior."
            ),
            "secure_example": "# Provide a safe, explicit code path tailored to this finding.",
        },
    )
    recommendation = f"{template['recommendation']} Context: {title}. {description}".strip()
    return {
        "provider": "fallback",
        "model": None,
        "recommendation": recommendation,
        "secure_example": template["secure_example"],
    }


def generate_fix(
    finding_id: str | None,
    title: str,
    description: str,
    code: str,
    api_key: str | None,
    model: str,
) -> dict:
    fallback = _fallback_payload(finding_id, title, description)
    if not api_key or OpenAI is None:
        return fallback

    prompt = dedent(
        f"""
        You are a security engineer.
        Explain how to remediate this issue and provide a safer Python example.

        Finding ID: {finding_id or "N/A"}
        Title: {title}
        Description: {description}

        Vulnerable code:
        {code or "No code sample provided."}
        """
    ).strip()

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            temperature=0.2,
            messages=[
                {
                    "role": "system",
                    "content": "Return concise secure coding guidance for Python services.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content or fallback["recommendation"]
        return {
            "provider": "openai",
            "model": model,
            "recommendation": content.strip(),
            "secure_example": fallback["secure_example"],
        }
    except Exception as exc:  # pragma: no cover - depends on network/runtime state
        fallback["recommendation"] = f"{fallback['recommendation']} OpenAI fallback reason: {exc}"
        return fallback
