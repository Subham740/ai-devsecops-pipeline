from __future__ import annotations

import json
import os
from typing import Any

import requests


def _settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or {}

    def read(key: str, default: Any = None):
        return config[key] if key in config else os.getenv(key, default)

    return {
        "openai_api_key": read("OPENAI_API_KEY"),
        "openai_model": read("OPENAI_MODEL", "gpt-4.1-mini"),
        "gemini_api_key": read("GEMINI_API_KEY"),
        "gemini_model": read("GEMINI_MODEL", "gemini-2.5-flash"),
        "ai_provider": str(read("AI_PROVIDER", "auto")).lower(),
    }


def get_active_provider(config: dict[str, Any] | None = None) -> str | None:
    settings = _settings(config)
    provider = settings["ai_provider"]

    if provider in ("gemini", "google", "gcp"):
        return "gemini" if settings["gemini_api_key"] else None
    if provider in ("openai", "gpt"):
        return "openai" if settings["openai_api_key"] else None
    if settings["gemini_api_key"]:
        return "gemini"
    if settings["openai_api_key"]:
        return "openai"
    return None


def _extract_gemini_text(payload: dict[str, Any]) -> str:
    candidates = payload.get("candidates", [])
    if not candidates:
        raise RuntimeError("Gemini response did not contain any candidates.")

    content = candidates[0].get("content", {})
    parts = content.get("parts", [])
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    text = "".join(texts).strip()
    if not text:
        raise RuntimeError("Gemini response did not contain text output.")
    return text


def call_gemini(prompt: str, *, config: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = _settings(config)
    api_key = settings["gemini_api_key"]
    model = settings["gemini_model"]

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not configured.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }

    response = requests.post(url, headers=headers, json=payload, timeout=45)
    if response.status_code != 200:
        raise RuntimeError(f"Gemini API error {response.status_code}: {response.text}")

    text = _extract_gemini_text(response.json())
    return json.loads(text)


def call_openai(prompt: str, *, config: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = _settings(config)
    api_key = settings["openai_api_key"]
    model = settings["openai_model"]

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not configured.")

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior application security engineer. Return only valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=45,
    )
    if response.status_code != 200:
        raise RuntimeError(f"OpenAI API error {response.status_code}: {response.text}")

    text = response.json()["choices"][0]["message"]["content"]
    return json.loads(text)


def _fallback_remediation(
    *,
    vulnerability_type: str,
    title: str | None,
    description: str | None,
    recommendation: str | None,
    error: str | None = None,
) -> dict[str, Any]:
    secure_example = recommendation or (
        "Validate external input, avoid dangerous dynamic execution, and use safer library APIs."
    )
    best_practices = [
        "Validate and sanitize all user-controlled input.",
        "Prefer structured library APIs over shell or dynamic execution helpers.",
        "Store secrets outside source code and review the change with security tests.",
    ]

    result = {
        "status": "ok",
        "provider": "fallback",
        "title": title or vulnerability_type,
        "explanation": description or f"Security issue detected: {vulnerability_type}.",
        "recommendation": recommendation or secure_example,
        "secure_example": secure_example,
        "best_practices": best_practices,
    }
    if error:
        result["warning"] = error
    return result


def generate_remediation(
    *,
    code: str,
    vulnerability_type: str,
    title: str | None = None,
    description: str | None = None,
    recommendation: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider = get_active_provider(config)
    if not provider:
        return _fallback_remediation(
            vulnerability_type=vulnerability_type,
            title=title,
            description=description,
            recommendation=recommendation,
            error="No AI provider key is configured.",
        )

    prompt = f"""
You are reviewing a vulnerable Python code snippet for a DevSecOps dashboard.

Return valid JSON with these keys only:
- explanation: string
- recommendation: string
- secure_example: string
- best_practices: array of strings

Finding ID: {vulnerability_type}
Finding Title: {title or vulnerability_type}
Finding Description: {description or ""}
Preferred Baseline Recommendation: {recommendation or ""}

Code Snippet:
```python
{code}
```

The response must be concise, practical, and production-oriented.
""".strip()

    try:
        if provider == "gemini":
            ai_result = call_gemini(prompt, config=config)
        else:
            ai_result = call_openai(prompt, config=config)

        return {
            "status": "ok",
            "provider": provider,
            "title": title or vulnerability_type,
            "explanation": ai_result.get("explanation") or description or "",
            "recommendation": ai_result.get("recommendation") or recommendation or "",
            "secure_example": ai_result.get("secure_example") or recommendation or "",
            "best_practices": ai_result.get("best_practices") or [],
        }
    except Exception as exc:
        return _fallback_remediation(
            vulnerability_type=vulnerability_type,
            title=title,
            description=description,
            recommendation=recommendation,
            error=str(exc),
        )


def write_remediation_report(
    output_path: str = "remediation_report.md", *, config: dict[str, Any] | None = None
) -> str:
    provider = get_active_provider(config) or "fallback"
    lines = [
        "# AI Remediation Report",
        "",
        f"- Active provider: `{provider}`",
        "- Status: baseline remediation guidance is available for scanner findings.",
        "- Source: runtime configuration and configured CI secrets.",
    ]

    if provider == "fallback":
        lines.append("- Note: no AI API key is configured, so CI will use built-in remediation guidance.")
    else:
        lines.append("- Note: AI-backed remediation is configured for interactive use in the application.")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    return output_path


if __name__ == "__main__":
    report_path = os.getenv("REMEDIATION_REPORT_PATH", "remediation_report.md")
    saved_to = write_remediation_report(report_path)
    print(f"Remediation report written to {saved_to}")
