# AI DevSecOps

`AI DevSecOps` is now a small Flask-based security service instead of a single demo endpoint. It combines local code scanning, optional AI remediation guidance, scan history, basic metrics, and a hardened demo login flow.

## Features

- JSON API with `/health`, `/rules`, `/scan`, `/scans`, `/metrics`, `/fix`, and `/login`
- Local Python security scanner for SQL injection, `eval`/`exec`, `shell=True`, Flask debug mode, hardcoded secrets, and unsafe deserialization
- SQLite-backed scan history and metrics
- Optional OpenAI-powered fix suggestions with deterministic fallback guidance when no API key is configured
- Unit tests, Semgrep rules, Docker image, and CI pipeline with Trivy scanning

## Local Run

```powershell
pip install -r requirements.txt
python -m app.app
```

The API listens on `http://127.0.0.1:5000` by default.

## Demo Login

- Username: `security-admin`
- Password: `ChangeMe123!`

Override with `DEMO_USERNAME` and `DEMO_PASSWORD` if needed.

## Useful Endpoints

- `GET /health`: service status and feature flags
- `GET /rules`: local scanner rule catalog
- `POST /scan`: scan inline code or a file relative to `SCAN_ROOT`
- `GET /scans`: recent scan history
- `GET /scans/<id>`: full details for one scan
- `GET /metrics`: aggregate usage and finding counts
- `POST /fix`: remediation guidance for a finding or code snippet
- `POST /login`: demo auth flow with rate limiting

## Example Scan Request

```json
{
  "code": "import subprocess\\nsubprocess.run(user_cmd, shell=True)",
  "filename": "danger.py"
}
```

## AI Fixes

Set `OPENAI_API_KEY` to enable model-backed remediation. Without it, the service still returns local fallback guidance so CI and local runs remain deterministic.
