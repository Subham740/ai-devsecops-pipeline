# AI-Augmented DevSecOps Pipeline

This project is a Flask-based DevSecOps workspace for scanning Python snippets, storing findings, and requesting AI-assisted remediation guidance from Gemini.

## Current Feature Set

- MongoDB-backed scan persistence with SQL fallback
- Login and registration flow for dashboard access
- Interactive dashboard with real metrics, scan history, and rule catalog
- Clickable stored scans that open detailed finding views
- AI remediation endpoint that can call Gemini and falls back gracefully when AI is unavailable
- Heuristic Python security scanner with rules for:
  - SQL Injection
  - Command Injection
  - Dynamic Code Execution
  - Unsafe Deserialization
  - Hardcoded Secrets

## Environment Setup

Create a local `.env` based on `.env.example`.

Important variables:

```env
DATA_BACKEND=mongo
MONGODB_URI=mongodb://127.0.0.1:27017/devsecops
MONGODB_DB_NAME=devsecops
AI_PROVIDER=gemini
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-2.5-flash
DEMO_USERNAME=tester
DEMO_PASSWORD=TestPass123!
```

## Run Locally

```bash
pip install -r requirements.txt
python run.py
```

Default local URL:

```text
http://127.0.0.1:5002
```

## Useful Routes

- `/health` - backend and AI provider status
- `/dashboard` - main application UI
- `/metrics` - dashboard metrics JSON
- `/rules` - active scanner rule catalog
- `/scans` - stored scan history
- `/fix` - AI remediation for a finding

## Test Commands

```bash
python -m unittest tests.test_app -v
python -m unittest tests.test_scanner -v
```

## Monitoring

- Grafana configuration lives under `grafana/`
