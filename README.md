# AI-Augmented DevSecOps Pipeline

This project is a Flask-based DevSecOps workspace for scanning Python snippets, storing findings, and requesting AI-assisted remediation guidance from Gemini.

## Current Feature Set

- MongoDB-backed scan persistence with SQL fallback
- Login and registration flow for dashboard access
- Interactive dashboard with real metrics, scan history, and rule catalog
- Clickable stored scans that open detailed finding views
- AI remediation endpoint that can call Gemini and falls back gracefully when AI is unavailable
- AI risk classification output for remediation responses, including severity, CVSS, and validation steps when the provider returns them
- CVSS-enriched dashboard metrics, Prometheus export, and Grafana risk dashboard provisioning
- Unified CI/CD security pipeline with Semgrep, Safety, OWASP ZAP, Trivy, and AI remediation reporting
- On-demand GitHub Actions remediation PR workflow
- Sample Java Spring Boot validation target under `sample-java-spring-boot/`
- Heuristic Python security scanner with rules for:
  - Python Syntax Errors
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
http://127.0.0.1:5000
```

## Useful Routes

- `/health` - backend and AI provider status
- `/dashboard` - main application UI
- `/metrics` - dashboard metrics JSON
- `/prometheus` - Prometheus scrape endpoint for Grafana
- `/rules` - active scanner rule catalog
- `/scans` - stored scan history
- `/fix` - AI remediation for a finding

## Test Commands

```bash
python -m unittest tests.test_app -v
python -m unittest tests.test_scanner -v
```

## Monitoring

- Prometheus configuration lives in `prometheus.yml`
- Grafana provisioning and the CVSS risk dashboard live under `grafana/`

```bash
docker compose up prometheus grafana
```

Grafana URL:

```text
http://127.0.0.1:3000
```

Default local credentials are `admin` / `admin`.

## CI/CD Security Pipeline

The GitHub Actions workflow runs:

- Unit tests
- Semgrep/Bandit SAST through `security/scanner.py`
- Safety dependency scanning
- OWASP ZAP baseline DAST against the running Flask app
- Gemini/OpenAI remediation report generation
- Docker image build
- Trivy container scanning
- Security report artifact upload

The `remediation-pr` job runs on `workflow_dispatch` and opens a pull request with generated remediation branch content.
