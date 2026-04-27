# AI-Augmented DevSecOps Pipeline

A professional-grade DevSecOps project integrating modern security tools, AI-powered remediation guidance, and automated CI/CD pipelines.

## Features

- **Backend**: Python 3.11 + Flask + SQLAlchemy (MySQL/SQLite)
- **Authentication**: Flask-Login + Bcrypt (Protected Dashboard)
- **SAST**: Semgrep + Bandit (Static Analysis Security Testing)
- **DAST**: OWASP ZAP (Dynamic Analysis Security Testing)
- **Container Scan**: Trivy (Scanning Docker images for CVEs)
- **AI Remediation**: GPT-4 (Automated fix suggestions based on scan results)
- **CI/CD**: Dual support for GitHub Actions and Jenkins
- **Monitoring**: Prometheus + Grafana Dashboard

## Project Structure

```
.
├── app/
│   ├── auth/          # Login, Register routes & forms
│   ├── dashboard/     # Protected employee directory
│   ├── templates/     # UI Templates (Glassmorphism theme)
│   ├── models.py      # SQLAlchemy models (User, Employee)
│   └── __init__.py    # App factory & extension init
├── security/
│   ├── scanner.py     # Runs Semgrep & Bandit
│   ├── ai_remediation.py # Calls GPT-4 for security fixes
│   └── zap_scan.py    # DAST scanning wrapper
├── .github/workflows/
│   └── devsecops.yml  # GitHub Actions pipeline
├── Dockerfile         # Containerization
├── Jenkinsfile        # Jenkins pipeline
├── grafana/           # Monitoring configurations
├── config.py          # Central configuration
├── requirements.txt   # Dependencies
└── run.py             # Entry point
```

## Getting Started

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the App**:
   ```bash
   python run.py
   ```

3. **Run Security Scans**:
   ```bash
   python security/scanner.py
   python security/ai_remediation.py  # Requires OPENAI_API_KEY
   ```

## CI/CD Integration

### GitHub Actions
- Ensure `OPENAI_API_KEY` is added to your GitHub Repository Secrets.
- The pipeline runs automatically on every push to `main`.

### Jenkins
- Configure a pipeline project and add the `OPENAI_API_KEY` credential.
- Use the provided `Jenkinsfile`.

## Monitoring
- Access metrics at `/metrics`.
- Import `grafana/dashboard.json` into your Grafana instance connected to Prometheus.
