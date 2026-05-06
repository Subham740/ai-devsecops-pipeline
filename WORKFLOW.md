# AI-Augmented DevSecOps Pipeline - Workflow Documentation

## Project Overview

This is a Flask-based DevSecOps workspace that enables developers to scan Python code snippets for security vulnerabilities, store findings, and request AI-assisted remediation guidance using Google Gemini API.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    User Interface Layer                 │
│  (Flask Web Dashboard + Authentication)                 │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│              API Layer (Flask Routes)                    │
│  ├── /dashboard     (Web Interface)                      │
│  ├── /scan          (Code Scanning)                      │
│  ├── /fix           (AI Remediation)                     │
│  ├── /metrics       (Analytics)                          │
│  └── /health        (Status Check)                       │
└────────────────┬────────────────────────────────────────┘
                 │
     ┌───────────┴───────────┐
     │                       │
┌────▼──────────┐    ┌──────▼────────┐
│  Security     │    │    Data        │
│  Scanner      │    │    Storage     │
│  (Rules)      │    │  (MongoDB/DB)  │
└────┬──────────┘    └──────┬────────┘
     │                      │
     ├─ SQL Injection       │
     ├─ Command Injection   │
     ├─ Code Execution      ├─ Scan Results
     ├─ Deserialization     ├─ User Profiles
     └─ Hardcoded Secrets   └─ Scan History
                            
         ┌────────────────────────────────────┐
         │      AI Layer (Gemini/OpenAI)      │
         │  (Remediation Suggestions)         │
         └────────────────────────────────────┘
```

---

## User Workflow

### Step 1: Authentication
- User navigates to `http://localhost:5000/dashboard`
- Enters credentials (Demo: username=`tester`, password=`TestPass123!`)
- Session established, user accesses dashboard

### Step 2: Code Scanning
1. User pastes or uploads Python code snippet
2. Frontend sends POST request to `/scan` endpoint
3. Security Scanner analyzes code against 5 vulnerability rules
4. Results displayed in real-time with severity badges

### Step 3: Viewing Results
- Dashboard shows scan history with timestamps
- Clicking on scan reveals detailed findings:
  - Vulnerability type
  - Line number and code context
  - Severity level (Critical/High/Medium/Low)
  - Affected function/variable

### Step 4: AI-Assisted Remediation
- User clicks "Get AI Fix" on a finding
- Flask sends request to Gemini API
- AI generates remediation guidance
- Suggestions displayed on dashboard

---

## Core Components

### 1. **Security Scanner** (`app/scanner.py`)
Heuristic-based Python security scanner with 5 built-in rules:

| Rule ID | Vulnerability | Severity | Pattern |
|---------|--------------|----------|---------|
| SQLI001 | SQL Injection | Critical | String concat in SQL queries |
| CMDI001 | Command Injection | Critical | `os.system()`, `subprocess` with user input |
| EXEC001 | Dynamic Code Execution | Critical | `eval()`, `exec()`, `__import__()` |
| DSER001 | Unsafe Deserialization | Critical | `pickle.loads()`, `yaml.load()` |
| SECR001 | Hardcoded Secrets | High | API keys, passwords in code |

**How it works:**
- Analyzes abstract syntax tree (AST) of Python code
- Pattern matching for dangerous functions + untrusted variables
- Returns findings with line numbers and context

### 2. **Data Storage** (`app/storage.py`)
Multi-backend support for persistence:
- **MongoDB**: Primary for production
- **SQLite**: Fallback for development

**Tables/Collections:**
- `users`: Authentication credentials
- `scans`: Scan results with findings
- `remediation_history`: AI suggestions cache

### 3. **Authentication** (`app/auth/`)
Login/registration system:
- Form validation (`forms.py`)
- Session management (`routes.py`)
- User credentials stored securely (bcrypt hashing planned)

### 4. **API Routes** (`app/` + Flask routes)

```
GET  /health              → System status + AI provider check
GET  /dashboard           → Main web interface
POST /scan                → Submit code for scanning
GET  /scans               → Scan history
GET  /scans/<id>          → Specific scan details
POST /fix                 → Request AI remediation
GET  /metrics             → Dashboard analytics
GET  /rules               → Active security rules
```

### 5. **AI Integration** (`security/ai_remediation.py`)
- Integrates with Gemini API (with OpenAI fallback)
- Sends vulnerability context to AI
- Receives remediation suggestions
- Graceful degradation if AI unavailable

### 6. **Monitoring** (`grafana/`, `prometheus.yml`)
- Prometheus metrics collection
- Grafana dashboard visualization
- Tracks scan frequency, vulnerability trends

---

## Data Flow Diagram

### Scanning Flow
```
User Input (Code)
      │
      ▼
┌──────────────┐
│  AST Parser  │ ─→ Extract syntax tree
└──────────────┘
      │
      ▼
┌──────────────────────────┐
│  Rule Engine             │
│  (5 Vulnerability Rules) │
└──────────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Finding Generation  │ ─→ Format results
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Store Results       │ ─→ MongoDB/SQLite
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Display Dashboard   │ ─→ JSON Response
└──────────────────────┘
```

### Remediation Flow
```
Finding + Code Context
      │
      ▼
┌──────────────────────┐
│  Format Prompt       │
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Call Gemini API     │
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Parse Response      │
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  Return Suggestion   │ ─→ JSON Response
└──────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Backend | Flask | Web framework |
| Database | MongoDB / SQLite | Persistent storage |
| Scanner | Python AST | Code analysis |
| AI | Google Gemini / OpenAI | Remediation engine |
| Frontend | HTML/CSS/JavaScript | Web dashboard |
| Monitoring | Prometheus + Grafana | Metrics & alerts |
| Containerization | Docker | Deployment |
| CI/CD | Jenkins | Pipeline automation |

---

## Setup & Execution

### Prerequisites
```
Python 3.8+
MongoDB (for production) or SQLite (development)
Gemini API Key (for AI features)
```

### Installation
```bash
# Clone repository
cd ai-devsecops

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your API keys
```

### Running the Application
```bash
# Start Flask application
python run.py

# Application runs on http://127.0.0.1:5000

# Run tests
python -m unittest tests.test_app -v
python -m unittest tests.test_scanner -v
```

### Accessing Services
- **Web Dashboard**: http://localhost:5000/dashboard
- **Health Check**: http://localhost:5000/health
- **Rules Catalog**: http://localhost:5000/rules

---

## Security Features

### 1. Heuristic-Based Detection
- **No database needed** for vulnerability patterns
- Rules defined in code (easily customizable)
- Fast analysis without external calls

### 2. Multi-Layer Protection
- **Input validation** on code snippets
- **Output encoding** to prevent XSS
- **Session management** for user isolation

### 3. AI-Assisted Security
- Gemini API provides context-aware fixes
- Suggestions reviewed by developers before implementation
- Not automatically applying fixes (safe-by-design)

---

## Key Features

✅ **Scan Python Code** - Detect 5 categories of vulnerabilities
✅ **Store Results** - MongoDB or SQLite persistence
✅ **History Tracking** - View past scans and trends
✅ **AI Remediation** - Get fix suggestions from Gemini
✅ **Web Dashboard** - User-friendly interface with metrics
✅ **Real-time Metrics** - Severity breakdown, rule distribution
✅ **Demo Access** - Pre-configured credentials for testing
✅ **Graceful Fallbacks** - Works without AI/MongoDB if needed
✅ **Monitoring Ready** - Prometheus metrics + Grafana dashboard

---

## Future Enhancements (Phase 2)

1. **Multi-Language Support** - JavaScript, Java, Go scanning
2. **Dependency Checking** - Identify vulnerable packages
3. **Webhook Alerts** - Slack/Teams notifications
4. **Batch Scanning** - Scan entire directories
5. **JWT Authentication** - Token-based API security
6. **SARIF Export** - GitHub Advanced Security integration

---

## Troubleshooting

### Issue: MongoDB Connection Failed
**Solution**: Check `MONGODB_URI` in `.env`, or set `DATA_BACKEND=sqlite`

### Issue: Gemini API Errors
**Solution**: Verify `GEMINI_API_KEY`, fallback to graceful degradation

### Issue: Dashboard Not Loading
**Solution**: Verify Flask is running on `127.0.0.1:5000`, check console logs

---

## Project Structure

```
ai-devsecops/
├── app/                    # Flask application
│   ├── __init__.py
│   ├── models.py          # Database models
│   ├── scanner.py         # Security scanner rules
│   ├── storage.py         # Data persistence layer
│   ├── auth/              # Authentication routes
│   ├── dashboard/         # Dashboard routes
│   ├── templates/         # HTML templates
│   └── static/            # CSS/JS assets
├── security/              # AI integration modules
│   ├── scanner.py
│   ├── ai_remediation.py
│   └── zap_scan.py
├── tests/                 # Unit tests
├── grafana/               # Monitoring dashboards
├── Dockerfile             # Container configuration
├── docker-compose.yml     # Multi-container setup
├── Jenkinsfile            # CI/CD pipeline
├── requirements.txt       # Python dependencies
├── config.py              # Configuration
├── run.py                 # Entry point
└── README.md              # Documentation
```

---

## Conclusion

This AI DevSecOps pipeline provides a complete solution for:
- ✨ Automated security scanning
- 🤖 AI-powered remediation guidance
- 📊 Visual dashboards and analytics
- 🔒 Secure code analysis
- 🚀 Production-ready deployment

The modular architecture allows easy integration into existing CI/CD pipelines and extensibility for additional security rules and scanning capabilities.

---

**Created**: May 2026
**Version**: 1.0
**Status**: Production Ready
