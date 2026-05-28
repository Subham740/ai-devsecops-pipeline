from flask import Flask, Response, current_app, render_template
from flask_login import LoginManager

from app.storage import create_storage
from config import config

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    storage = current_app.extensions.get("storage")
    return storage.get_user_by_id(user_id) if storage else None


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config)

    if test_config:
        app.config.update(test_config)

    if app.config.get("DATABASE_PATH") and not app.config.get("DATABASE_URL"):
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{app.config['DATABASE_PATH']}"

    if app.config.get("TESTING") and str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite:///"):
        from sqlalchemy.pool import NullPool

        engine_options = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS", {}))
        engine_options.setdefault("poolclass", NullPool)
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options

    storage = create_storage(app.config)
    app.extensions["storage"] = storage

    storage.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from app.auth.routes import auth_bp
        from app.dashboard.routes import dashboard_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp)

        @app.route("/")
        def home():
            return render_template("index.html")

        @app.route("/health")
        def health():
            storage_state = current_app.extensions["storage"].healthcheck()
            using_mongo = storage_state["backend"] == "mongo"
            gemini_enabled = bool(app.config.get("GEMINI_API_KEY"))
            openai_enabled = bool(app.config.get("OPENAI_API_KEY"))

            provider = None
            if gemini_enabled:
                provider = "gemini"
            elif openai_enabled:
                provider = "openai"

            return {
                "status": "ok",
                "ai_enabled": gemini_enabled or openai_enabled,
                "ai_provider": provider,
                "openai_enabled": openai_enabled,
                "gemini_enabled": gemini_enabled,
                "gemini_model": app.config.get("GEMINI_MODEL"),
                "data_backend": storage_state["backend"],
                "data_connected": storage_state["connected"],
                "mongodb_enabled": using_mongo,
                "mongodb_connected": storage_state["connected"] if using_mongo else False,
            }

        @app.route("/prometheus")
        def prometheus_metrics():
            metrics = current_app.extensions["storage"].get_dashboard_metrics()
            severity_breakdown = metrics.get("severity_breakdown", {})
            lines = [
                "# HELP devsecops_scans_total Total scans stored by the dashboard.",
                "# TYPE devsecops_scans_total gauge",
                f"devsecops_scans_total {metrics.get('total_scans', 0)}",
                "# HELP devsecops_findings_total Total findings stored by the dashboard.",
                "# TYPE devsecops_findings_total gauge",
                f"devsecops_findings_total {metrics.get('total_findings', 0)}",
                "# HELP devsecops_risk_score CVSS-enriched aggregate risk score.",
                "# TYPE devsecops_risk_score gauge",
                f"devsecops_risk_score {metrics.get('risk_score', 0)}",
                "# HELP devsecops_max_cvss Highest CVSS score currently stored.",
                "# TYPE devsecops_max_cvss gauge",
                f"devsecops_max_cvss {metrics.get('max_cvss', 0)}",
                "# HELP devsecops_findings_by_severity Stored findings grouped by severity.",
                "# TYPE devsecops_findings_by_severity gauge",
            ]
            for severity, count in sorted(severity_breakdown.items()):
                lines.append(f'devsecops_findings_by_severity{{severity="{severity}"}} {count}')
            return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

        if app.config.get("DEMO_USERNAME"):
            current_app.extensions["storage"].ensure_demo_user(
                app.config["DEMO_USERNAME"],
                password=app.config.get("DEMO_PASSWORD"),
                password_hash=app.config.get("DEMO_PASSWORD_HASH"),
            )

    return app
