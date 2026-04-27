from flask import Flask, redirect, url_for
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from app.models import db, User, Employee
from config import config

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.config.from_object(config)

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from app.auth.routes import auth_bp
        from app.dashboard.routes import dashboard_bp
        
        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp)

        @app.route('/')
        def home():
            return redirect(url_for('auth.login'))

        @app.route('/health')
        def health():
            return {
                "status": "ok",
                "openai_enabled": bool(app.config.get('OPENAI_API_KEY'))
            }

        db.create_all()

        # Create demo user if configured
        if app.config.get('DEMO_USERNAME') and app.config.get('DEMO_PASSWORD'):
            demo_user = User.query.filter_by(username=app.config['DEMO_USERNAME']).first()
            if not demo_user:
                demo_user = User(username=app.config['DEMO_USERNAME'])
                demo_user.set_password(app.config['DEMO_PASSWORD'])
                db.session.add(demo_user)
                db.session.commit() # Create tables if they don't exist

    return app
