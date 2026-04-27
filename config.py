import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-12345")
    
    # SQLAlchemy Configuration
    # Supports MySQL (PlanetScale/Railway) via environment variable
    # Defaults to local SQLite for development
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{BASE_DIR / 'devsecops.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Scan Configuration
    SCAN_ROOT = os.getenv("SCAN_ROOT", str(BASE_DIR))
    MAX_SCAN_LENGTH = int(os.getenv("MAX_SCAN_LENGTH", "100000"))
    
    # AI Engine (GPT-4)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
    
    # Demo User (for testing)
    DEMO_USERNAME = os.getenv("DEMO_USERNAME", "tester")
    DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "TestPass123!")
    
    # App Settings
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 5000))

config = Config()
