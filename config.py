import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-12345")

    DATABASE_URL = os.getenv("DATABASE_URL")
    DATABASE_PATH = os.getenv("DATABASE_PATH")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or (
        f"sqlite:///{Path(DATABASE_PATH)}" if DATABASE_PATH else f"sqlite:///{BASE_DIR / 'devsecops.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DATA_BACKEND = os.getenv("DATA_BACKEND", "auto").lower()
    MONGODB_URI = os.getenv("MONGODB_URI")
    MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME")
    MONGODB_TIMEOUT_MS = int(os.getenv("MONGODB_TIMEOUT_MS", "2000"))

    SCAN_ROOT = os.getenv("SCAN_ROOT", str(BASE_DIR))
    MAX_SCAN_LENGTH = int(os.getenv("MAX_SCAN_LENGTH", "100000"))

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    AI_PROVIDER = os.getenv("AI_PROVIDER", "auto").lower()

    DEMO_USERNAME = os.getenv("DEMO_USERNAME", "tester")
    DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "TestPass123!")
    DEMO_PASSWORD_HASH = os.getenv("DEMO_PASSWORD_HASH")

    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 5000))


config = Config()
