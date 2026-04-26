from __future__ import annotations

import os
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DATABASE_PATH = DATA_DIR / "devsecops.db"
DEFAULT_LOG_PATH = BASE_DIR / "app.log"
DEFAULT_SCAN_ROOT = BASE_DIR.parent
DEFAULT_DEMO_PASSWORD_HASH = (
    "scrypt:32768:8:1$PkweAF6EJau6pXgS$"
    "4bf0ef9790bf0f0571e99c901f2ca482ad43fe1030c242e6656d73242d1e20cf"
    "6ce1288b2b015e578eaba0d0d4ffd6e1e72c000e18f1f142c5d2db07ee1cedd5"
)


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config(overrides: dict | None = None) -> dict:
    demo_password = os.getenv("DEMO_PASSWORD")
    demo_password_hash = os.getenv("DEMO_PASSWORD_HASH") or (
        generate_password_hash(demo_password) if demo_password else DEFAULT_DEMO_PASSWORD_HASH
    )
    config = {
        "APP_NAME": "AI DevSecOps",
        "HOST": os.getenv("HOST", "127.0.0.1"),
        "PORT": int(os.getenv("PORT", "5000")),
        "DEBUG": _as_bool(os.getenv("APP_DEBUG"), False),
        "DATABASE_PATH": str(Path(os.getenv("DATABASE_PATH", DEFAULT_DATABASE_PATH)).resolve()),
        "LOG_PATH": str(Path(os.getenv("LOG_PATH", DEFAULT_LOG_PATH)).resolve()),
        "SCAN_ROOT": str(Path(os.getenv("SCAN_ROOT", DEFAULT_SCAN_ROOT)).resolve()),
        "MAX_SCAN_LENGTH": int(os.getenv("MAX_SCAN_LENGTH", "100000")),
        "SCAN_RESULT_LIMIT": int(os.getenv("SCAN_RESULT_LIMIT", "25")),
        "LOGIN_ATTEMPT_LIMIT": int(os.getenv("LOGIN_ATTEMPT_LIMIT", "5")),
        "LOGIN_WINDOW_SECONDS": int(os.getenv("LOGIN_WINDOW_SECONDS", "60")),
        "DEMO_USERNAME": os.getenv("DEMO_USERNAME", "security-admin"),
        "DEMO_PASSWORD_HASH": demo_password_hash,
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "OPENAI_MODEL": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "TESTING": False,
    }
    if overrides:
        config.update(overrides)
    return config
