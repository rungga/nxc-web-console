"""Application configuration sourced from environment variables."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

APP_DATA_DIR = Path(os.environ.get("NXCWEB_DATA_DIR", str(Path.home() / ".nxc-webgui")))
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

LOGS_DIR = APP_DATA_DIR / "job_logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

JOBS_DB_PATH = APP_DATA_DIR / "jobs.sqlite3"
AUTH_STORE_PATH = APP_DATA_DIR / "auth.json"

NXC_BIN = os.environ.get("NXC_BIN", "nxc")

NXC_HOME = Path(os.environ.get("NXC_HOME", str(Path.home() / ".nxc")))
NXC_WORKSPACES_DIR = NXC_HOME / "workspaces"

_SECRET_KEY_PATH = APP_DATA_DIR / "secret.key"


def _load_or_create_secret_key() -> str:
    env_key = os.environ.get("NXCWEB_SECRET_KEY")
    if env_key:
        return env_key
    if _SECRET_KEY_PATH.exists():
        return _SECRET_KEY_PATH.read_text().strip()
    key = secrets.token_hex(32)
    _SECRET_KEY_PATH.write_text(key)
    _SECRET_KEY_PATH.chmod(0o600)
    return key


SECRET_KEY = _load_or_create_secret_key()

SESSION_MAX_AGE = int(os.environ.get("NXCWEB_SESSION_MAX_AGE", str(8 * 3600)))
COOKIE_SECURE = os.environ.get("NXCWEB_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
WEB_HOST = os.environ.get("NXCWEB_HOST", "127.0.0.1")

ADMIN_USERNAME = os.environ.get("NXCWEB_ADMIN_USER", "admin")

LISTENER_BIND_HOST = os.environ.get("NXCWEB_LISTENER_BIND", "127.0.0.1")

MAX_CONCURRENT_JOBS = int(os.environ.get("NXCWEB_MAX_CONCURRENT_JOBS", "5"))
MAX_RETAINED_JOBS = int(os.environ.get("NXCWEB_MAX_RETAINED_JOBS", "200"))
MAX_JOB_LOG_BYTES = int(os.environ.get("NXCWEB_MAX_JOB_LOG_BYTES", str(20 * 1024 * 1024)))
MAX_WS_CONNECTIONS_PER_USER = max(1, int(os.environ.get("NXCWEB_MAX_WS_CONNECTIONS_PER_USER", "8")))

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300

AI_PROVIDER = os.environ.get("NXCWEB_AI_PROVIDER", "local").strip().lower()
AI_MODEL = os.environ.get("NXCWEB_AI_MODEL", "").strip()
AI_API_KEY = os.environ.get("NXCWEB_AI_API_KEY", "").strip()
AI_BASE_URL = os.environ.get("NXCWEB_AI_BASE_URL", "").strip()
AI_TIMEOUT_SECONDS = min(60.0, max(3.0, float(os.environ.get("NXCWEB_AI_TIMEOUT", "20"))))
