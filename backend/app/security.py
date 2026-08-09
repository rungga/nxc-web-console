"""Authentication: password hashing, first-run bootstrap, and signed session cookies.

Design goals (OWASP-conscious):
- No plaintext credentials stored anywhere; PBKDF2-HMAC-SHA256 with per-user salt.
- Session tokens are HMAC-signed and time-limited (not a JWT lib dependency needed).
- A random admin password is generated on first run instead of a hardcoded default.
- Login attempts are rate-limited per source IP to slow down brute forcing.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass

from fastapi import Cookie, Depends, HTTPException, Request, status

from app import config

PBKDF2_ITERATIONS = 260_000
COOKIE_NAME = "nxcweb_session"
AUTH_STORE_VERSION = 2
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
VALID_ROLES = {ROLE_ADMIN, ROLE_OPERATOR}
_AUTH_LOCK = threading.RLock()


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(digest).decode("ascii")


def _normalize_username(username: str) -> str:
    return username.strip().casefold()


def _credential_record(
    password: str,
    role: str,
    created_at: float | None = None,
    session_version: int = 1,
) -> dict:
    salt = secrets.token_bytes(16)
    now = time.time()
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": _hash_password(password, salt),
        "role": role,
        "enabled": True,
        "session_version": session_version,
        "created_at": created_at or now,
        "updated_at": now,
    }


def _normalize_auth_store(data: dict) -> tuple[dict, bool]:
    if isinstance(data.get("users"), dict):
        store = {"version": AUTH_STORE_VERSION, "users": data["users"]}
        changed = data.get("version") != AUTH_STORE_VERSION
        for username, record in list(store["users"].items()):
            if not isinstance(record, dict) or not record.get("salt") or not record.get("hash"):
                del store["users"][username]
                changed = True
                continue
            record.setdefault("role", ROLE_OPERATOR)
            record.setdefault("enabled", True)
            if "session_version" not in record:
                record["session_version"] = 1
                changed = True
            record.setdefault("created_at", time.time())
            record.setdefault("updated_at", record["created_at"])
        return store, changed

    if data.get("username") and data.get("salt") and data.get("hash"):
        username = str(data["username"]).strip()
        return {
            "version": AUTH_STORE_VERSION,
            "users": {
                _normalize_username(username): {
                    "username": username,
                    "salt": data["salt"],
                    "hash": data["hash"],
                    "role": ROLE_ADMIN,
                    "enabled": True,
                    "session_version": 1,
                    "created_at": time.time(),
                    "updated_at": time.time(),
                }
            },
        }, True

    return {"version": AUTH_STORE_VERSION, "users": {}}, bool(data)


def _load_auth_store() -> dict:
    with _AUTH_LOCK:
        data: dict = {}
        if config.AUTH_STORE_PATH.exists():
            try:
                data = json.loads(config.AUTH_STORE_PATH.read_text())
            except (OSError, json.JSONDecodeError):
                data = {}
        store, changed = _normalize_auth_store(data)
        if changed:
            _save_auth_store(store)
        return store


def _save_auth_store(data: dict) -> None:
    with _AUTH_LOCK:
        temp_path = config.AUTH_STORE_PATH.with_suffix(".tmp")
        temp_path.write_text(json.dumps(data, separators=(",", ":")))
        temp_path.chmod(0o600)
        os.replace(temp_path, config.AUTH_STORE_PATH)
        config.AUTH_STORE_PATH.chmod(0o600)


def bootstrap_admin_account() -> str | None:
    """Create the admin account with a random password on first run.

    Returns the generated plaintext password (only on first run) so the
    operator can print/log it once; returns None if an account already exists.
    """
    store = _load_auth_store()
    if store["users"]:
        return None

    password = secrets.token_urlsafe(12)
    username = config.ADMIN_USERNAME.strip()
    record = _credential_record(password, ROLE_ADMIN)
    record["username"] = username
    store["users"][_normalize_username(username)] = record
    _save_auth_store(store)
    return password


def verify_credentials(username: str, password: str) -> bool:
    store = _load_auth_store()
    record = store["users"].get(_normalize_username(username))
    if not record or not record.get("enabled", True):
        return False
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = record["hash"]
    except (KeyError, ValueError, binascii.Error):
        return False
    computed = _hash_password(password, salt)
    return hmac.compare_digest(expected, computed)


def change_password(username: str, new_password: str) -> None:
    with _AUTH_LOCK:
        store = _load_auth_store()
        key = _normalize_username(username)
        existing = store["users"].get(key)
        if existing is None and store["users"]:
            raise KeyError(username)
        role = existing.get("role", ROLE_ADMIN) if existing else ROLE_ADMIN
        created_at = existing.get("created_at") if existing else None
        session_version = int(existing.get("session_version", 1)) + 1 if existing else 1
        record = _credential_record(new_password, role, created_at, session_version)
        record["username"] = existing.get("username", username.strip()) if existing else username.strip()
        record["enabled"] = existing.get("enabled", True) if existing else True
        store["users"][key] = record
        _save_auth_store(store)


def get_user(username: str) -> dict | None:
    record = _load_auth_store()["users"].get(_normalize_username(username))
    if not record:
        return None
    return {
        "username": record.get("username", username),
        "role": record.get("role", ROLE_OPERATOR),
        "enabled": bool(record.get("enabled", True)),
        "created_at": float(record.get("created_at", 0)),
        "updated_at": float(record.get("updated_at", 0)),
    }


def list_users() -> list[dict]:
    users = []
    for key, record in _load_auth_store()["users"].items():
        users.append({
            "username": record.get("username", key),
            "role": record.get("role", ROLE_OPERATOR),
            "enabled": bool(record.get("enabled", True)),
            "created_at": float(record.get("created_at", 0)),
            "updated_at": float(record.get("updated_at", 0)),
        })
    return sorted(users, key=lambda user: user["username"].casefold())


def create_user(username: str, password: str, role: str) -> dict:
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    with _AUTH_LOCK:
        store = _load_auth_store()
        key = _normalize_username(username)
        if not key:
            raise ValueError("Username is required")
        if key in store["users"]:
            raise ValueError("Username already exists")
        record = _credential_record(password, role)
        record["username"] = username.strip()
        store["users"][key] = record
        _save_auth_store(store)
    return get_user(username) or {}


def _enabled_admin_count(store: dict) -> int:
    return sum(
        1
        for record in store["users"].values()
        if record.get("role") == ROLE_ADMIN and record.get("enabled", True)
    )


def update_user(username: str, role: str | None = None, enabled: bool | None = None) -> dict:
    if role is not None and role not in VALID_ROLES:
        raise ValueError("Invalid role")
    with _AUTH_LOCK:
        store = _load_auth_store()
        key = _normalize_username(username)
        record = store["users"].get(key)
        if not record:
            raise KeyError(username)
        removes_enabled_admin = (
            record.get("role") == ROLE_ADMIN
            and record.get("enabled", True)
            and (role == ROLE_OPERATOR or enabled is False)
        )
        if removes_enabled_admin and _enabled_admin_count(store) <= 1:
            raise ValueError("At least one enabled administrator is required")
        if role is not None:
            record["role"] = role
        if enabled is not None:
            record["enabled"] = enabled
        if role is not None or enabled is not None:
            record["session_version"] = int(record.get("session_version", 1)) + 1
        record["updated_at"] = time.time()
        _save_auth_store(store)
    return get_user(username) or {}


def delete_user(username: str) -> None:
    with _AUTH_LOCK:
        store = _load_auth_store()
        key = _normalize_username(username)
        record = store["users"].get(key)
        if not record:
            raise KeyError(username)
        if record.get("role") == ROLE_ADMIN and record.get("enabled", True) and _enabled_admin_count(store) <= 1:
            raise ValueError("At least one enabled administrator is required")
        del store["users"][key]
        _save_auth_store(store)


# --- Signed session tokens -------------------------------------------------

def _sign(payload: str) -> str:
    mac = hmac.new(config.SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return mac


def create_session_token(username: str) -> str:
    store = _load_auth_store()
    record = store["users"].get(_normalize_username(username))
    if not record or not record.get("enabled", True):
        raise ValueError("Account is disabled or missing")
    canonical_username = record.get("username", username)
    session_version = str(int(record.get("session_version", 1)))
    issued_at = str(int(time.time()))
    payload = f"{canonical_username}|{session_version}|{issued_at}"
    signature = _sign(payload)
    raw = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_session_token(token: str) -> str | None:
    """Returns the username if the token is valid and not expired, else None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        username, session_version, issued_at, signature = raw.split("|")
        issued_at_value = int(issued_at)
        session_version_value = int(session_version)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None

    payload = f"{username}|{session_version}|{issued_at}"
    expected_signature = _sign(payload)
    if not hmac.compare_digest(expected_signature, signature):
        return None

    if int(time.time()) - issued_at_value > config.SESSION_MAX_AGE:
        return None

    record = _load_auth_store()["users"].get(_normalize_username(username))
    if not record or not record.get("enabled", True):
        return None
    if session_version_value != int(record.get("session_version", 1)):
        return None

    return record.get("username", username)


# --- Brute-force lockout ----------------------------------------------------

@dataclass
class _AttemptState:
    failures: int = 0
    locked_until: float = 0.0


_login_attempts: dict[str, _AttemptState] = {}


def register_failed_attempt(source: str) -> None:
    state = _login_attempts.setdefault(source, _AttemptState())
    state.failures += 1
    if state.failures >= config.LOGIN_MAX_ATTEMPTS:
        state.locked_until = time.time() + config.LOGIN_LOCKOUT_SECONDS


def reset_attempts(source: str) -> None:
    _login_attempts.pop(source, None)


def is_locked_out(source: str) -> bool:
    state = _login_attempts.get(source)
    if not state:
        return False
    if state.locked_until and time.time() < state.locked_until:
        return True
    if state.locked_until and time.time() >= state.locked_until:
        _login_attempts.pop(source, None)
    return False


# --- FastAPI dependency ------------------------------------------------------

def get_current_user(request: Request, nxcweb_session: str | None = Cookie(default=None)) -> str:
    token = nxcweb_session
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    username = verify_session_token(token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")
    user = get_user(username)
    if not user or not user["enabled"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is disabled or missing")
    return user["username"]


def require_admin(user: str = Depends(get_current_user)) -> str:
    account = get_user(user)
    if not account or account["role"] != ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required")
    return account["username"]


def verify_ws_session(token: str | None) -> str | None:
    if not token:
        return None
    username = verify_session_token(token)
    user = get_user(username) if username else None
    return user["username"] if user and user["enabled"] else None
