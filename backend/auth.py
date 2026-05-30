"""
Authentication module for Athena Attendance System.
Uses bcrypt for password hashing and itsdangerous for signed session cookies.
"""
import bcrypt
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# In-memory rate limiting store
_rate_limit_store: dict[str, list[datetime]] = {}


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with strong rounds."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(password_hash, str):
        password_hash = password_hash.encode('utf-8')
    return bcrypt.checkpw(password, password_hash)


def check_rate_limit(ip: str, max_attempts: int, window_minutes: int) -> bool:
    """
    Check if an IP is rate-limited.
    Returns True if request is allowed, False if rate-limited.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)

    # Clean old entries
    if ip in _rate_limit_store:
        _rate_limit_store[ip] = [
            t for t in _rate_limit_store[ip] if t > window_start
        ]
    else:
        _rate_limit_store[ip] = []

    if len(_rate_limit_store[ip]) >= max_attempts:
        return False  # Rate limited

    _rate_limit_store[ip].append(now)
    return True  # Allowed


def reset_rate_limit(ip: str):
    """Reset rate limit counter for an IP (e.g., after successful login)."""
    if ip in _rate_limit_store:
        del _rate_limit_store[ip]


def generate_session_id() -> str:
    """Generate a cryptographically secure random session ID."""
    return secrets.token_urlsafe(48)


def get_session_timeout_minutes(config_value: str) -> int:
    """Parse session timeout from config, default to 30."""
    try:
        return int(config_value)
    except (ValueError, TypeError):
        return 30


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return secrets.token_hex(32)
