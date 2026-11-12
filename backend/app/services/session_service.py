"""
SENTRIX Browser Session Management Service
-------------------------------------------
Cryptographically secure opaque browser sessions and CSRF synchronizer tokens.
Stores only SHA-256 hashes of tokens in SQLite/PostgreSQL.
Enforces 60-minute inactivity timeout, 12-hour absolute lifetime ceiling,
and atomic conditional write throttling (5 minutes) for activity updates.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
import secrets
from typing import Optional, Tuple
from fastapi import Response
from sqlalchemy.orm import Session

from backend.app.models.session import UserSession

logger = logging.getLogger(__name__)

# Lifespan Constants
SESSION_INACTIVITY_TIMEOUT_SECONDS = 3600   # 60 minutes
SESSION_ABSOLUTE_LIFETIME_SECONDS = 43200   # 12 hours
SESSION_ACTIVITY_THROTTLE_SECONDS = 300     # 5 minutes atomic write throttle

# Cookie Constants
COOKIE_NAME = "sentrix_session"
COOKIE_MAX_AGE = SESSION_ABSOLUTE_LIFETIME_SECONDS  # 43200 seconds (12 hours)
COOKIE_PATH = "/"
COOKIE_SAMESITE = "lax"


def is_cookie_secure() -> bool:
    """
    Determines whether session cookies must have the Secure attribute.
    - True in production (or if SENTRIX_COOKIE_SECURE=true)
    - False in local development without HTTPS
    """
    env_override = os.getenv("SENTRIX_COOKIE_SECURE", "").strip().lower()
    if env_override in ("true", "1", "yes"):
        return True
    if env_override in ("false", "0", "no"):
        return False
    env_mode = (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").lower()
    return env_mode in ("production", "prod")


def set_session_cookie(response: Response, raw_session_token: str) -> None:
    """Sets the secure, HttpOnly, SameSite=Lax session cookie."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=raw_session_token,
        max_age=COOKIE_MAX_AGE,
        path=COOKIE_PATH,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=is_cookie_secure(),
    )


def clear_session_cookie(response: Response) -> None:
    """Deletes the session cookie using exact matching attributes."""
    response.delete_cookie(
        key=COOKIE_NAME,
        path=COOKIE_PATH,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=is_cookie_secure(),
    )


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 hex digest of a raw token. Never logs or leaks the raw token."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def _ensure_utc(dt: datetime) -> datetime:
    """Guarantees timezone-aware UTC comparison regardless of database dialect."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_csrf_secret() -> str:
    """
    Retrieves secret for CSRF token HMAC derivation.
    Checks SENTRIX_CSRF_SECRET first; if not configured, falls back to get_jwt_secret().
    Never logs or exposes the secret.
    """
    csrf_secret = os.getenv("SENTRIX_CSRF_SECRET", "").strip()
    if csrf_secret:
        return csrf_secret
    from backend.app.services.auth import get_jwt_secret
    return get_jwt_secret()


def derive_session_csrf_token(session_id: str) -> str:
    """
    Derives a deterministic, session-bound CSRF token using HMAC-SHA256.
    Explicit domain separation prefix 'csrf:' prevents cross-protocol reuse.
    """
    secret = get_csrf_secret().encode("utf-8")
    message = f"csrf:{session_id}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def get_session_csrf_token(session: UserSession) -> str:
    """
    Returns the deterministic session-bound CSRF token for an active session.
    Guarantees multi-tab stability (repeated /session/me calls return identical token).
    """
    return derive_session_csrf_token(session.id)


def create_session(db: Session, user_id: int) -> Tuple[str, str, UserSession]:
    """
    Creates a new browser session for a user.
    Generates opaque session token (>= 32 random bytes) and derives a deterministic,
    session-bound CSRF token using HMAC-SHA256 with domain separation.
    Stores only their SHA-256 hashes in the database.
    Returns (raw_session_token, raw_csrf_token, session_model).
    """
    raw_session_token = secrets.token_urlsafe(32)
    session_id = hash_token(raw_session_token)
    raw_csrf_token = derive_session_csrf_token(session_id)
    csrf_hash = hash_token(raw_csrf_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=SESSION_ABSOLUTE_LIFETIME_SECONDS)

    session = UserSession(
        id=session_id,
        user_id=user_id,
        csrf_token_hash=csrf_hash,
        created_at=now,
        expires_at=expires_at,
        last_activity_at=now,
        revoked=False,
        revoked_at=None,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return raw_session_token, raw_csrf_token, session


def get_valid_session(db: Session, raw_session_token: str) -> Optional[UserSession]:
    """
    Validates a session by its raw token.
    1. Computes SHA-256 hash and looks up database record.
    2. Rejects revoked sessions.
    3. Enforces 12-hour absolute lifetime ceiling (immutable).
    4. Enforces 60-minute inactivity timeout.
    5. Performs atomic conditional write update if activity is older than 5 minutes.
    """
    if not raw_session_token or not raw_session_token.strip():
        return None

    session_id = hash_token(raw_session_token)
    session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not session or session.revoked:
        return None

    now = datetime.now(timezone.utc)

    # 1. Absolute Maximum Lifetime Check (12 hours) - Never extended
    if now > _ensure_utc(session.expires_at):
        session.revoked = True
        session.revoked_at = now
        db.commit()
        return None

    # 2. Inactivity Timeout Check (60 minutes)
    if (now - _ensure_utc(session.last_activity_at)).total_seconds() > SESSION_INACTIVITY_TIMEOUT_SECONDS:
        session.revoked = True
        session.revoked_at = now
        db.commit()
        return None

    # 3. Atomic Conditional Write Throttling (5-minute window)
    throttle_cutoff = now - timedelta(seconds=SESSION_ACTIVITY_THROTTLE_SECONDS)
    updated = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.last_activity_at < throttle_cutoff,
            UserSession.revoked == False,
        )
        .update({"last_activity_at": now}, synchronize_session=False)
    )
    if updated > 0:
        db.commit()
        db.refresh(session)

    return session


def rotate_session_csrf_token(db: Session, session: UserSession) -> str:
    """
    Legacy helper: returns the deterministic session-bound CSRF token without
    corrupting the session's stored state.
    """
    raw_csrf_token = derive_session_csrf_token(session.id)
    session.csrf_token_hash = hash_token(raw_csrf_token)
    db.commit()
    db.refresh(session)
    return raw_csrf_token


def verify_csrf_token(session: UserSession, raw_csrf_token: Optional[str]) -> bool:
    """
    Validates submitted CSRF token against the session's stored hash and deterministic HMAC derivation.
    Fails closed if token is missing, session is revoked, or hashes mismatch.
    Uses constant-time comparison.
    """
    if not raw_csrf_token or not raw_csrf_token.strip() or session.revoked:
        return False

    token_val = raw_csrf_token.strip()
    expected_token = derive_session_csrf_token(session.id)
    submitted_hash = hash_token(token_val)

    match_derivation = hmac.compare_digest(token_val, expected_token)
    match_hash = hmac.compare_digest(submitted_hash, session.csrf_token_hash)

    return match_derivation and match_hash


def revoke_session(db: Session, raw_session_token: str) -> bool:
    """
    Revokes a specific session immediately in the database.
    Returns True if an active session was revoked, False otherwise.
    """
    if not raw_session_token or not raw_session_token.strip():
        return False

    session_id = hash_token(raw_session_token)
    now = datetime.now(timezone.utc)
    count = (
        db.query(UserSession)
        .filter(UserSession.id == session_id, UserSession.revoked == False)
        .update({"revoked": True, "revoked_at": now})
    )
    db.commit()
    return count > 0


def revoke_all_user_sessions(db: Session, user_id: int) -> int:
    """
    Revokes all active sessions for a user across all devices/browsers.
    Useful for password changes and administrative lockouts.
    """
    now = datetime.now(timezone.utc)
    count = (
        db.query(UserSession)
        .filter(UserSession.user_id == user_id, UserSession.revoked == False)
        .update({"revoked": True, "revoked_at": now})
    )
    db.commit()
    return count
