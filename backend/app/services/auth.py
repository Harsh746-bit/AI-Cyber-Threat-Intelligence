"""
SENTRIX Authentication & Role-Based Access Control (RBAC) Service
------------------------------------------------------------------
Standard-library compliant JWT (HS256) and PBKDF2-HMAC-SHA256 password hashing.
Zero external C-dependencies, Python 3.12 compatible.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.services import session_service

# Secret & Algorithm Configuration
JWT_ALGORITHM = "HS256"
DEFAULT_EXPIRATION_SECONDS = 86400  # 24 hours
MINIMUM_SECRET_BYTES = 32

_EPHEMERAL_DEV_SECRET: Optional[str] = None


def get_jwt_secret() -> str:
    """
    Retrieves and validates the JWT signing secret.
    - In production (SENTRIX_ENV=production or APP_ENV=production):
        * Requires a configured JWT_SECRET of at least 32 bytes.
        * Rejects default demo keys or short/predictable keys with ValueError.
    - In development / testing:
        * Uses JWT_SECRET if configured.
        * Otherwise generates an ephemeral 32-byte secret for this process session.
    Never prints or logs the secret material.
    """
    global _EPHEMERAL_DEV_SECRET
    env_mode = (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").lower()
    is_production = env_mode in ("production", "prod")

    secret = os.getenv("JWT_SECRET")

    if is_production:
        if not secret:
            raise ValueError(
                "Insecure Configuration: JWT_SECRET environment variable is missing in production. "
                "A cryptographically random secret with at least 32 characters is required."
            )
        if len(secret.encode("utf-8")) < MINIMUM_SECRET_BYTES:
            raise ValueError(
                f"Insecure Configuration: JWT_SECRET in production must have at least {MINIMUM_SECRET_BYTES} bytes of entropy."
            )
        insecure_defaults = {
            "sentrix-cyber-threat-intelligence-secret-key-2026",
            "sentrix-production-cyber-intelligence-key-2026",
            "secret",
            "changeme",
            "password",
        }
        if secret in insecure_defaults:
            raise ValueError(
                "Insecure Configuration: Known default or insecure JWT_SECRET cannot be used in production."
            )
        return secret

    # Development / Testing fallback
    if secret:
        return secret

    if _EPHEMERAL_DEV_SECRET is None:
        _EPHEMERAL_DEV_SECRET = secrets.token_urlsafe(MINIMUM_SECRET_BYTES)

    return _EPHEMERAL_DEV_SECRET


# ============================================================================
# Password Hashing via PBKDF2-HMAC-SHA256
# ============================================================================

def hash_password(password: str) -> str:
    """Hashes a password with a cryptographically secure random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    )
    return f"pbkdf2_sha256$100000${salt}${dk.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2 hash."""
    if not password_hash or not password_hash.startswith("pbkdf2_sha256$"):
        return False

    try:
        parts = password_hash.split("$")
        if len(parts) != 4:
            return False
        _, iterations_str, salt, stored_hash = parts
        iterations = int(iterations_str)

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=iterations,
        )
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False


# ============================================================================
# Base64URL and JWT Token Utilities (RFC 7519)
# ============================================================================

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _base64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def create_access_token(data: Dict[str, Any], expires_delta_seconds: int = DEFAULT_EXPIRATION_SECONDS) -> str:
    """Generates a standard HS256-signed JWT token using validated secret."""
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    now = int(time.time())
    payload = dict(data)
    payload.setdefault("iat", now)
    payload.setdefault("exp", now + expires_delta_seconds)

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = _base64url_encode(header_bytes)
    payload_b64 = _base64url_encode(payload_bytes)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret = get_jwt_secret()
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a standard HS256 JWT token using validated secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        secret = get_jwt_secret()
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_sig = _base64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, provided_sig):
            return None

        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Verify expiration
        exp = payload.get("exp")
        if exp is not None and time.time() > float(exp):
            return None

        return payload
    except Exception:
        return None


# ============================================================================
# Default User Seeding
# ============================================================================

def seed_default_users(db: Session):
    """
    Ensures baseline admin and analyst accounts exist.
    In production (SENTRIX_ENV=production or APP_ENV=production):
        * Passwords MUST be provided via ADMIN_INITIAL_PASSWORD and ANALYST_INITIAL_PASSWORD.
        * Refuses to seed known default passwords, raising ValueError.
    In development / testing:
        * Uses environment passwords if provided, falling back to local dev credentials with a warning.
    """
    env_mode = (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").lower()
    is_production = env_mode in ("production", "prod")

    admin_pwd = os.getenv("ADMIN_INITIAL_PASSWORD")
    analyst_pwd = os.getenv("ANALYST_INITIAL_PASSWORD")

    if is_production:
        if not admin_pwd or not admin_pwd.strip():
            raise ValueError(
                "Insecure Configuration: ADMIN_INITIAL_PASSWORD must be provided in production to seed the admin account."
            )
        if not analyst_pwd or not analyst_pwd.strip():
            raise ValueError(
                "Insecure Configuration: ANALYST_INITIAL_PASSWORD must be provided in production to seed the analyst account."
            )
    else:
        # Development fallbacks
        admin_pwd = admin_pwd or "sentrix123"
        analyst_pwd = analyst_pwd or "analyst123"

    user_configs = [
        {"username": "admin", "password": admin_pwd, "role": "admin"},
        {"username": "analyst", "password": analyst_pwd, "role": "analyst"},
    ]

    for u in user_configs:
        existing = db.query(User).filter(User.username == u["username"]).first()
        if not existing:
            new_user = User(
                username=u["username"],
                password_hash=hash_password(u["password"]),
                role=u["role"],
            )
            db.add(new_user)
    try:
        db.commit()
    except Exception:
        db.rollback()


# ============================================================================
# Origin & CSRF Verification
# ============================================================================

def get_trusted_origins(request: Optional[Request] = None) -> set[str]:
    """
    Returns trusted origins for CORS and CSRF verification.
    Origins are normalized to lower-case scheme://netloc (without trailing slashes).
    """
    env_mode = (os.getenv("SENTRIX_ENV") or os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "development").lower()
    is_production = env_mode in ("production", "prod")

    trusted = set()
    raw = os.getenv("SENTRIX_CORS_ORIGINS", "").strip()
    if raw:
        for o in raw.split(","):
            val = o.strip().rstrip("/").lower()
            if val and val != "*":
                trusted.add(val)

    if not is_production:
        trusted.update([
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ])

    trusted.update(["http://testserver", "https://testserver"])
    return trusted


def validate_request_origin(request: Request) -> None:
    """
    Validates request Origin or Referer against trusted origins to prevent CSRF attacks.
    On state-changing requests, missing Origin/Referer is rejected with HTTP 403.
    Untrusted Origin/Referer is rejected with HTTP 403.
    """
    trusted = get_trusted_origins(request)
    origin = request.headers.get("Origin")
    if origin:
        norm_origin = origin.strip().rstrip("/").lower()
        if norm_origin not in trusted:
            raise HTTPException(status_code=403, detail="Untrusted request origin")
        return

    referer = request.headers.get("Referer")
    if referer:
        parsed = urlparse(referer.strip())
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=403, detail="Malformed referer header")
        norm_referer = f"{parsed.scheme}://{parsed.netloc}".lower()
        if norm_referer not in trusted:
            raise HTTPException(status_code=403, detail="Untrusted request referer")
        return

    raise HTTPException(
        status_code=403,
        detail="Missing Origin and Referer headers on state-changing request",
    )


# ============================================================================
# FastAPI Dependencies & RBAC Guards (Dual-Mode: Bearer JWT & Cookie Sessions)
# ============================================================================

def authenticate_request(
    request: Request,
    db: Session,
    allowed_roles: Optional[List[str]] = None,
) -> User:
    """
    Core dual-mode authentication validator.
    1. Rejects mixed credentials (session cookie + ANY Authorization header) with HTTP 400.
    2. Supports CLI/programmatic clients via Bearer JWT in Authorization header.
    3. Supports browser clients via secure HttpOnly session cookie + CSRF synchronizer token.
    4. Evaluates user account status and role directly against the database.
    """
    auth_header = request.headers.get("Authorization")
    raw_cookie = request.cookies.get("sentrix_session")

    # 1. Reject requests containing both a session cookie and ANY Authorization header
    if auth_header and raw_cookie:
        raise HTTPException(
            status_code=400,
            detail="Ambiguous authentication credentials: both session cookie and Authorization header provided",
        )

    # 2. Reject if neither credential is provided
    if not auth_header and not raw_cookie:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required",
        )

    user: Optional[User] = None

    # 3. CLI / API Bearer JWT Authentication
    if auth_header:
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid Authorization header format")

        token = parts[1]
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired access token")

        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token missing subject identity")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User account not found")

    # 4. Browser Session Cookie Authentication
    elif raw_cookie:
        session = session_service.get_valid_session(db, raw_cookie)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid, expired, or revoked session")

        # For state-changing methods, enforce Origin verification and CSRF token
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            validate_request_origin(request)
            csrf_header = request.headers.get("X-SENTRIX-CSRF")
            if not csrf_header or not session_service.verify_csrf_token(session, csrf_header):
                raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

        user = db.query(User).filter(User.id == session.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User account not found")

    # 5. Enforce RBAC
    if allowed_roles is not None and user.role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Action requires one of {allowed_roles} role(s)",
        )

    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Validates user identity via Bearer JWT or browser session cookie."""
    return authenticate_request(request, db, allowed_roles=None)


def require_role(allowed_roles: List[str]):
    """
    Factory creating a FastAPI dependency that enforces RBAC roles.
    Supports both Bearer JWT and secure browser session cookies.
    Can be used via Depends(require_role([...])) or invoked directly.
    """
    def role_dependency(request: Request, db: Session = Depends(get_db)) -> User:
        return authenticate_request(request, db, allowed_roles=allowed_roles)

    return role_dependency
