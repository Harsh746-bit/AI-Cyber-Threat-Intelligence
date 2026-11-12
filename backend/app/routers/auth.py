from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.models.user import User
from backend.app.services.auth import (
    create_access_token,
    get_current_user,
    validate_request_origin,
    verify_password,
)
from backend.app.services import session_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


# ============================================================================
# CLI / Programmatic Authentication (Bearer JWT)
# ============================================================================

@router.post("/login")
def login(
    login_req: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    CLI / API authentication endpoint.
    Returns JWT access token and user info for programmatic use.
    """
    username = login_req.username.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(login_req.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    token = create_access_token({
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        },
    }


@router.get("/me")
def get_auth_me(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Returns the authenticated user's profile (supports Bearer JWT or session cookie).
    """
    user = get_current_user(request, db)
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


# ============================================================================
# Browser-Only Session Authentication (HttpOnly Cookie + CSRF Synchronizer)
# ============================================================================

@router.post("/session/login")
def session_login(
    login_req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Browser login endpoint:
    1. Validates request origin against trusted origins (Login CSRF prevention).
    2. Verifies user credentials.
    3. Creates opaque session and issues HttpOnly, SameSite=Lax cookie.
    4. Returns CSRF synchronizer token and user profile in JSON body.
       (Never exposes raw session token in JSON).
    """
    validate_request_origin(request)

    username = login_req.username.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(login_req.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    raw_session_token, raw_csrf_token, session_obj = session_service.create_session(db, user.id)
    session_service.set_session_cookie(response, raw_session_token)

    return {
        "csrf_token": raw_csrf_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        },
    }


@router.get("/session/me")
def session_me(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Hydrates browser session state on page refresh:
    1. Rejects mixed credentials (cookie + Authorization header) with HTTP 400.
    2. Validates session cookie, lifetime ceiling, and inactivity timeout.
    3. Rotates CSRF synchronizer token and returns fresh token in response JSON.
    """
    auth_header = request.headers.get("Authorization")
    raw_cookie = request.cookies.get("sentrix_session")

    if auth_header and raw_cookie:
        raise HTTPException(
            status_code=400,
            detail="Ambiguous authentication credentials: both session cookie and Authorization header provided",
        )

    if not raw_cookie:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required",
        )

    session_obj = session_service.get_valid_session(db, raw_cookie)
    if not session_obj:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or revoked session",
        )

    user = db.query(User).filter(User.id == session_obj.user_id).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User account not found",
        )

    raw_csrf_token = session_service.get_session_csrf_token(session_obj)

    return {
        "csrf_token": raw_csrf_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
    }


@router.post("/session/logout")
def session_logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Browser logout endpoint:
    1. Rejects mixed credentials with HTTP 400.
    2. Validates request origin and CSRF synchronizer token.
    3. Revokes session in database.
    4. Clears session cookie using identical matching attributes.
    """
    auth_header = request.headers.get("Authorization")
    raw_cookie = request.cookies.get("sentrix_session")

    if auth_header and raw_cookie:
        raise HTTPException(
            status_code=400,
            detail="Ambiguous authentication credentials: both session cookie and Authorization header provided",
        )

    if not raw_cookie:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required",
        )

    validate_request_origin(request)

    session_obj = session_service.get_valid_session(db, raw_cookie)
    if not session_obj:
        session_service.clear_session_cookie(response)
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or revoked session",
        )

    csrf_header = request.headers.get("X-SENTRIX-CSRF")
    if not csrf_header or not session_service.verify_csrf_token(session_obj, csrf_header):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    session_service.revoke_session(db, raw_cookie)
    session_service.clear_session_cookie(response)

    return {"message": "Logged out successfully"}
