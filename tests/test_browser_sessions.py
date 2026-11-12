import os
import hashlib
import time
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app, get_db
from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.models.incident import Incident
from backend.app.models.session import UserSession
from backend.app.models.user import User
from backend.app.services.auth import seed_default_users, create_access_token
from backend.app.services import session_service

test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

Base.metadata.create_all(bind=test_engine)
ensure_schema_migrations(test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    ensure_schema_migrations(test_engine)
    db = TestingSessionLocal()
    seed_default_users(db)
    db.close()
    monkeypatch.setenv("SENTRIX_SENSOR_API_KEY", "test-sensor-api-key-secure-value-32chars!")
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_reject_mixed_credentials_bearer_and_cookie(client):
    """
    Mandatory clarification 1:
    Reject requests containing both a session cookie and ANY Authorization header with HTTP 400.
    """
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    response = client.get(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        cookies={"sentrix_session": "any-mock-cookie-value"},
    )
    assert response.status_code == 400
    assert "Ambiguous authentication credentials" in response.json()["detail"]


def test_reject_mixed_credentials_arbitrary_auth_header_and_cookie(client):
    """
    Verify rejection applies to ANY Authorization header (e.g. Basic, Token, custom).
    """
    response = client.get(
        "/api/v1/incidents",
        headers={"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
        cookies={"sentrix_session": "any-mock-cookie-value"},
    )
    assert response.status_code == 400
    assert "Ambiguous authentication credentials" in response.json()["detail"]


def test_session_login_flow_and_cookie_attributes(client):
    """
    POST /auth/session/login sets secure HttpOnly cookie and returns CSRF token in JSON.
    Never exposes raw session token in JSON response body.
    """
    response = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    data = response.json()

    # 1. Verify JSON payload
    assert "csrf_token" in data
    assert len(data["csrf_token"]) >= 32
    assert "user" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"
    assert "access_token" not in data
    assert "session_token" not in data

    # 2. Verify Cookie attributes
    assert "sentrix_session" in response.cookies
    cookie = response.cookies["sentrix_session"]
    assert len(cookie) >= 32

    # Verify Set-Cookie header directives
    set_cookie_header = response.headers.get("set-cookie", "")
    assert "sentrix_session=" in set_cookie_header
    assert "HttpOnly" in set_cookie_header
    assert "SameSite=lax" in set_cookie_header or "samesite=lax" in set_cookie_header.lower()
    assert "Path=/" in set_cookie_header or "path=/" in set_cookie_header.lower()


def test_database_stores_only_sha256_token_hashes(client):
    """
    Verify neither the raw session token nor raw CSRF token are stored in plaintext in the DB.
    Only SHA-256 hashes must be stored.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_resp.status_code == 200
    raw_csrf = login_resp.json()["csrf_token"]
    raw_session = login_resp.cookies["sentrix_session"]

    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        csrf_hash = hashlib.sha256(raw_csrf.encode("utf-8")).hexdigest()

        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        assert record is not None
        assert record.id == session_id
        assert record.csrf_token_hash == csrf_hash

        # Verify plaintext tokens do NOT appear anywhere in the database row
        assert raw_session not in str(record.__dict__)
        assert raw_csrf not in str(record.__dict__)
    finally:
        db.close()


def test_login_csrf_defense_rejects_untrusted_origin(client):
    """
    POST /auth/session/login from an untrusted origin must be rejected with HTTP 403.
    """
    response = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://malicious-origin.com"},
    )
    assert response.status_code == 403
    assert "Untrusted request origin" in response.json()["detail"]


def test_safe_get_request_succeeds_without_csrf_token(client):
    """
    Safe HTTP GET requests require only the session cookie, not X-SENTRIX-CSRF.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "analyst", "password": "analyst123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_resp.status_code == 200
    raw_session = login_resp.cookies["sentrix_session"]

    # GET /incidents without CSRF header
    resp = client.get(
        "/api/v1/incidents",
        cookies={"sentrix_session": raw_session},
    )
    assert resp.status_code == 200
    assert "incidents" in resp.json()


def test_session_me_hydrates_deterministic_csrf_token(client):
    """
    GET /auth/session/me verifies the session cookie and returns the deterministic CSRF token.
    Repeated calls return the identical token.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "analyst", "password": "analyst123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_resp.status_code == 200
    initial_csrf = login_resp.json()["csrf_token"]
    raw_session = login_resp.cookies["sentrix_session"]

    me_resp = client.get(
        "/api/v1/auth/session/me",
        cookies={"sentrix_session": raw_session},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["user"]["username"] == "analyst"
    csrf_from_me = me_data["csrf_token"]

    # CSRF token must match initial login token identically
    assert csrf_from_me == initial_csrf

    # DB record must reflect the correct CSRF hash
    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        assert record.csrf_token_hash == hashlib.sha256(csrf_from_me.encode("utf-8")).hexdigest()
    finally:
        db.close()


def test_mutating_request_fails_without_csrf_header(client):
    """
    State-changing requests with cookie but missing X-SENTRIX-CSRF must be rejected with 403.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]

    # Create incident in DB
    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=101,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/101/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173"},
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 403
    assert "Invalid or missing CSRF token" in patch_resp.json()["detail"]


def test_mutating_request_fails_with_mismatched_csrf_token(client):
    """
    State-changing requests with mismatched CSRF token must be rejected with 403.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]

    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=102,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/102/status",
        json={"status": "INVESTIGATING"},
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": "completely-wrong-csrf-token",
        },
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 403
    assert "Invalid or missing CSRF token" in patch_resp.json()["detail"]


def test_mutating_request_succeeds_with_valid_cookie_and_csrf(client):
    """
    State-changing requests with valid cookie, valid CSRF token, and trusted origin succeed.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=103,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/103/status",
        json={"status": "INVESTIGATING"},
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"


def test_mutating_request_fails_with_untrusted_origin(client):
    """
    Valid cookie and CSRF token, but cross-site untrusted Origin must be rejected with 403.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=103,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/103/status",
        json={"status": "RESOLVED"},
        headers={
            "Origin": "http://evil-attacker.com",
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 403
    assert "Untrusted request origin" in patch_resp.json()["detail"]


def test_mutating_request_fails_with_missing_origin_and_referer(client):
    """
    Cookie-authenticated mutating request with NO Origin and NO Referer must be rejected with 403.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=103,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/103/status",
        json={"status": "RESOLVED"},
        headers={
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 403
    assert "Missing Origin and Referer headers" in patch_resp.json()["detail"]


def test_mutating_request_succeeds_with_trusted_referer_when_origin_absent(client):
    """
    When Origin header is absent (e.g. some browser navigations), a valid trusted Referer succeeds.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=103,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    patch_resp = client.patch(
        "/api/v1/incidents/103/status",
        json={"status": "RESOLVED"},
        headers={
            "Referer": "http://localhost:5173/incidents/103",
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "RESOLVED"


def test_absolute_session_ceiling_12_hours(client):
    """
    Backend enforces immutable 12-hour absolute ceiling.
    Expired sessions fail with 401 and are marked revoked.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]

    # Manually expire the session past 12-hour ceiling in DB
    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()
    finally:
        db.close()

    resp = client.get(
        "/api/v1/incidents",
        cookies={"sentrix_session": raw_session},
    )
    assert resp.status_code == 401
    assert "Invalid, expired, or revoked session" in resp.json()["detail"]

    # Verify session is now revoked in DB
    db = TestingSessionLocal()
    try:
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        assert record.revoked is True
        assert record.revoked_at is not None
    finally:
        db.close()


def test_inactivity_timeout_60_minutes(client):
    """
    Backend enforces 60-minute inactivity timeout.
    Sessions inactive for > 60 minutes fail with 401 and are revoked.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "analyst", "password": "analyst123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]

    # Set last_activity_at to 61 minutes ago
    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        record.last_activity_at = datetime.now(timezone.utc) - timedelta(minutes=61)
        db.commit()
    finally:
        db.close()

    resp = client.get(
        "/api/v1/incidents",
        cookies={"sentrix_session": raw_session},
    )
    assert resp.status_code == 401
    assert "Invalid, expired, or revoked session" in resp.json()["detail"]


def test_activity_write_throttling_5_minutes(client):
    """
    Atomic conditional update throttles last_activity_at writes to 5-minute intervals.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]

    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        initial_record = db.query(UserSession).filter(UserSession.id == session_id).first()
        t0 = initial_record.last_activity_at

        # Immediate follow-up request (under 5 minutes)
        client.get("/api/v1/incidents", cookies={"sentrix_session": raw_session})

        record_after_immediate = db.query(UserSession).filter(UserSession.id == session_id).first()
        assert record_after_immediate.last_activity_at == t0

        # Now simulate elapsed time greater than 5 minutes (e.g. 6 minutes ago)
        six_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=6)
        initial_record.last_activity_at = six_minutes_ago
        db.commit()

        # Next request should trigger the atomic conditional update
        client.get("/api/v1/incidents", cookies={"sentrix_session": raw_session})

        db.refresh(initial_record)
        assert session_service._ensure_utc(initial_record.last_activity_at) > six_minutes_ago
    finally:
        db.close()


def test_session_logout_and_revocation(client):
    """
    POST /auth/session/logout revokes session in DB, deletes cookie with matching attributes,
    and subsequent replay of the revoked cookie fails with 401.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    logout_resp = client.post(
        "/api/v1/auth/session/logout",
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["message"] == "Logged out successfully"

    # Verify cookie was cleared with matching attributes
    set_cookie_header = logout_resp.headers.get("set-cookie", "")
    assert "sentrix_session=" in set_cookie_header
    assert "HttpOnly" in set_cookie_header
    assert "SameSite=lax" in set_cookie_header or "samesite=lax" in set_cookie_header.lower()
    assert "Path=/" in set_cookie_header or "path=/" in set_cookie_header.lower()

    # Verify DB revoked state
    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        assert record.revoked is True
        assert record.revoked_at is not None
    finally:
        db.close()

    # Replaying the revoked cookie fails
    replay_resp = client.get(
        "/api/v1/incidents",
        cookies={"sentrix_session": raw_session},
    )
    assert replay_resp.status_code == 401
    assert "Invalid, expired, or revoked session" in replay_resp.json()["detail"]


def test_immediate_rbac_enforcement_on_role_change(client):
    """
    Role changes in the database take immediate effect on the next cookie-authenticated request.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    # Demote admin to analyst in the database
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        user.role = "analyst"
        db.commit()

        # Create test incident
        inc = Incident(
            id=104,
            severity="HIGH",
            status="OPEN",
            risk_score=75.0,
            source_ip="192.168.1.100",
            reasons="Test",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Demoted user tries admin-only endpoint: PATCH /incidents/{id}/status
    patch_resp = client.patch(
        "/api/v1/incidents/104/status",
        json={"status": "INVESTIGATING"},
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": raw_csrf,
        },
        cookies={"sentrix_session": raw_session},
    )
    # Must immediately return 403 Forbidden!
    assert patch_resp.status_code == 403
    assert "Forbidden" in patch_resp.json()["detail"]


def test_cli_bearer_jwt_and_sensor_auth_isolation(client):
    """
    Verify complete isolation:
    1. CLI Bearer JWT login continues to work.
    2. Bearer JWT requests succeed without cookies or CSRF tokens.
    3. Sensor telemetry ingestion works via X-SENTRIX-SENSOR-KEY without cookies or tokens.
    """
    # 1. CLI Login
    cli_login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "sentrix123"},
    )
    assert cli_login_resp.status_code == 200
    cli_data = cli_login_resp.json()
    assert "access_token" in cli_data
    token = cli_data["access_token"]

    # 2. Programmatic API call with Bearer JWT (no cookie, no CSRF)
    api_resp = client.get(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert api_resp.status_code == 200

    # 3. Sensor API call with X-SENTRIX-SENSOR-KEY (no cookie, no CSRF, no JWT)
    sensor_resp = client.post(
        "/api/v1/events",
        headers={"X-SENTRIX-SENSOR-KEY": "test-sensor-api-key-secure-value-32chars!"},
        json={
            "source_ip": "10.0.0.99",
            "destination_ip": "10.0.0.1",
            "features": {"Flow Duration": 100.0, "Total Fwd Packets": 10.0},
        },
    )
    assert sensor_resp.status_code in (200, 201, 202)


# ============================================================================
# Phase 3B.3.1 Dedicated Multi-Tab & Deterministic CSRF Tests
# ============================================================================

def test_login_returns_valid_session_bound_csrf_token(client):
    """
    Requirement 1: Login returns a valid deterministic, session-bound CSRF token.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    csrf_token = data["csrf_token"]
    raw_session = login_resp.cookies["sentrix_session"]
    session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()

    # Verify deterministic HMAC derivation
    expected = session_service.derive_session_csrf_token(session_id)
    assert csrf_token == expected
    assert len(csrf_token) == 64


def test_repeated_session_me_calls_return_identical_token(client):
    """
    Requirement 2: Repeated /session/me calls return the exact same token and do not rotate.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "analyst", "password": "analyst123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    login_csrf = login_resp.json()["csrf_token"]

    tokens = []
    for _ in range(5):
        resp = client.get(
            "/api/v1/auth/session/me",
            cookies={"sentrix_session": raw_session},
        )
        assert resp.status_code == 200
        tokens.append(resp.json()["csrf_token"])

    # All 5 calls returned the exact same token matching login
    assert all(t == login_csrf for t in tokens)


def test_two_tabs_sharing_session_can_both_perform_state_changing_operations(client):
    """
    Requirement 3: Two tabs sharing one session can both perform state-changing operations independently.
    """
    # Tab A logs in
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    tab_a_csrf = login_resp.json()["csrf_token"]

    # Tab B opens and fetches session
    tab_b_resp = client.get(
        "/api/v1/auth/session/me",
        cookies={"sentrix_session": raw_session},
    )
    tab_b_csrf = tab_b_resp.json()["csrf_token"]

    # Both tabs must hold the same valid CSRF token
    assert tab_a_csrf == tab_b_csrf

    # Insert test incidents
    db = TestingSessionLocal()
    try:
        inc1 = Incident(id=201, severity="HIGH", status="OPEN", risk_score=80.0, source_ip="10.0.0.1", reasons="TabA")
        inc2 = Incident(id=202, severity="HIGH", status="OPEN", risk_score=80.0, source_ip="10.0.0.2", reasons="TabB")
        db.add_all([inc1, inc2])
        db.commit()
    finally:
        db.close()

    # Tab A performs mutation
    res_a = client.patch(
        "/api/v1/incidents/201/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": tab_a_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert res_a.status_code == 200
    assert res_a.json()["status"] == "INVESTIGATING"

    # Tab B performs mutation
    res_b = client.patch(
        "/api/v1/incidents/202/status",
        json={"status": "RESOLVED"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": tab_b_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert res_b.status_code == 200
    assert res_b.json()["status"] == "RESOLVED"


def test_refreshing_tab_b_does_not_invalidate_tab_a(client):
    """
    Requirement 4: Refreshing Tab B multiple times does not invalidate Tab A's CSRF token.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    tab_a_csrf = login_resp.json()["csrf_token"]

    # Refresh Tab B 5 times
    for _ in range(5):
        me_resp = client.get(
            "/api/v1/auth/session/me",
            cookies={"sentrix_session": raw_session},
        )
        assert me_resp.status_code == 200

    # Insert incident
    db = TestingSessionLocal()
    try:
        inc = Incident(id=203, severity="HIGH", status="OPEN", risk_score=70.0, source_ip="10.0.0.3", reasons="TabTest")
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Tab A mutation must STILL succeed with HTTP 200
    res_a = client.patch(
        "/api/v1/incidents/203/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": tab_a_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert res_a.status_code == 200
    assert res_a.json()["status"] == "INVESTIGATING"


def test_csrf_token_from_another_session_is_rejected(client):
    """
    Requirement 5: A CSRF token from another session is rejected with HTTP 403.
    """
    # User 1 logs in
    resp1 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    session1_cookie = resp1.cookies["sentrix_session"]
    csrf_token_1 = resp1.json()["csrf_token"]

    # User 2 logs in
    resp2 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "analyst", "password": "analyst123"},
        headers={"Origin": "http://localhost:5173"},
    )
    session2_cookie = resp2.cookies["sentrix_session"]
    csrf_token_2 = resp2.json()["csrf_token"]

    assert csrf_token_1 != csrf_token_2

    # Insert incident
    db = TestingSessionLocal()
    try:
        inc = Incident(id=204, severity="HIGH", status="OPEN", risk_score=70.0, source_ip="10.0.0.4", reasons="SessTest")
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Attempt mutation on session 1 using csrf_token_2
    cross_resp = client.patch(
        "/api/v1/incidents/204/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": csrf_token_2},
        cookies={"sentrix_session": session1_cookie},
    )
    assert cross_resp.status_code == 403
    assert "Invalid or missing CSRF token" in cross_resp.json()["detail"]


def test_new_login_creates_different_session_bound_token(client):
    """
    Requirement 6: A new login creates a different session and different session-bound token.
    """
    resp1 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    token1 = resp1.json()["csrf_token"]
    cookie1 = resp1.cookies["sentrix_session"]

    resp2 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    token2 = resp2.json()["csrf_token"]
    cookie2 = resp2.cookies["sentrix_session"]

    assert cookie1 != cookie2
    assert token1 != token2


def test_logout_invalidates_session_and_csrf_authorization(client):
    """
    Requirement 7: Logout immediately invalidates the session and its CSRF authorization.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    # Logout
    logout_resp = client.post(
        "/api/v1/auth/session/logout",
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": raw_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert logout_resp.status_code == 200

    # Insert incident
    db = TestingSessionLocal()
    try:
        inc = Incident(id=205, severity="HIGH", status="OPEN", risk_score=70.0, source_ip="10.0.0.5", reasons="LogoutTest")
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Replay attempt fails with 401
    replay_resp = client.patch(
        "/api/v1/incidents/205/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": raw_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert replay_resp.status_code == 401
    assert "Invalid, expired, or revoked session" in replay_resp.json()["detail"]


def test_expired_session_rejects_requests_even_with_correct_csrf_token(client):
    """
    Requirement 8: Expired sessions reject requests even with the correct CSRF token.
    """
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    raw_session = login_resp.cookies["sentrix_session"]
    raw_csrf = login_resp.json()["csrf_token"]

    # Manually expire session
    db = TestingSessionLocal()
    try:
        session_id = hashlib.sha256(raw_session.encode("utf-8")).hexdigest()
        record = db.query(UserSession).filter(UserSession.id == session_id).first()
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

        inc = Incident(id=206, severity="HIGH", status="OPEN", risk_score=70.0, source_ip="10.0.0.6", reasons="ExpTest")
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Attempt mutation with valid CSRF on expired session
    exp_resp = client.patch(
        "/api/v1/incidents/206/status",
        json={"status": "INVESTIGATING"},
        headers={"Origin": "http://localhost:5173", "X-SENTRIX-CSRF": raw_csrf},
        cookies={"sentrix_session": raw_session},
    )
    assert exp_resp.status_code == 401
    assert "Invalid, expired, or revoked session" in exp_resp.json()["detail"]


def test_revoke_all_user_sessions_invalidates_all_active_sessions(client):
    """
    Requirement 9: revoke_all_user_sessions revokes all active sessions for a user.
    """
    # Create two sessions for admin
    resp1 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    cookie1 = resp1.cookies["sentrix_session"]

    resp2 = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    cookie2 = resp2.cookies["sentrix_session"]

    db = TestingSessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        revoked_count = session_service.revoke_all_user_sessions(db, user.id)
        assert revoked_count >= 2
    finally:
        db.close()

    # Both sessions now return 401
    r1 = client.get("/api/v1/incidents", cookies={"sentrix_session": cookie1})
    r2 = client.get("/api/v1/incidents", cookies={"sentrix_session": cookie2})
    assert r1.status_code == 401
    assert r2.status_code == 401


def test_multi_tab_acceptance_workflow(client):
    """
    User Acceptance Test:
    1. Tab A logs in and receives session + CSRF token.
    2. Tab B refreshes and calls /session/me.
    3. Tab A performs an incident status update.
    4. Tab B performs an incident note submission.
    5. Both requests succeed without refreshing either tab.
    6. Logout in one tab invalidates the shared session in both tabs.
    (Expected: both tabs work, then both are logged out)
    """
    # Step 1: Tab A logs in and receives session cookie + CSRF token A
    login_resp = client.post(
        "/api/v1/auth/session/login",
        json={"username": "admin", "password": "sentrix123"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert login_resp.status_code == 200
    shared_session_cookie = login_resp.cookies["sentrix_session"]
    tab_a_csrf = login_resp.json()["csrf_token"]
    assert tab_a_csrf is not None and len(tab_a_csrf) == 64

    # Step 2: Tab B opens/refreshes and calls /session/me
    me_resp = client.get(
        "/api/v1/auth/session/me",
        cookies={"sentrix_session": shared_session_cookie},
    )
    assert me_resp.status_code == 200
    tab_b_csrf = me_resp.json()["csrf_token"]
    # Deterministic HMAC derivation guarantees identical CSRF token across tabs
    assert tab_b_csrf == tab_a_csrf

    # Setup incident in DB
    db = TestingSessionLocal()
    try:
        inc = Incident(
            id=301,
            severity="HIGH",
            status="OPEN",
            risk_score=85.0,
            source_ip="198.51.100.99",
            reasons="Acceptance Test Incident",
        )
        db.add(inc)
        db.commit()
    finally:
        db.close()

    # Step 3: Tab A performs an incident status update (without refreshing)
    patch_resp_a = client.patch(
        "/api/v1/incidents/301/status",
        json={"status": "INVESTIGATING"},
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": tab_a_csrf,
        },
        cookies={"sentrix_session": shared_session_cookie},
    )
    assert patch_resp_a.status_code == 200
    assert patch_resp_a.json()["status"] == "INVESTIGATING"

    # Step 4: Tab B performs an incident note submission (without refreshing)
    note_resp_b = client.post(
        "/api/v1/incidents/301/notes",
        json={
            "author": "SecOps Admin",
            "content": "Tab B confirmed threat actor IP and initiated investigation.",
        },
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": tab_b_csrf,
        },
        cookies={"sentrix_session": shared_session_cookie},
    )
    # Step 5: Both requests succeeded without refreshing either tab
    assert note_resp_b.status_code == 200
    assert len(note_resp_b.json().get("investigation_notes", [])) >= 1

    # Step 6: Logout in one tab (Tab A) invalidates the shared session in both tabs
    logout_resp = client.post(
        "/api/v1/auth/session/logout",
        headers={
            "Origin": "http://localhost:5173",
            "X-SENTRIX-CSRF": tab_a_csrf,
        },
        cookies={"sentrix_session": shared_session_cookie},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["message"] == "Logged out successfully"

    # Verify both Tab A and Tab B are now logged out and rejected
    tab_a_subsequent_request = client.get(
        "/api/v1/incidents/301",
        cookies={"sentrix_session": shared_session_cookie},
    )
    assert tab_a_subsequent_request.status_code == 401
    assert "Invalid, expired, or revoked session" in tab_a_subsequent_request.json()["detail"]

    tab_b_subsequent_request = client.get(
        "/api/v1/incidents/301",
        cookies={"sentrix_session": shared_session_cookie},
    )
    assert tab_b_subsequent_request.status_code == 401
    assert "Invalid, expired, or revoked session" in tab_b_subsequent_request.json()["detail"]

