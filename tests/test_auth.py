import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app, get_db
from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.models.incident import Incident
from backend.app.models.security_event import SecurityEventRecord
from backend.app.models.user import User
from backend.app.services.auth import seed_default_users, create_access_token

test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

Base.metadata.create_all(bind=test_engine)
ensure_schema_migrations(test_engine)


def admin_headers():
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def analyst_headers():
    token = create_access_token({"sub": "analyst", "user_id": 2, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    ensure_schema_migrations(test_engine)
    db = TestingSessionLocal()
    seed_default_users(db)
    db.close()
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


def create_sample_incident():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    inc = Incident(
        event_id="evt-auth-001",
        source_ip="198.51.100.99",
        risk_score=75.0,
        severity="HIGH",
        reasons="attack_probability=1.000000",
        status="OPEN",
        event_count=1,
        created_at=now,
        last_seen_at=now,
        investigation_notes=[],
        assigned_to=None,
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    inc_id = inc.id
    db.close()
    return inc_id


# ============================================================================
# 1. Login & Token Generation Tests
# ============================================================================

def test_login_success_admin(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "sentrix123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


def test_login_success_analyst(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["username"] == "analyst"
    assert data["user"]["role"] == "analyst"


def test_login_invalid_password_returns_401(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert res.status_code == 401
    assert "invalid username or password" in res.json()["detail"].lower()


def test_login_nonexistent_user_returns_401(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_hacker", "password": "password"},
    )
    assert res.status_code == 401


# ============================================================================
# 2. Authenticated Profile (GET /api/v1/auth/me)
# ============================================================================

def test_get_auth_me_with_valid_token(client):
    # Log in first
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "sentrix123"},
    )
    token = login_res.json()["access_token"]

    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    profile = res.json()
    assert profile["username"] == "admin"
    assert profile["role"] == "admin"


def test_get_auth_me_missing_token_returns_401(client):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401


def test_get_auth_me_invalid_token_returns_401(client):
    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.fake.token"},
    )
    assert res.status_code == 401


# ============================================================================
# 3. Role-Based Access Control (RBAC) Enforcement
# ============================================================================

def test_patch_status_with_analyst_token_forbidden_403(client):
    inc_id = create_sample_incident()

    # Log in as analyst
    analyst_token = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    ).json()["access_token"]

    # Attempt to change incident status with analyst role -> MUST BE FORBIDDEN (403)
    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"status": "RESOLVED"},
    )
    assert res.status_code == 403
    assert "forbidden" in res.json()["detail"].lower()


def test_patch_status_with_admin_token_succeeds_200(client):
    inc_id = create_sample_incident()

    # Log in as admin
    admin_token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "sentrix123"},
    ).json()["access_token"]

    # Admin changes status -> SUCCESS (200)
    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "RESOLVED"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"


def test_analyst_can_add_note_and_be_recorded_as_author(client):
    inc_id = create_sample_incident()

    analyst_token = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    ).json()["access_token"]

    # Analyst adds note
    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"content": "Investigating potential lateral movement from source IP."},
    )
    assert res.status_code == 200
    notes = res.json()["investigation_notes"]
    assert len(notes) == 1
    assert notes[0]["author"] == "analyst"


# ============================================================================
# 4. Strict RBAC Enforcement & Public Preservation Tests (Security Hardening)
# ============================================================================

def test_protected_endpoints_without_token_return_401(client):
    """Verifies that accessing protected endpoints without an Authorization header returns 401."""
    inc_id = create_sample_incident()

    # Admin-only status update
    res1 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "RESOLVED"})
    assert res1.status_code == 401
    assert "authentication credentials required" in res1.json()["detail"].lower()

    # Analyst/Admin notes
    res2 = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"content": "Unauthorized note"})
    assert res2.status_code == 401
    assert "authentication credentials required" in res2.json()["detail"].lower()

    # Analyst/Admin assign
    res3 = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to": "Analyst"})
    assert res3.status_code == 401

    # Analyst/Admin AI analysis
    res4 = client.post(f"/api/v1/incidents/{inc_id}/analyze-ai")
    assert res4.status_code == 401

    # Analyst/Admin propose response
    res5 = client.post(f"/api/v1/incidents/{inc_id}/responses", json={"action_type": "BLOCK_IP", "target": "198.51.100.99"})
    assert res5.status_code == 401

    # Admin approve response
    res6 = client.post("/api/v1/responses/1/approve")
    assert res6.status_code == 401

    # Admin reject response
    res7 = client.post("/api/v1/responses/1/reject")
    assert res7.status_code == 401

    # Admin rollback response
    res8 = client.post("/api/v1/responses/1/rollback")
    assert res8.status_code == 401


def test_protected_endpoints_with_expired_token_return_401(client):
    """Verifies that an expired JWT token returns 401 on protected endpoints."""
    inc_id = create_sample_incident()
    expired_token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"}, expires_delta_seconds=-3600)

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers={"Authorization": f"Bearer {expired_token}"},
        json={"status": "RESOLVED"},
    )
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower() or "invalid" in res.json()["detail"].lower()


def test_protected_endpoints_with_malformed_token_return_401(client):
    """Verifies that a malformed Bearer token returns 401 on protected endpoints."""
    inc_id = create_sample_incident()

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers={"Authorization": "Bearer this.is.garbage.jwt"},
        json={"status": "RESOLVED"},
    )
    assert res.status_code == 401


def test_public_endpoints_accessible_without_auth(client):
    """Verifies that public informational and aggregate endpoints remain accessible without tokens."""
    # Health checks
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200

    # Ingestion connector metadata
    assert client.get("/api/v1/ingest/connectors").status_code == 200

    # Aggregate summary for public dashboard counters (SEC-03: summary is public, incident lists are protected)
    assert client.get("/api/v1/incidents/summary").status_code == 200
    assert client.get("/api/v1/ml/metrics").status_code == 200


def test_incident_read_endpoints_require_auth(client):
    """SEC-03: Verifies that incident list, detail, and responses require Admin/Analyst authentication."""
    inc_id = create_sample_incident()

    # 1. Without credentials -> 401 Unauthorized
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get(f"/api/v1/incidents/{inc_id}").status_code == 401
    assert client.get(f"/api/v1/incidents/{inc_id}/responses").status_code == 401

    # 2. With analyst credentials -> 200 OK
    a_headers = analyst_headers()
    res_list = client.get("/api/v1/incidents", headers=a_headers)
    assert res_list.status_code == 200
    res_detail = client.get(f"/api/v1/incidents/{inc_id}", headers=a_headers)
    assert res_detail.status_code == 200
    res_resp = client.get(f"/api/v1/incidents/{inc_id}/responses", headers=a_headers)
    assert res_resp.status_code == 200

    # 3. With admin credentials -> 200 OK
    adm_headers = admin_headers()
    assert client.get("/api/v1/incidents", headers=adm_headers).status_code == 200
    assert client.get(f"/api/v1/incidents/{inc_id}", headers=adm_headers).status_code == 200
    assert client.get(f"/api/v1/incidents/{inc_id}/responses", headers=adm_headers).status_code == 200


# ============================================================================
# 5. Production Credential & JWT Secret Hardening Tests
# ============================================================================

def test_missing_jwt_secret_in_production(monkeypatch):
    """Verifies that missing JWT_SECRET in production mode fails safely with ValueError."""
    from backend.app.services.auth import get_jwt_secret

    monkeypatch.setenv("SENTRIX_ENV", "production")
    monkeypatch.delenv("JWT_SECRET", raising=False)

    with pytest.raises(ValueError, match="JWT_SECRET environment variable is missing"):
        get_jwt_secret()


def test_weak_or_default_jwt_secret_in_production(monkeypatch):
    """Verifies that short or default JWT secrets are rejected in production."""
    from backend.app.services.auth import get_jwt_secret

    monkeypatch.setenv("SENTRIX_ENV", "production")

    # Short secret (< 32 bytes)
    monkeypatch.setenv("JWT_SECRET", "too-short-key")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        get_jwt_secret()

    # Known default secret
    monkeypatch.setenv("JWT_SECRET", "sentrix-cyber-threat-intelligence-secret-key-2026")
    with pytest.raises(ValueError, match="Known default or insecure JWT_SECRET"):
        get_jwt_secret()


def test_valid_strong_jwt_secret_in_production(monkeypatch):
    """Verifies that a 32+ byte high-entropy secret succeeds in production."""
    from backend.app.services.auth import get_jwt_secret

    strong_secret = "c7d9a18f943e4981a8c9b207d5e4f3a1b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3"
    monkeypatch.setenv("SENTRIX_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", strong_secret)

    secret = get_jwt_secret()
    assert secret == strong_secret


def test_missing_initial_passwords_in_production(monkeypatch):
    """Verifies that seed_default_users fails safely if initial passwords are missing in production."""
    from backend.app.services.auth import seed_default_users

    monkeypatch.setenv("SENTRIX_ENV", "production")
    monkeypatch.delenv("ADMIN_INITIAL_PASSWORD", raising=False)
    monkeypatch.delenv("ANALYST_INITIAL_PASSWORD", raising=False)

    db = TestingSessionLocal()
    with pytest.raises(ValueError, match="ADMIN_INITIAL_PASSWORD must be provided"):
        seed_default_users(db)
    db.close()


def test_correct_password_hashing_and_verification():
    """Verifies PBKDF2 salt uniqueness and verification accuracy."""
    from backend.app.services.auth import hash_password, verify_password

    raw_pass = "SuperSecurePassword123!"
    hash1 = hash_password(raw_pass)
    hash2 = hash_password(raw_pass)

    # Different salts must yield different hashes
    assert hash1 != hash2
    assert hash1.startswith("pbkdf2_sha256$100000$")

    # Verification must succeed
    assert verify_password(raw_pass, hash1) is True
    assert verify_password(raw_pass, hash2) is True
    assert verify_password("WrongPassword!", hash1) is False


def test_jwt_token_creation_and_verification_with_configured_secret(monkeypatch):
    """Verifies token issuance and verification roundtrip with dynamic secret."""
    from backend.app.services.auth import create_access_token, decode_access_token

    test_secret = "custom-test-secret-key-that-is-at-least-32-chars-long"
    monkeypatch.setenv("JWT_SECRET", test_secret)

    payload = {"sub": "test_analyst", "role": "analyst", "custom": "field"}
    token = create_access_token(payload, expires_delta_seconds=300)

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "test_analyst"
    assert decoded["role"] == "analyst"
    assert decoded["custom"] == "field"


def test_no_credentials_exposed_in_api_responses(client):
    """Verifies that API responses never return password hashes or raw secrets."""
    # Login response check
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "sentrix123"},
    )
    assert res.status_code == 200
    login_data = res.json()
    assert "password" not in str(login_data).lower() or "password_hash" not in str(login_data).lower()
    assert "password_hash" not in login_data["user"]

    # Profile response check
    token = login_data["access_token"]
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert "password" not in me_data
    assert "password_hash" not in me_data


