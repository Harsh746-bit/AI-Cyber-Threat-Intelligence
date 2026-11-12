import json
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.main import app, get_db
from backend.app.models.incident import Incident
from backend.app.models.response import ResponseAction
from backend.app.models.security_event import SecurityEventRecord
from backend.app.services.auth import create_access_token, seed_default_users

TEST_VALID_KEY = "sentrix-test-isolated-sensor-key-32chars!"
TEST_INVALID_KEY = "invalid-sensor-key-that-is-32-chars-long-xxx!"

# In-memory test database with StaticPool
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
    monkeypatch.setenv("SENTRIX_SENSOR_API_KEY", TEST_VALID_KEY)
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
def unauthenticated_client():
    """Client without any default headers."""
    return TestClient(app)


@pytest.fixture
def sensor_client():
    """Client with valid X-SENTRIX-SENSOR-KEY header."""
    return TestClient(app, headers={"X-SENTRIX-SENSOR-KEY": TEST_VALID_KEY})


def admin_token():
    return create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})


def analyst_token():
    return create_access_token({"sub": "analyst", "user_id": 2, "role": "analyst"})


# ============================================================================
# 1. Dedicated Sensor Key Authentication Tests
# ============================================================================

def test_valid_sensor_key_accepted_on_events_endpoint(sensor_client):
    payload = {
        "event_id": str(uuid4()),
        "schema_version": "1.0",
        "event_type": "NETWORK_FLOW",
        "source_ip": "198.51.100.10",
        "destination_port": 80,
        "protocol": "TCP",
        "features": {
            "Destination Port": 80.0,
            "Flow Duration": 150.0,
        },
    }
    resp = sensor_client.post("/api/v1/events", json=payload)
    assert resp.status_code == 202
    assert resp.json()["status"] == "accepted"


def test_valid_sensor_key_accepted_on_raw_ingest_endpoint(sensor_client):
    log_line = '198.51.100.22 - - [12/Nov/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
    payload = {
        "source_type": "NGINX_ACCESS",
        "raw_payload": log_line,
    }
    resp = sensor_client.post("/api/v1/ingest/raw", json=payload)
    assert resp.status_code == 202
    assert resp.json()["status"] == "ACCEPTED"


def test_missing_sensor_key_returns_401(unauthenticated_client):
    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post("/api/v1/events", json=payload)
    assert resp.status_code == 401
    assert "Missing sensor authentication key" in resp.json()["detail"]


def test_invalid_sensor_key_returns_401(unauthenticated_client):
    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post(
        "/api/v1/events",
        json=payload,
        headers={"X-SENTRIX-SENSOR-KEY": TEST_INVALID_KEY},
    )
    assert resp.status_code == 401
    assert "Invalid sensor authentication key" in resp.json()["detail"]


def test_incorrect_header_name_returns_401(unauthenticated_client):
    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    # Passing valid key under incorrect header names
    for bad_header in ["X-API-KEY", "Authorization", "X-SENSOR-KEY", "ApiKey"]:
        resp = unauthenticated_client.post(
            "/api/v1/events",
            json=payload,
            headers={bad_header: TEST_VALID_KEY},
        )
        assert resp.status_code == 401
        assert "Missing sensor authentication key" in resp.json()["detail"]


def test_missing_server_side_key_configuration_fails_closed(monkeypatch, unauthenticated_client):
    """When SENTRIX_SENSOR_API_KEY is not configured on the server, requests must fail closed."""
    monkeypatch.delenv("SENTRIX_SENSOR_API_KEY", raising=False)

    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    # Even with a supplied header, server fails closed with 500 error
    resp = unauthenticated_client.post(
        "/api/v1/events",
        json=payload,
        headers={"X-SENTRIX-SENSOR-KEY": "any-key-supplied-by-client-32chars!"},
    )
    assert resp.status_code == 500
    assert "not configured" in resp.json()["detail"].lower()


def test_short_server_side_key_fails_closed(monkeypatch, unauthenticated_client):
    """Server key with < 32 characters entropy must fail closed."""
    monkeypatch.setenv("SENTRIX_SENSOR_API_KEY", "too-short-key")

    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post(
        "/api/v1/events",
        json=payload,
        headers={"X-SENTRIX-SENSOR-KEY": "too-short-key"},
    )
    assert resp.status_code == 500
    assert "entropy" in resp.json()["detail"].lower()


# ============================================================================
# 2. Boundary & Cross-Authentication Isolation Tests
# ============================================================================

def test_user_jwt_alone_cannot_authenticate_sensor(unauthenticated_client):
    """A valid Admin or Analyst JWT must NOT be accepted on sensor telemetry endpoints."""
    token = admin_token()
    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post(
        "/api/v1/events",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Missing sensor authentication key" in resp.json()["detail"]


def test_sensor_key_alone_cannot_authenticate_admin_endpoint(sensor_client):
    """A sensor API key must NOT grant access to Admin/Analyst management endpoints."""
    # Attempt to access status update endpoint with sensor client
    resp = sensor_client.patch(
        "/api/v1/incidents/1/status",
        json={"status": "RESOLVED"},
    )
    assert resp.status_code == 401
    assert "credentials required" in resp.json()["detail"].lower()


def test_sensor_key_alone_cannot_authenticate_ml_predict(sensor_client):
    """Sensor API key alone cannot access /api/v1/ml/predict without user JWT."""
    payload = {
        "source_ip": "198.51.100.50",
        "features": {"Flow Duration": 100.0},
    }
    resp = sensor_client.post("/api/v1/ml/predict", json=payload)
    assert resp.status_code == 401
    assert "credentials required" in resp.json()["detail"].lower()


def test_admin_jwt_can_authenticate_ml_predict(unauthenticated_client):
    """Admin JWT can access /api/v1/ml/predict."""
    token = admin_token()
    payload = {
        "source_ip": "198.51.100.50",
        "features": {"Destination Port": 80.0, "Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post(
        "/api/v1/ml/predict",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (200, 422)


def test_analyst_jwt_can_authenticate_ml_predict(unauthenticated_client):
    """Analyst JWT can access /api/v1/ml/predict."""
    token = analyst_token()
    payload = {
        "source_ip": "198.51.100.50",
        "features": {"Destination Port": 80.0, "Flow Duration": 100.0},
    }
    resp = unauthenticated_client.post(
        "/api/v1/ml/predict",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (200, 422)


# ============================================================================
# 3. Side-Effect & Rejection Isolation Verification
# ============================================================================

def test_unauthorized_events_request_produces_no_database_side_effects(unauthenticated_client):
    """Verify that an unauthorized request to /api/v1/events creates NO database records."""
    db = TestingSessionLocal()
    init_events = db.query(SecurityEventRecord).count()
    init_incidents = db.query(Incident).count()
    init_responses = db.query(ResponseAction).count()
    db.close()

    # Attempt submission with no key
    unauthenticated_client.post(
        "/api/v1/events",
        json={
            "event_type": "NETWORK_FLOW",
            "source_ip": "203.0.113.111",
            "features": {"Flow Duration": 100.0},
        },
    )

    # Attempt submission with invalid key
    unauthenticated_client.post(
        "/api/v1/events",
        json={
            "event_type": "NETWORK_FLOW",
            "source_ip": "203.0.113.111",
            "features": {"Flow Duration": 100.0},
        },
        headers={"X-SENTRIX-SENSOR-KEY": TEST_INVALID_KEY},
    )

    db = TestingSessionLocal()
    assert db.query(SecurityEventRecord).count() == init_events
    assert db.query(Incident).count() == init_incidents
    assert db.query(ResponseAction).count() == init_responses
    db.close()


def test_unauthorized_raw_ingest_produces_no_database_side_effects(unauthenticated_client):
    """Verify that an unauthorized request to /api/v1/ingest/raw creates NO database records."""
    db = TestingSessionLocal()
    init_events = db.query(SecurityEventRecord).count()
    init_incidents = db.query(Incident).count()
    db.close()

    log_line = '203.0.113.111 - - [12/Nov/2026:10:00:00 +0000] "GET /admin/config.php HTTP/1.1" 404 120'
    unauthenticated_client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": log_line},
        headers={"X-SENTRIX-SENSOR-KEY": TEST_INVALID_KEY},
    )

    db = TestingSessionLocal()
    assert db.query(SecurityEventRecord).count() == init_events
    assert db.query(Incident).count() == init_incidents
    db.close()


def test_connectors_metadata_remains_public(unauthenticated_client):
    """GET /api/v1/ingest/connectors remains accessible without any sensor key or JWT."""
    resp = unauthenticated_client.get("/api/v1/ingest/connectors")
    assert resp.status_code == 200
    assert "supported_connectors" in resp.json()


# ============================================================================
# 4. Authenticated Analyst Simulation Workflow Tests
# ============================================================================

def test_unauthenticated_simulation_returns_401(unauthenticated_client):
    """Unauthenticated simulation requests are rejected with HTTP 401."""
    resp1 = unauthenticated_client.post(
        "/api/v1/simulation/event",
        json={"event_type": "NETWORK_FLOW", "features": {"Flow Duration": 1.0}},
    )
    assert resp1.status_code == 401
    assert "credentials required" in resp1.json()["detail"].lower()

    resp2 = unauthenticated_client.post(
        "/api/v1/simulation/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": "line"},
    )
    assert resp2.status_code == 401
    assert "credentials required" in resp2.json()["detail"].lower()


def test_sensor_key_alone_cannot_access_simulation_endpoints(sensor_client):
    """A sensor key cannot access the user-authenticated simulation endpoints."""
    resp = sensor_client.post(
        "/api/v1/simulation/event",
        json={"event_type": "NETWORK_FLOW", "features": {"Flow Duration": 1.0}},
    )
    assert resp.status_code == 401
    assert "credentials required" in resp.json()["detail"].lower()


def test_analyst_jwt_can_access_simulation_endpoints(unauthenticated_client):
    """An authenticated Analyst JWT can submit events and raw telemetry via simulation."""
    token = analyst_token()
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "event_type": "NETWORK_FLOW",
        "features": {"Flow Duration": 10.0, "Total Fwd Packets": 2.0},
    }
    resp1 = unauthenticated_client.post(
        "/api/v1/simulation/event",
        json=payload,
        headers=headers,
    )
    assert resp1.status_code == 202
    assert resp1.json()["status"] == "accepted"

    log_line = '198.51.100.99 - - [12/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 500'
    resp2 = unauthenticated_client.post(
        "/api/v1/simulation/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": log_line},
        headers=headers,
    )
    assert resp2.status_code == 202
    assert resp2.json()["status"] == "ACCEPTED"
