
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.main import app, get_db
from backend.app.models.incident import Incident
from backend.app.services.auth import seed_default_users, create_access_token


def admin_headers():
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Shared fixtures — identical pattern to test_event_ingestion.py
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )

    Base.metadata.create_all(bind=test_engine)
    ensure_schema_migrations(test_engine)
    db = TestingSessionLocal()
    seed_default_users(db)
    db.close()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    previous_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestingSessionLocal
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override

        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


@pytest.fixture
def client(test_db):
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    with TestClient(
        app,
        headers={
            "X-SENTRIX-SENSOR-KEY": "sentrix-test-isolated-sensor-key-32chars!",
            "Authorization": f"Bearer {token}",
        },
    ) as test_client:
        yield test_client


@pytest.fixture
def unauthenticated_client(test_db):
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helper — insert an incident directly into the test database
# ---------------------------------------------------------------------------

def create_incident(test_db, *, source_ip="10.0.0.1", risk_score=80,
                    severity="HIGH", reasons="Test reason", status="OPEN",
                    event_id=None):
    with test_db() as db:
        incident = Incident(
            source_ip=source_ip,
            risk_score=risk_score,
            severity=severity,
            reasons=reasons,
            status=status,
            event_id=event_id,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id


# ---------------------------------------------------------------------------
# 1. GET all incidents
# ---------------------------------------------------------------------------

def test_get_all_incidents_empty(client):
    response = client.get("/api/v1/incidents")

    assert response.status_code == 200
    body = response.json()
    assert body["total_returned"] == 0
    assert body["incidents"] == []


def test_get_all_incidents_returns_existing(client, test_db):
    create_incident(test_db, source_ip="192.168.1.1")
    create_incident(test_db, source_ip="192.168.1.2")

    response = client.get("/api/v1/incidents")

    assert response.status_code == 200
    body = response.json()
    assert body["total_returned"] == 2
    assert len(body["incidents"]) == 2


def test_get_all_incidents_limit(client, test_db):
    for i in range(5):
        create_incident(test_db, source_ip=f"10.0.0.{i + 1}")

    response = client.get("/api/v1/incidents?limit=3")

    assert response.status_code == 200
    assert response.json()["total_returned"] == 3


# ---------------------------------------------------------------------------
# 2. GET individual incident — exists
# ---------------------------------------------------------------------------

def test_get_incident_by_id(client, test_db):
    incident_id = create_incident(
        test_db,
        source_ip="172.16.0.5",
        risk_score=75,
        severity="HIGH",
        reasons="ML predicted ATTACK",
        status="OPEN",
    )

    response = client.get(f"/api/v1/incidents/{incident_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["source_ip"] == "172.16.0.5"
    assert body["risk_score"] == 75
    assert body["severity"] == "HIGH"
    assert body["reasons"] == "ML predicted ATTACK"
    assert body["status"] == "OPEN"
    assert "created_at" in body
    assert "event_id" in body


# ---------------------------------------------------------------------------
# 3. GET individual incident — does not exist
# ---------------------------------------------------------------------------

def test_get_nonexistent_incident_returns_404(client):
    response = client.get("/api/v1/incidents/99999")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 4. GET incident summary
# ---------------------------------------------------------------------------

def test_get_incident_summary_empty(client):
    response = client.get("/api/v1/incidents/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total_incidents"] == 0
    assert body["severity_breakdown"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    assert body["status_breakdown"] == {
        "OPEN": 0, "INVESTIGATING": 0, "RESOLVED": 0
    }


def test_get_incident_summary_reflects_data(client, test_db):
    create_incident(test_db, severity="HIGH", status="OPEN")
    create_incident(test_db, severity="HIGH", status="INVESTIGATING")
    create_incident(test_db, severity="MEDIUM", status="RESOLVED")
    create_incident(test_db, severity="LOW", status="OPEN")

    response = client.get("/api/v1/incidents/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["total_incidents"] == 4
    assert body["severity_breakdown"]["HIGH"] == 2
    assert body["severity_breakdown"]["MEDIUM"] == 1
    assert body["severity_breakdown"]["LOW"] == 1
    assert body["status_breakdown"]["OPEN"] == 2
    assert body["status_breakdown"]["INVESTIGATING"] == 1
    assert body["status_breakdown"]["RESOLVED"] == 1


# ---------------------------------------------------------------------------
# 5. PATCH status — successful update
# ---------------------------------------------------------------------------

def test_update_incident_status_success(client, test_db):
    incident_id = create_incident(test_db, status="OPEN")

    response = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "INVESTIGATING"},
        headers=admin_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["status"] == "INVESTIGATING"
    # Full incident dict is returned — verify required fields are present
    assert "source_ip" in body
    assert "severity" in body
    assert "risk_score" in body
    assert "reasons" in body
    assert "created_at" in body


# ---------------------------------------------------------------------------
# 6. PATCH status — invalid value rejected
# ---------------------------------------------------------------------------

def test_update_incident_status_invalid_value(client, test_db):
    incident_id = create_incident(test_db)

    response = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "DELETED"},
        headers=admin_headers(),
    )

    assert response.status_code == 400
    assert "status" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 7. PATCH status — nonexistent incident
# ---------------------------------------------------------------------------

def test_update_nonexistent_incident_returns_404(client):
    response = client.patch(
        "/api/v1/incidents/99999/status",
        json={"status": "RESOLVED"},
        headers=admin_headers(),
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Status persistence — change survives session close and re-open
# ---------------------------------------------------------------------------

def test_status_update_persists(client, test_db):
    incident_id = create_incident(test_db, status="OPEN")

    client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "RESOLVED"},
        headers=admin_headers(),
    )

    # Open a fresh session to confirm the change was committed to the DB
    with test_db() as db:
        stored = db.query(Incident).filter(Incident.id == incident_id).first()
        assert stored is not None
        assert stored.status == "RESOLVED"


# ---------------------------------------------------------------------------
# 9. ML-generated incident creation still works end-to-end
# ---------------------------------------------------------------------------

def test_ml_attack_event_creates_incident(client):
    """
    Submit a full 78-feature attack payload via POST /api/v1/events and
    confirm an incident is created and retrievable via GET /api/v1/incidents.
    Uses the real ML model artifact; skips if the artifact is absent.
    """
    import json
    from pathlib import Path

    payload_path = Path(__file__).resolve().parent.parent / "attack_request.json"
    if not payload_path.exists():
        payload_path = Path("attack_request.json")
    if not payload_path.exists():
        pytest.skip("attack_request.json not found — skipping ML integration test")

    payload = json.loads(payload_path.read_text())

    # Wrap in the SecurityEvent envelope expected by POST /api/v1/events
    event_payload = {
        "source_ip": payload.get("source_ip"),
        "features": payload["features"],
    }

    response = client.post("/api/v1/events", json=event_payload)

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["analysis_status"] == "COMPLETED"
    assert body["predicted_label"] == "ATTACK"
    assert body["incident_created"] is True

    incident_id = body["incident_id"]
    assert incident_id is not None

    # Confirm the incident is retrievable individually
    get_response = client.get(f"/api/v1/incidents/{incident_id}")
    assert get_response.status_code == 200
    incident = get_response.json()
    assert incident["incident_id"] == incident_id
    assert incident["severity"] in ("LOW", "MEDIUM", "HIGH")
    assert incident["status"] == "OPEN"


# ---------------------------------------------------------------------------
# 10. ML benign event does not create an incident
# ---------------------------------------------------------------------------

def test_ml_benign_event_does_not_create_incident(client):
    """
    Submit a full 78-feature benign payload via POST /api/v1/events and
    confirm that it is classified as BENIGN and no incident is created.
    """
    import json
    from pathlib import Path

    payload_path = Path(__file__).resolve().parent.parent / "benign_request.json"
    if not payload_path.exists():
        payload_path = Path("benign_request.json")
    if not payload_path.exists():
        pytest.skip("benign_request.json not found — skipping ML integration test")

    payload = json.loads(payload_path.read_text())

    event_payload = {
        "source_ip": payload.get("source_ip"),
        "features": payload["features"],
    }

    response = client.post("/api/v1/events", json=event_payload)

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["analysis_status"] == "COMPLETED"
    assert body["predicted_label"] == "BENIGN"
    assert body["incident_created"] is False
    assert body.get("incident_id") is None

    # Confirm no incidents exist in the database
    get_incidents = client.get("/api/v1/incidents")
    assert get_incidents.status_code == 200
    assert get_incidents.json()["total_returned"] == 0

    get_summary = client.get("/api/v1/incidents/summary")
    assert get_summary.status_code == 200
    assert get_summary.json()["total_incidents"] == 0


# ---------------------------------------------------------------------------
# 11. Full incident lifecycle: event -> incident -> GET details -> PATCH status to each valid state -> summary verification
# ---------------------------------------------------------------------------

def test_incident_full_lifecycle(client):
    """
    End-to-end lifecycle verification:
    1. Ingest attack event -> Incident created with status OPEN.
    2. Retrieve incident details via GET /api/v1/incidents/{id}.
    3. Update status to each valid state via PATCH /api/v1/incidents/{id}/status:
       - OPEN -> INVESTIGATING
       - INVESTIGATING -> RESOLVED
       - RESOLVED -> OPEN
    4. Verify status persistence and summary counts after each transition.
    """
    import json
    from pathlib import Path

    payload_path = Path(__file__).resolve().parent.parent / "attack_request.json"
    if not payload_path.exists():
        payload_path = Path("attack_request.json")
    if not payload_path.exists():
        pytest.skip("attack_request.json not found — skipping ML integration test")

    payload = json.loads(payload_path.read_text())
    event_payload = {
        "source_ip": payload.get("source_ip"),
        "features": payload["features"],
    }

    # 1. Ingest event
    ingest_resp = client.post("/api/v1/events", json=event_payload)
    assert ingest_resp.status_code == 202
    ingest_data = ingest_resp.json()
    assert ingest_data["incident_created"] is True
    incident_id = ingest_data["incident_id"]
    assert incident_id is not None

    # 2. Fetch incident details
    detail_resp = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["incident_id"] == incident_id
    assert detail["status"] == "OPEN"
    assert detail["source_ip"] == payload.get("source_ip")
    assert "risk_score" in detail
    assert "severity" in detail
    assert "reasons" in detail
    assert "created_at" in detail

    # Check initial summary
    sum_resp = client.get("/api/v1/incidents/summary")
    assert sum_resp.status_code == 200
    sum_data = sum_resp.json()
    assert sum_data["total_incidents"] == 1
    assert sum_data["status_breakdown"]["OPEN"] == 1
    assert sum_data["status_breakdown"]["INVESTIGATING"] == 0
    assert sum_data["status_breakdown"]["RESOLVED"] == 0

    # 3. Transition: OPEN -> INVESTIGATING
    patch_resp1 = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "INVESTIGATING"},
        headers=admin_headers(),
    )
    assert patch_resp1.status_code == 200
    assert patch_resp1.json()["status"] == "INVESTIGATING"

    # Verify detail fetch reflects INVESTIGATING
    detail_resp1 = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_resp1.status_code == 200
    assert detail_resp1.json()["status"] == "INVESTIGATING"

    # Verify summary reflects INVESTIGATING
    sum_resp1 = client.get("/api/v1/incidents/summary")
    assert sum_resp1.json()["status_breakdown"]["INVESTIGATING"] == 1
    assert sum_resp1.json()["status_breakdown"]["OPEN"] == 0

    # 4. Transition: INVESTIGATING -> RESOLVED
    patch_resp2 = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "RESOLVED"},
        headers=admin_headers(),
    )
    assert patch_resp2.status_code == 200
    assert patch_resp2.json()["status"] == "RESOLVED"

    # Verify detail fetch reflects RESOLVED
    detail_resp2 = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_resp2.status_code == 200
    assert detail_resp2.json()["status"] == "RESOLVED"

    # Verify summary reflects RESOLVED
    sum_resp2 = client.get("/api/v1/incidents/summary")
    assert sum_resp2.json()["status_breakdown"]["RESOLVED"] == 1
    assert sum_resp2.json()["status_breakdown"]["INVESTIGATING"] == 0

    # 5. Transition: RESOLVED -> OPEN
    patch_resp3 = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "OPEN"},
        headers=admin_headers(),
    )
    assert patch_resp3.status_code == 200
    assert patch_resp3.json()["status"] == "OPEN"

    detail_resp3 = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_resp3.status_code == 200
    assert detail_resp3.json()["status"] == "OPEN"

    sum_resp3 = client.get("/api/v1/incidents/summary")
    assert sum_resp3.json()["status_breakdown"]["OPEN"] == 1
    assert sum_resp3.json()["status_breakdown"]["RESOLVED"] == 0


def test_unauthenticated_read_incidents_rejected(unauthenticated_client, test_db):
    """SEC-03: Verifies unauthenticated GET /incidents and GET /incidents/{id} fail with 401."""
    inc_id = create_incident(test_db)

    # Reading incident list without JWT fails closed
    res_list = unauthenticated_client.get("/api/v1/incidents")
    assert res_list.status_code == 401

    # Reading incident details without JWT fails closed
    res_detail = unauthenticated_client.get(f"/api/v1/incidents/{inc_id}")
    assert res_detail.status_code == 401

    # Aggregate summary remains publicly viewable
    res_sum = unauthenticated_client.get("/api/v1/incidents/summary")
    assert res_sum.status_code == 200

