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

from backend.app.services.auth import seed_default_users, create_access_token

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


def auth_headers(role: str = "analyst", username: str = "analyst"):
    token = create_access_token({"sub": username, "user_id": 2 if role == "analyst" else 1, "role": role})
    return {"Authorization": f"Bearer {token}"}


def create_sample_incident():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    inc = Incident(
        event_id="evt-invest-001",
        source_ip="198.51.100.44",
        risk_score=78.0,
        severity="CRITICAL",
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
# Investigation Notes Tests
# ============================================================================

def test_add_note_to_incident_success(client):
    inc_id = create_sample_incident()

    payload = {
        "author": "Analyst Alice",
        "content": "Observed multiple SSH brute force attempts from target IP. Recommending immediate egress blocking.",
    }

    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json=payload,
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert "investigation_notes" in data
    notes = data["investigation_notes"]
    assert len(notes) == 1
    assert notes[0]["author"] == "Analyst Alice"
    assert notes[0]["content"] == payload["content"]
    assert "note_id" in notes[0]
    assert "created_at" in notes[0]

    # Verify persistence via separate GET
    get_res = client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers())
    assert get_res.status_code == 200
    assert len(get_res.json()["investigation_notes"]) == 1


def test_add_multiple_notes_maintains_order(client):
    inc_id = create_sample_incident()

    client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"author": "Tier 1 SOC", "content": "Initial triage complete. Escalated to Tier 2."},
        headers=auth_headers("analyst"),
    )
    res2 = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"author": "Tier 2 Lead", "content": "Firewall ACL rule applied. Monitoring traffic."},
        headers=auth_headers("analyst"),
    )
    assert res2.status_code == 200
    notes = res2.json()["investigation_notes"]
    assert len(notes) == 2
    assert notes[0]["author"] == "Tier 1 SOC"
    assert notes[1]["author"] == "Tier 2 Lead"


def test_add_note_empty_content_rejected(client):
    inc_id = create_sample_incident()
    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"author": "Alice", "content": ""},
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 422


def test_add_note_nonexistent_incident_returns_404(client):
    res = client.post(
        "/api/v1/incidents/99999/notes",
        json={"author": "Alice", "content": "Test note"},
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ============================================================================
# Incident Assignment Tests
# ============================================================================

def test_assign_incident_success(client):
    inc_id = create_sample_incident()

    # Initial check: unassigned
    init_res = client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers())
    assert init_res.json()["assigned_to"] is None

    # Assign to analyst
    assign_payload = {"assigned_to": "SecOps Lead - Harsh"}
    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        json=assign_payload,
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 200
    assert res.json()["assigned_to"] == "SecOps Lead - Harsh"

    # Confirm persistence
    get_res = client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers())
    assert get_res.json()["assigned_to"] == "SecOps Lead - Harsh"


def test_assign_incident_empty_rejected(client):
    inc_id = create_sample_incident()
    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        json={"assigned_to": ""},
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 422


def test_assign_nonexistent_incident_returns_404(client):
    res = client.patch(
        "/api/v1/incidents/99999/assign",
        json={"assigned_to": "Analyst Bob"},
        headers=auth_headers("analyst"),
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
