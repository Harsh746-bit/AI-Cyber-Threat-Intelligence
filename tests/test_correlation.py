import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app, get_db
from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.models.incident import Incident
from backend.app.models.security_event import SecurityEventRecord
from backend.app.services.correlation import CorrelationEngine
from backend.app.services.auth import seed_default_users, create_access_token
from sqlalchemy.pool import StaticPool

# In-memory test DB with StaticPool
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
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    return TestClient(
        app,
        headers={
            "X-SENTRIX-SENSOR-KEY": "sentrix-test-isolated-sensor-key-32chars!",
            "Authorization": f"Bearer {token}",
        },
    )


def admin_headers():
    token = create_access_token({"sub": "admin", "user_id": 1, "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def load_attack_payload():
    payload_path = Path(__file__).resolve().parent.parent / "attack_request.json"
    if not payload_path.exists():
        payload_path = Path("attack_request.json")
    if not payload_path.exists():
        pytest.skip("attack_request.json not found — skipping test")
    return json.loads(payload_path.read_text())


# ============================================================================
# Unit Tests: Correlation Engine Logic
# ============================================================================

def test_calculate_risk_score_bands():
    engine = CorrelationEngine()

    # Low score: low conf, zero abuse, 1 event -> 0.2*40 + 0 + 6 = 14 -> LOW
    score, sev = engine.calculate_risk_score(ml_confidence=0.2, abuse_score=0, event_count=1)
    assert score == 14.0
    assert sev == "LOW"

    # Medium score: 0.5 conf, 10 abuse, 1 event -> 20 + 3 + 6 = 29 -> MEDIUM
    score, sev = engine.calculate_risk_score(ml_confidence=0.5, abuse_score=10, event_count=1)
    assert score == 29.0
    assert sev == "MEDIUM"

    # High score: 1.0 conf, 85 abuse, 1 event -> 40 + 25.5 + 6 = 71.5 -> HIGH
    score, sev = engine.calculate_risk_score(ml_confidence=1.0, abuse_score=85, event_count=1)
    assert score == 71.5
    assert sev == "HIGH"

    # Critical score: 1.0 conf, 85 abuse, 3 events -> 40 + 25.5 + 18 = 83.5 -> CRITICAL
    score, sev = engine.calculate_risk_score(ml_confidence=1.0, abuse_score=85, event_count=3)
    assert score == 83.5
    assert sev == "CRITICAL"

    # Score capping at 100.0
    score, sev = engine.calculate_risk_score(ml_confidence=1.0, abuse_score=100, event_count=10)
    assert score == 100.0
    assert sev == "CRITICAL"


def test_map_mitre_technique():
    engine = CorrelationEngine()

    # Web exploitation
    t80 = engine.map_mitre_technique(80)
    assert t80["technique_id"] == "T1190"
    assert "Exploit Public-Facing Application" in t80["technique_name"]

    t443 = engine.map_mitre_technique(443)
    assert t443["technique_id"] == "T1190"

    t8080 = engine.map_mitre_technique(8080)
    assert t8080["technique_id"] == "T1190"

    # Remote Services
    t22 = engine.map_mitre_technique(22)
    assert t22["technique_id"] == "T1021"
    assert "Remote Services" in t22["technique_name"]

    t3389 = engine.map_mitre_technique(3389)
    assert t3389["technique_id"] == "T1021"

    # DNS Exfiltration / C2
    t53 = engine.map_mitre_technique(53)
    assert t53["technique_id"] == "T1071.004"

    # Fallback / Generic DoS
    t_other = engine.map_mitre_technique(9999)
    assert t_other["technique_id"] == "T1498"


def test_find_active_incident_window_and_status():
    db = TestingSessionLocal()
    engine = CorrelationEngine()

    now = datetime.now(timezone.utc)
    inc1 = Incident(
        event_id="evt-001",
        source_ip="198.51.100.50",
        risk_score=70.0,
        severity="HIGH",
        reasons="Attack 1",
        status="OPEN",
        event_count=1,
        correlated_events=[],
        created_at=now,
        last_seen_at=now,
    )
    db.add(inc1)
    db.commit()

    # Should match inc1
    active = engine.find_active_incident(db, "198.51.100.50", time_window_minutes=10)
    assert active is not None
    assert active.id == inc1.id

    # Should NOT match different IP
    assert engine.find_active_incident(db, "198.51.100.51", time_window_minutes=10) is None

    # Expired incident outside 10m window
    old_time = now - timedelta(minutes=15)
    inc_old = Incident(
        event_id="evt-002",
        source_ip="198.51.100.60",
        risk_score=70.0,
        severity="HIGH",
        reasons="Attack old",
        status="OPEN",
        event_count=1,
        correlated_events=[],
        created_at=old_time,
        last_seen_at=old_time,
    )
    db.add(inc_old)
    db.commit()

    assert engine.find_active_incident(db, "198.51.100.60", time_window_minutes=10) is None

    # Resolved incident should NOT match
    inc1.status = "RESOLVED"
    db.commit()
    assert engine.find_active_incident(db, "198.51.100.50", time_window_minutes=10) is None

    db.close()


# ============================================================================
# End-to-End API Correlation Tests
# ============================================================================

def test_multi_event_correlation_aggregates_into_single_incident(client):
    """
    Submitting multiple malicious flows from the same IP should:
    1. Create an incident for the 1st event with event_count = 1.
    2. Correlate the 2nd event into the existing incident (count = 2, total incidents stays 1).
    3. Update risk_score, severity, and correlated_events list.
    """
    raw_payload = load_attack_payload()
    payload_1 = {
        "source_ip": "198.51.100.25",
        "features": dict(raw_payload["features"]),
    }
    payload_1["features"]["Destination Port"] = 80.0

    # First event ingestion
    res1 = client.post("/api/v1/events", json=payload_1)
    assert res1.status_code == 202
    data1 = res1.json()
    assert data1["predicted_label"] == "ATTACK"
    assert data1["incident_created"] is True
    inc1_id = data1["incident_id"]

    # Verify initial incident state
    inc_res1 = client.get(f"/api/v1/incidents/{inc1_id}")
    assert inc_res1.status_code == 200
    inc1_body = inc_res1.json()
    assert inc1_body["event_count"] == 1
    assert len(inc1_body["correlated_events"]) == 1
    assert inc1_body["mitre_attack"]["technique_id"] == "T1190"
    assert inc1_body["severity"] == "HIGH"
    first_risk = inc1_body["risk_score"]

    # Second event ingestion (same source_ip, port 8080)
    payload_2 = {
        "source_ip": "198.51.100.25",
        "features": dict(raw_payload["features"]),
    }
    payload_2["features"]["Destination Port"] = 8080.0

    res2 = client.post("/api/v1/events", json=payload_2)
    assert res2.status_code == 202
    data2 = res2.json()
    assert data2["predicted_label"] == "ATTACK"
    assert data2["incident_created"] is False  # Aggregated, not new!
    assert data2["incident_id"] == inc1_id

    # Check that total incident count in dashboard is still 1
    list_res = client.get("/api/v1/incidents")
    assert list_res.status_code == 200
    incidents_list = list_res.json()["incidents"]
    assert len(incidents_list) == 1
    assert incidents_list[0]["incident_id"] == inc1_id
    assert incidents_list[0]["event_count"] == 2

    # Check updated incident detail
    inc_res2 = client.get(f"/api/v1/incidents/{inc1_id}")
    assert inc_res2.status_code == 200
    inc2_body = inc_res2.json()
    assert inc2_body["event_count"] == 2
    assert len(inc2_body["correlated_events"]) == 2
    assert inc2_body["correlated_events"][1]["destination_port"] == 8080
    assert inc2_body["risk_score"] > first_risk

    # Third event -> escalates to CRITICAL
    payload_3 = {
        "source_ip": "198.51.100.25",
        "features": dict(raw_payload["features"]),
    }
    payload_3["features"]["Destination Port"] = 443.0

    res3 = client.post("/api/v1/events", json=payload_3)
    assert res3.status_code == 202
    data3 = res3.json()
    assert data3["incident_id"] == inc1_id

    inc_res3 = client.get(f"/api/v1/incidents/{inc1_id}")
    inc3_body = inc_res3.json()
    assert inc3_body["event_count"] == 3
    assert inc3_body["severity"] == "CRITICAL"
    assert inc3_body["risk_score"] >= 76.0


def test_different_source_ips_create_separate_incidents(client):
    raw_payload = load_attack_payload()
    payload_a = {
        "source_ip": "198.51.100.25",
        "features": dict(raw_payload["features"]),
    }
    payload_b = {
        "source_ip": "203.0.113.88",
        "features": dict(raw_payload["features"]),
    }

    res_a = client.post("/api/v1/events", json=payload_a)
    assert res_a.status_code == 202
    res_b = client.post("/api/v1/events", json=payload_b)
    assert res_b.status_code == 202

    assert res_a.json()["incident_id"] != res_b.json()["incident_id"]

    list_res = client.get("/api/v1/incidents")
    assert len(list_res.json()["incidents"]) == 2


def test_resolved_incident_triggers_new_incident_on_next_attack(client):
    raw_payload = load_attack_payload()
    payload = {
        "source_ip": "198.51.100.25",
        "features": dict(raw_payload["features"]),
    }

    # Step 1: Ingest attack -> creates incident 1
    res1 = client.post("/api/v1/events", json=payload)
    assert res1.status_code == 202
    inc1_id = res1.json()["incident_id"]

    # Step 2: Resolve incident 1
    patch_res = client.patch(
        f"/api/v1/incidents/{inc1_id}/status",
        json={"status": "RESOLVED"},
        headers=admin_headers(),
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "RESOLVED"

    # Step 3: Ingest new attack from same source IP -> must create NEW incident
    res2 = client.post("/api/v1/events", json=payload)
    assert res2.status_code == 202
    data2 = res2.json()
    assert data2["incident_created"] is True
    assert data2["incident_id"] != inc1_id
