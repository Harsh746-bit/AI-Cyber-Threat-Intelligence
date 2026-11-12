import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app, get_db
from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.models.incident import Incident
from backend.app.models.response import ResponseAction
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


def analyst_headers():
    token = create_access_token({"sub": "analyst", "user_id": 2, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def create_sample_incident(ip: str = "203.0.113.50") -> int:
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    inc = Incident(
        event_id=f"evt-{ip}-1",
        source_ip=ip,
        risk_score=95.0,
        severity="CRITICAL",
        reasons="attack_probability=0.9999",
        threat_intel={"abuse_confidence_score": 90, "total_reports": 450},
        mitre_attack={"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
        ai_analysis={
            "summary": "Critical brute force detected",
            "recommended_action": "BLOCK_IP",
            "action_target": ip,
            "confidence": "HIGH",
            "provider": "LocalRuleEngine",
        },
        event_count=5,
        status="OPEN",
        created_at=now,
        last_seen_at=now,
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    inc_id = inc.id
    db.close()
    return inc_id


def test_safety_allowlist_rejects_protected_ips(client):
    inc_id = create_sample_incident("198.51.100.1")
    
    # Attempt to propose containment targeting 127.0.0.1
    resp = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": "127.0.0.1"},
        headers=admin_headers(),
    )
    assert resp.status_code == 400
    assert "Safety Violation" in resp.json()["detail"]

    # Attempt to propose containment targeting 10.0.0.1
    resp2 = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": "10.0.0.1"},
        headers=admin_headers(),
    )
    assert resp2.status_code == 400
    assert "Safety Violation" in resp2.json()["detail"]


def test_admin_can_approve_and_execute_block_ip(client):
    target_ip = "198.51.100.77"
    inc_id = create_sample_incident(target_ip)

    # Propose action
    prop_resp = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": target_ip},
        headers=admin_headers(),
    )
    assert prop_resp.status_code == 200
    action_id = prop_resp.json()["id"]
    assert prop_resp.json()["status"] == "PENDING"
    assert prop_resp.json()["is_active"] is False

    # Admin approves action
    appr_resp = client.post(
        f"/api/v1/responses/{action_id}/approve",
        headers=admin_headers(),
    )
    assert appr_resp.status_code == 200
    data = appr_resp.json()
    assert data["status"] == "EXECUTED"
    assert data["is_active"] is True
    assert data["approved_by"] == "admin"
    assert "firewall drop rule applied" in data["execution_output"]

    # Check incident audit notes
    inc_resp = client.get(f"/api/v1/incidents/{inc_id}")
    assert inc_resp.status_code == 200
    notes = inc_resp.json()["investigation_notes"]
    assert any("[CONTAINMENT EXECUTED]" in n["content"] for n in notes)


def test_analyst_cannot_approve_response_action_403(client):
    target_ip = "198.51.100.88"
    inc_id = create_sample_incident(target_ip)

    prop_resp = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": target_ip},
        headers=analyst_headers(),
    )
    assert prop_resp.status_code == 200
    action_id = prop_resp.json()["id"]

    # Analyst attempts to approve -> 403 Forbidden
    appr_resp = client.post(
        f"/api/v1/responses/{action_id}/approve",
        headers=analyst_headers(),
    )
    assert appr_resp.status_code == 403

    # Analyst attempts to reject -> 403 Forbidden
    rej_resp = client.post(
        f"/api/v1/responses/{action_id}/reject",
        headers=analyst_headers(),
    )
    assert rej_resp.status_code == 403

    # Analyst attempts to rollback -> 403 Forbidden
    roll_resp = client.post(
        f"/api/v1/responses/{action_id}/rollback",
        headers=analyst_headers(),
    )
    assert roll_resp.status_code == 403


def test_admin_can_reject_response_action(client):
    target_ip = "198.51.100.99"
    inc_id = create_sample_incident(target_ip)

    prop_resp = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "RATE_LIMIT", "target": target_ip},
        headers=admin_headers(),
    )
    action_id = prop_resp.json()["id"]

    rej_resp = client.post(
        f"/api/v1/responses/{action_id}/reject",
        headers=admin_headers(),
    )
    assert rej_resp.status_code == 200
    data = rej_resp.json()
    assert data["status"] == "REJECTED"
    assert data["is_active"] is False

    # Check incident audit notes
    inc_resp = client.get(f"/api/v1/incidents/{inc_id}")
    notes = inc_resp.json()["investigation_notes"]
    assert any("[CONTAINMENT REJECTED]" in n["content"] for n in notes)


def test_ingestion_drops_traffic_from_blocked_ip_and_rollback_restores(client):
    blocked_ip = "203.0.113.200"
    inc_id = create_sample_incident(blocked_ip)

    # Propose and approve BLOCK_IP
    prop_resp = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": blocked_ip},
        headers=admin_headers(),
    )
    action_id = prop_resp.json()["id"]

    client.post(
        f"/api/v1/responses/{action_id}/approve",
        headers=admin_headers(),
    )

    # Try ingesting an event from blocked_ip -> Must be dropped with 403
    payload = {
        "event_id": "00000000-0000-0000-0000-000000000001",
        "schema_version": "1.0",
        "event_type": "NETWORK_FLOW",
        "source_ip": blocked_ip,
        "destination_port": 80,
        "protocol": "TCP",
        "features": {"Destination Port": 80.0, "Flow Duration": 100.0},
    }
    drop_resp = client.post("/api/v1/events", json=payload)
    assert drop_resp.status_code == 403
    assert "actively blocked" in drop_resp.json()["detail"]

    # Now rollback the block
    roll_resp = client.post(
        f"/api/v1/responses/{action_id}/rollback",
        headers=admin_headers(),
    )
    assert roll_resp.status_code == 200
    assert roll_resp.json()["status"] == "ROLLED_BACK"
    assert roll_resp.json()["is_active"] is False

    # Ingestion should now accept telemetry from the unblocked IP (or validate ML)
    payload_2 = {
        "event_id": "00000000-0000-0000-0000-000000000002",
        "schema_version": "1.0",
        "event_type": "NETWORK_FLOW",
        "source_ip": blocked_ip,
        "destination_port": 80,
        "protocol": "TCP",
        "features": {"Destination Port": 80.0, "Flow Duration": 100.0},
    }
    accept_resp = client.post("/api/v1/events", json=payload_2)
    assert accept_resp.status_code in (200, 202)


# ============================================================================
# Deep IP Validation & Subnet Containment Policy Tests
# ============================================================================

def test_ipv4_and_ipv6_loopback_protection(client):
    """Verifies that all loopback variants are rejected as safety violations."""
    inc_id = create_sample_incident("198.51.100.1")

    # IPv4 loopback variants
    for loop_ip in ["127.0.0.1", "127.0.0.2", "127.1.2.3"]:
        resp = client.post(
            f"/api/v1/incidents/{inc_id}/responses",
            json={"action_type": "BLOCK_IP", "target": loop_ip},
            headers=admin_headers(),
        )
        assert resp.status_code == 400
        assert "Safety Violation" in resp.json()["detail"]

    # IPv6 loopback
    resp_v6 = client.post(
        f"/api/v1/incidents/{inc_id}/responses",
        json={"action_type": "BLOCK_IP", "target": "::1"},
        headers=admin_headers(),
    )
    assert resp_v6.status_code == 400
    assert "Safety Violation" in resp_v6.json()["detail"]


def test_unspecified_and_link_local_ip_protection(client):
    """Verifies that unspecified (0.0.0.0, ::) and link-local addresses are rejected."""
    inc_id = create_sample_incident("198.51.100.2")

    # Unspecified
    for unspec in ["0.0.0.0", "::"]:
        resp = client.post(
            f"/api/v1/incidents/{inc_id}/responses",
            json={"action_type": "BLOCK_IP", "target": unspec},
            headers=admin_headers(),
        )
        assert resp.status_code == 400
        assert "Safety Violation" in resp.json()["detail"]

    # Link-local IPv4 & IPv6
    for link_local in ["169.254.1.1", "fe80::1"]:
        resp = client.post(
            f"/api/v1/incidents/{inc_id}/responses",
            json={"action_type": "BLOCK_IP", "target": link_local},
            headers=admin_headers(),
        )
        assert resp.status_code == 400
        assert "Safety Violation" in resp.json()["detail"]


def test_malformed_ip_rejection(client):
    """Verifies that syntactically malformed IPs cannot be proposed for containment."""
    inc_id = create_sample_incident("198.51.100.3")

    for bad_ip in ["999.999.999.999", "192.168.1.500", "not-an-ip", "2001:xyz::1"]:
        resp = client.post(
            f"/api/v1/incidents/{inc_id}/responses",
            json={"action_type": "BLOCK_IP", "target": bad_ip},
            headers=admin_headers(),
        )
        assert resp.status_code == 400
        assert "Safety Violation" in resp.json()["detail"]
        assert "Malformed IP" in resp.json()["detail"] or "not a valid" in resp.json()["detail"]


def test_configured_protected_individual_ip_and_cidr_subnets():
    """Unit test ResponseEngine with custom protected hosts and CIDR ranges."""
    from backend.app.services.response_engine import ResponseEngine

    custom_engine = ResponseEngine(
        protected_ips={"192.168.50.10", "db.internal.lan"},
        protected_cidrs=["10.50.0.0/16", "172.20.0.0/24"],
    )

    # 1. Individual protected IP
    allowed, reason = custom_engine.validate_target("192.168.50.10")
    assert allowed is False
    assert "protected infrastructure" in reason.lower()

    # 2. Inside protected CIDR
    allowed, reason = custom_engine.validate_target("10.50.1.25")
    assert allowed is False
    assert "protected network subnet" in reason.lower()

    allowed, reason = custom_engine.validate_target("172.20.0.42")
    assert allowed is False
    assert "protected network subnet" in reason.lower()

    # 3. Outside protected CIDR but private RFC1918 enterprise endpoint -> ALLOWED for containment
    allowed, reason = custom_engine.validate_target("10.60.1.25")
    assert allowed is True
    assert reason == "OK"

    allowed, reason = custom_engine.validate_target("192.168.100.45")
    assert allowed is True
    assert reason == "OK"

    # 4. Public IP -> ALLOWED for containment
    allowed, reason = custom_engine.validate_target("203.0.113.195")
    assert allowed is True
    assert reason == "OK"

