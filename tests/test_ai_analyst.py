import json
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
from backend.app.services.ai_analyst import (
    AIThreatAnalyst,
    ai_threat_analyst,
    VALID_ACTIONS,
    VALID_CONFIDENCES,
)
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


def analyst_headers():
    token = create_access_token({"sub": "analyst", "user_id": 2, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# 1. Deterministic Template Generation Across Severity Bands
# ============================================================================

def test_deterministic_analysis_critical_severity():
    analyst = AIThreatAnalyst()
    payload = {
        "id": 101,
        "source_ip": "198.51.100.25",
        "risk_score": 85.0,
        "severity": "CRITICAL",
        "event_count": 3,
        "destination_port": 80,
        "protocol": "TCP",
        "ml_confidence": 1.0,
        "threat_intel": {
            "abuse_confidence_score": 85,
            "total_reports": 24,
            "country_code": "US",
            "is_private": False,
        },
        "mitre_attack": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
    }

    report = analyst._generate_rule_based_analysis(payload)

    # Schema validation
    assert "summary" in report and len(report["summary"]) > 0
    assert "analysis" in report and len(report["analysis"]) > 0
    assert report["recommended_action"] in VALID_ACTIONS
    assert report["recommended_action"] == "BLOCK_IP"
    assert report["confidence"] == "HIGH"
    assert report["action_target"] == "198.51.100.25"
    assert report["provider"] == "LocalRuleEngine"
    assert "generated_at" in report
    # Grounded reasoning verification
    assert "198.51.100.25" in report["summary"]
    assert "T1190" in report["summary"]
    assert "100.0%" in report["analysis"]
    assert "85%" in report["analysis"]


def test_deterministic_analysis_high_severity():
    analyst = AIThreatAnalyst()
    payload = {
        "id": 102,
        "source_ip": "203.0.113.88",
        "risk_score": 65.0,
        "severity": "HIGH",
        "event_count": 1,
        "destination_port": 22,
        "protocol": "TCP",
        "ml_confidence": 0.85,
        "threat_intel": {
            "abuse_confidence_score": 40,
            "total_reports": 5,
            "country_code": "DE",
            "is_private": False,
        },
        "mitre_attack": {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "tactic": "Lateral Movement",
        },
    }

    report = analyst._generate_rule_based_analysis(payload)

    assert report["recommended_action"] == "RATE_LIMIT"
    assert report["confidence"] == "MEDIUM"
    assert "T1021" in report["summary"]
    assert "203.0.113.88" in report["action_target"]


def test_deterministic_analysis_low_severity():
    analyst = AIThreatAnalyst()
    payload = {
        "id": 103,
        "source_ip": "10.0.0.15",
        "risk_score": 20.0,
        "severity": "LOW",
        "event_count": 1,
        "destination_port": 8080,
        "protocol": "TCP",
        "ml_confidence": 0.35,
        "threat_intel": {
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": "PRIVATE",
            "is_private": True,
        },
        "mitre_attack": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
    }

    report = analyst._generate_rule_based_analysis(payload)

    assert report["recommended_action"] == "MONITOR"
    assert report["confidence"] == "LOW"
    assert "internal origin" in report["analysis"]


# ============================================================================
# 2. Resilient Execution & Fallback on Missing / Invalid Keys
# ============================================================================

def test_analyze_incident_falls_back_when_no_keys(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    analyst = AIThreatAnalyst()
    payload = {
        "source_ip": "198.51.100.12",
        "risk_score": 78.0,
        "severity": "CRITICAL",
        "reasons": "attack_probability=0.990000",
        "threat_intel": {"abuse_confidence_score": 85},
    }

    res = analyst.analyze_incident(payload)
    assert res["provider"] == "LocalRuleEngine"
    assert res["recommended_action"] == "BLOCK_IP"
    assert res["confidence"] == "HIGH"


def test_analyze_incident_handles_invalid_key_gracefully(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "INVALID_TEST_KEY_THAT_WILL_FAIL")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    analyst = AIThreatAnalyst()
    payload = {
        "source_ip": "198.51.100.12",
        "risk_score": 78.0,
        "severity": "CRITICAL",
        "reasons": "attack_probability=0.990000",
        "threat_intel": {"abuse_confidence_score": 85},
    }

    # Should catch HTTP error / timeout and fall back to LocalRuleEngine without raising
    res = analyst.analyze_incident(payload)
    assert res["provider"] == "LocalRuleEngine"
    assert res["recommended_action"] == "BLOCK_IP"


# ============================================================================
# 3. Interactive Endpoint: POST /api/v1/incidents/{id}/analyze-ai
# ============================================================================

def test_trigger_ai_analysis_endpoint_success(client):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    incident = Incident(
        event_id="evt-ai-test-01",
        source_ip="198.51.100.25",
        risk_score=82.0,
        severity="CRITICAL",
        reasons="attack_probability=1.000000",
        status="OPEN",
        event_count=2,
        threat_intel={"abuse_confidence_score": 85, "country_code": "US", "total_reports": 20},
        mitre_attack={"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        correlated_events=[{"event_id": "evt-1", "destination_port": 80}],
        created_at=now,
        last_seen_at=now,
    )
    db.add(incident)
    db.commit()
    inc_id = incident.id
    db.close()

    # Call on-demand AI analysis endpoint
    response = client.post(
        f"/api/v1/incidents/{inc_id}/analyze-ai",
        headers=analyst_headers(),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == inc_id
    assert "ai_analysis" in data
    ai_report = data["ai_analysis"]
    assert ai_report is not None
    assert ai_report["recommended_action"] == "BLOCK_IP"
    assert ai_report["confidence"] == "HIGH"
    assert ai_report["action_target"] == "198.51.100.25"
    assert "summary" in ai_report
    assert "analysis" in ai_report
    assert ai_report["provider"] in ("LocalRuleEngine", "Gemini", "OpenAI")


def test_trigger_ai_analysis_endpoint_404(client):
    response = client.post(
        "/api/v1/incidents/99999/analyze-ai",
        headers=analyst_headers(),
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
