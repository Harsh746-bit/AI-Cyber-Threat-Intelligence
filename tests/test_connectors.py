import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app, get_db
from backend.app.db.database import Base, ensure_schema_migrations
from backend.app.models.response import ResponseAction
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
    return TestClient(app, headers={"X-SENTRIX-SENSOR-KEY": "sentrix-test-isolated-sensor-key-32chars!"})


def test_get_supported_connectors(client):
    resp = client.get("/api/v1/ingest/connectors")
    assert resp.status_code == 200
    connectors = resp.json()["supported_connectors"]
    ids = [c["id"] for c in connectors]
    assert "NGINX_ACCESS" in ids
    assert "SURICATA_EVE" in ids
    assert "SYSLOG_AUTH" in ids
    assert "NETWORK_FLOW" in ids


def test_nginx_access_log_ingestion_and_incident_creation(client):
    log_line = '198.51.100.33 - - [10/Nov/2026:14:32:10 +0000] "GET /admin/config.php HTTP/1.1" 404 342 "-" "Mozilla/5.0"'
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": log_line},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["source_type"] == "NGINX_ACCESS"
    assert data["incident_created"] is True
    assert data["incident_id"] is not None
    assert data["normalized_data"]["source_ip"] == "198.51.100.33"
    assert data["normalized_data"]["event_type"] == "WEB_ACCESS"
    assert data["normalized_data"]["destination_port"] == 80


def test_suricata_eve_json_ingestion(client):
    eve_payload = {
        "timestamp": "2026-11-10T14:32:10.000Z",
        "src_ip": "198.51.100.45",
        "src_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2001219,
            "rev": 2,
            "signature": "ET SCAN Potential SSH Scan OUTBOUND",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
    }
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "SURICATA_EVE", "raw_payload": eve_payload},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["source_type"] == "SURICATA_EVE"
    assert data["incident_created"] is True
    assert data["normalized_data"]["source_ip"] == "198.51.100.45"
    assert data["normalized_data"]["event_type"] == "NIDS_ALERT"
    assert "ET SCAN Potential SSH Scan" in data["normalized_data"]["detection_reason"]


def test_syslog_auth_failed_ssh(client):
    syslog_line = "Nov 10 14:32:10 soc-gateway sshd[2412]: Failed password for invalid user admin from 198.51.100.77 port 48212 ssh2"
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "SYSLOG_AUTH", "raw_payload": syslog_line},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["source_type"] == "SYSLOG_AUTH"
    assert data["incident_created"] is True
    assert data["normalized_data"]["source_ip"] == "198.51.100.77"
    assert data["normalized_data"]["event_type"] == "AUTH_FAILURE"
    assert data["normalized_data"]["destination_port"] == 22
    assert data["normalized_data"]["raw_metadata"]["target_username"] == "admin"


def test_corrupt_or_unparseable_log_returns_422(client):
    junk = "NOT A VALID LOG LINE 12345 HELLO WORLD"
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": junk},
    )
    assert resp.status_code == 422
    assert "Failed to parse raw telemetry" in resp.json()["detail"]


def test_unsupported_source_type_returns_400(client):
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "UNKNOWN_FIREWALL", "raw_payload": "some data"},
    )
    assert resp.status_code == 400
    assert "Unsupported source_type" in resp.json()["detail"]


def test_ingest_raw_drops_traffic_from_blocked_ip_403(client):
    blocked_ip = "198.51.100.99"
    # Create an active block rule in DB directly
    db = TestingSessionLocal()
    block_rule = ResponseAction(
        incident_id=1,
        action_type="BLOCK_IP",
        target=blocked_ip,
        status="EXECUTED",
        requested_by="Admin",
        approved_by="Admin",
        is_active=True,
    )
    db.add(block_rule)
    db.commit()
    db.close()

    # Now attempt to ingest a raw log from the blocked IP
    log_line = f'{blocked_ip} - - [10/Nov/2026:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1024'
    resp = client.post(
        "/api/v1/ingest/raw",
        json={"source_type": "NGINX_ACCESS", "raw_payload": log_line},
    )
    assert resp.status_code == 403
    assert "actively blocked" in resp.json()["detail"]
