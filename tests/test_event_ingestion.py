
import pytest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.main import app, get_db
from backend.app.models.security_event import SecurityEventRecord


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
    with TestClient(app) as test_client:
        yield test_client


def test_valid_event_is_accepted(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "NETWORK_FLOW",
            "destination_port": 443,
            "features": {
                "Flow Duration": 100.0,
                "Total Fwd Packets": 5.0,
            },
        },
    )

    assert response.status_code == 202, response.text

    body = response.json()

    assert body["status"] == "accepted"
    assert body["event_type"] == "NETWORK_FLOW"
    assert body["event_id"]


def test_invalid_port_is_rejected(client):
    response = client.post(
        "/api/v1/events",
        json={
            "destination_port": 70000,
            "features": {
                "Flow Duration": 10.0,
            },
        },
    )

    assert response.status_code == 422


def test_ground_truth_label_is_rejected(client):
    response = client.post(
        "/api/v1/events",
        json={
            "features": {
                "Flow Duration": 10.0,
            },
            "dataset_label": "BENIGN",
        },
    )

    assert response.status_code == 422


def test_non_finite_feature_is_rejected(client):
    response = client.post(
        "/api/v1/events",
        json={
            "features": {
                "Flow Duration": "Infinity",
            },
        },
    )

    assert response.status_code == 422


def test_event_is_persisted(client, test_db):
    payload = {
        "event_type": "NETWORK_FLOW",
        "destination_port": 443,
        "features": {
            "Flow Duration": 100.0,
            "Total Fwd Packets": 5.0,
        },
    }

    response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert response.status_code == 202, response.text

    event_id = response.json()["event_id"]

    with test_db() as db:
        stored_event = (
            db.query(SecurityEventRecord)
            .filter(
                SecurityEventRecord.event_id == event_id
            )
            .first()
        )

        assert stored_event is not None
        assert stored_event.destination_port == 443
        assert stored_event.features["Flow Duration"] == 100.0
        assert stored_event.features["Total Fwd Packets"] == 5.0


def test_duplicate_event_id_is_rejected(client):
    payload = {
        "event_id": str(uuid4()),
        "event_type": "NETWORK_FLOW",
        "features": {
            "Flow Duration": 100.0,
        },
    }

    first_response = client.post(
        "/api/v1/events",
        json=payload,
    )

    second_response = client.post(
        "/api/v1/events",
        json=payload,
    )

    assert first_response.status_code == 202, first_response.text
    assert second_response.status_code == 409, second_response.text
