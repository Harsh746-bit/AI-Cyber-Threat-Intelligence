
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_valid_event_is_accepted():
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


def test_invalid_port_is_rejected():
    response = client.post(
        "/api/v1/events",
        json={
            "destination_port": 70000,
            "features": {"Flow Duration": 10.0},
        },
    )

    assert response.status_code == 422


def test_ground_truth_label_is_rejected():
    response = client.post(
        "/api/v1/events",
        json={
            "features": {"Flow Duration": 10.0},
            "dataset_label": "BENIGN",
        },
    )

    assert response.status_code == 422


def test_non_finite_feature_is_rejected():
    response = client.post(
        "/api/v1/events",
        json={
            "features": {"Flow Duration": "Infinity"},
        },
    )

    assert response.status_code == 422

    
