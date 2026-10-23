
from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from backend.app.schemas.security_event import (
    DatasetTrainingRecord,
    DetectionResult,
    SecurityEvent,
)


def test_valid_network_event():
    event = SecurityEvent(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        destination_port=443,
        observed_at=datetime.now(timezone.utc),
        features={
            "Flow Duration": 100.0,
            "Total Fwd Packets": 5.0,
        },
    )

    assert event.event_type == "NETWORK_FLOW"
    assert event.destination_port == 443
    assert isinstance(event.event_id, UUID)


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            source_ip="not-an-ip",
            features={"Flow Duration": 10.0},
        )


def test_invalid_port_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            destination_port=70000,
            features={"Flow Duration": 10.0},
        )


def test_non_finite_feature_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent(
            features={"Flow Bytes/s": float("inf")},
        )


def test_dataset_label_is_separate_from_features():
    record = DatasetTrainingRecord(
        features={"Flow Duration": 10.0},
        dataset_label="BENIGN",
    )

    assert record.dataset_label == "BENIGN"
    assert "Label" not in record.features


def test_detection_result_ranges():
    result = DetectionResult(
        event_id=SecurityEvent(
            features={"Flow Duration": 10.0}
        ).event_id,
        predicted_label="ATTACK",
        confidence=0.95,
        risk_score=80,
    )

    assert result.predicted_label == "ATTACK"
    assert result.confidence == 0.95


def test_invalid_confidence_is_rejected():
    with pytest.raises(ValidationError):
        DetectionResult(
            event_id=SecurityEvent(
                features={"Flow Duration": 10.0}
            ).event_id,
            predicted_label="ATTACK",
            confidence=1.5,
        )
