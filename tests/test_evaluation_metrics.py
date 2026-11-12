import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_get_ml_metrics_returns_200(client):
    resp = client.get("/api/v1/ml/metrics")
    assert resp.status_code == 200
    data = resp.json()

    assert "model_metadata" in data
    assert "evaluation_metrics" in data

    meta = data["model_metadata"]
    assert meta["total_features"] == 78
    assert "CIC-IDS2017" in meta["training_dataset"]
    assert meta["model_type"] == "RandomForestClassifier"


def test_ml_metrics_values_conform_to_benchmark(client):
    resp = client.get("/api/v1/ml/metrics")
    assert resp.status_code == 200
    metrics = resp.json()["evaluation_metrics"]

    assert 0.95 <= metrics["accuracy"] <= 1.0
    assert 0.95 <= metrics["precision"] <= 1.0
    assert 0.95 <= metrics["recall"] <= 1.0
    assert 0.95 <= metrics["f1_score"] <= 1.0
    assert 0.98 <= metrics["roc_auc"] <= 1.0
    assert metrics["false_positive_rate"] < 0.05
    assert metrics["false_negative_rate"] < 0.05


def test_confusion_matrix_schema(client):
    resp = client.get("/api/v1/ml/metrics")
    assert resp.status_code == 200
    data = resp.json()

    if "confusion_matrix" in data:
        cm = data["confusion_matrix"]
        assert "true_negatives" in cm
        assert "false_positives" in cm
        assert "false_negatives" in cm
        assert "true_positives" in cm


# ============================================================================
# ML Inference Consistency & Feature Name Tests
# ============================================================================

def test_predict_attack_feature_consistency_and_warning_elimination():
    """Verifies that predict_attack supplies 78 named features without sklearn warnings."""
    import json
    import warnings
    from pathlib import Path
    from backend.app.services.ml_detection import predict_attack, load_model

    saved = load_model()
    expected_features = saved["feature_columns"]
    assert len(expected_features) == 78

    payload_path = Path("attack_request.json")
    if not payload_path.exists():
        pytest.skip("attack_request.json not found")

    with open(payload_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    # Catch warnings during prediction
    with warnings.catch_warnings(record=True) as captured_warnings:
        warnings.simplefilter("always")
        result = predict_attack(payload["features"])

        # Must produce clean inference without SimpleImputer feature name warnings
        sklearn_warnings = [
            w for w in captured_warnings
            if "does not have valid feature names" in str(w.message)
        ]
        assert len(sklearn_warnings) == 0, f"Expected 0 feature name warnings, found: {sklearn_warnings}"

    assert result["predicted_label"] == "ATTACK"
    assert result["attack_probability"] >= 0.90
    assert result["feature_count"] == 78


def test_predict_attack_rejects_missing_and_non_finite_features():
    """Verifies that invalid feature inputs are correctly handled."""
    from backend.app.services.ml_detection import predict_attack

    # Incomplete features
    with pytest.raises(ValueError):
        predict_attack({"Destination Port": 80.0})

    # Non-finite feature value
    import json
    from pathlib import Path
    payload_path = Path("attack_request.json")
    if not payload_path.exists():
        pytest.skip("attack_request.json not found")

    with open(payload_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    bad_features = dict(payload["features"])
    bad_features["Destination Port"] = float("nan")

    with pytest.raises(ValueError, match="must be finite"):
        predict_attack(bad_features)

        assert cm["true_positives"] > 0
        assert cm["true_negatives"] > 0
