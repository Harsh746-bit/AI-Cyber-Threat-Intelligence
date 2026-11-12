
from functools import lru_cache
from pathlib import Path
from math import isfinite

import joblib
import numpy as np
import pandas as pd


MODEL_PATH = (
    Path(__file__).resolve().parents[3]
    / "ml"
    / "artifacts"
    / "binary_model.joblib"
)


@lru_cache(maxsize=1)
def load_model():
    """Load the trusted, locally trained model once."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Trained ML model not found at {MODEL_PATH}"
        )

    saved = joblib.load(MODEL_PATH)

    if not isinstance(saved, dict):
        raise ValueError("Unexpected saved model format.")

    if "pipeline" not in saved or "feature_columns" not in saved:
        raise ValueError("Saved model is missing required metadata.")

    feature_columns = saved["feature_columns"]

    if not feature_columns or len(set(feature_columns)) != len(feature_columns):
        raise ValueError("Invalid feature-column metadata.")

    return saved


def predict_attack(features: dict[str, float]) -> dict:
    """Validate traffic features and predict BENIGN or ATTACK."""
    saved = load_model()
    expected = saved["feature_columns"]

    missing = sorted(set(expected) - set(features))
    unexpected = sorted(set(features) - set(expected))

    if missing or unexpected:
        raise ValueError({
            "message": "Feature names do not match the trained model.",
            "missing_features": missing,
            "unexpected_features": unexpected,
        })

    for name, value in features.items():
        if not isfinite(value):
            raise ValueError(f"Feature '{name}' must be finite.")

    # Preserve the exact feature names and order used during training
    # using a pandas DataFrame to maintain feature name consistency with SimpleImputer.
    row = pd.DataFrame(
        [[float(features[name]) for name in expected]],
        columns=expected,
        dtype=np.float64,
    )

    model = saved["pipeline"]
    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]

    attack_index = list(model.classes_).index(1)
    attack_probability = float(probabilities[attack_index])

    return {
        "predicted_label": (
            "ATTACK" if prediction == 1 else "BENIGN"
        ),
        "attack_probability": round(attack_probability, 6),
        "model_type": "random_forest_binary",
        "feature_count": len(expected),
    }
