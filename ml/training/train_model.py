
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DATA_PATH = Path("ml/artifacts/binary_sample.csv")
MODEL_PATH = Path("ml/artifacts/binary_model.joblib")

RANDOM_STATE = 42


def main():
    if not DATA_PATH.exists():
        raise SystemExit(
            f"Dataset not found: {DATA_PATH}. "
            "Run ml/prepare_dataset.py first."
        )

    print("Loading prepared sample...")
    df = pd.read_csv(DATA_PATH, low_memory=False)

    if "_target" not in df.columns:
        raise SystemExit("Missing _target column.")

    # Keep only numeric features. Never train on labels or targets.
    excluded = {"Label", "_target"}
    feature_columns = [
        c for c in df.columns
        if c not in excluded and pd.api.types.is_numeric_dtype(df[c])
    ]

    if not feature_columns:
        raise SystemExit("No numeric feature columns found.")

    X = df[feature_columns].replace(
        [np.inf, -np.inf], np.nan
    )
    y = df["_target"].astype("int8")

    print(f"Records: {len(df):,}")
    print(f"Numeric features: {len(feature_columns)}")
    print("Splitting into training and test sets...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )),
    ])

    print("Training Random Forest. This may take a while...")
    model.fit(X_train, y_train)

    print("\nEvaluating on held-out test data...")
    predictions = model.predict(X_test)

    print(f"\nAccuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    ))

    print("Confusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test, predictions))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": model,
        "feature_columns": feature_columns,
        "target_mapping": {0: "BENIGN", 1: "ATTACK"},
    }, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")
    print("Training complete.")


if __name__ == "__main__":
    main()
