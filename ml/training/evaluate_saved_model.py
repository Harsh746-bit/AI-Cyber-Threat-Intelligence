
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

DATA_PATH = Path("ml/artifacts/binary_sample.csv")
MODEL_PATH = Path("ml/artifacts/binary_model.joblib")


def main():
    print("Loading dataset and saved model...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    saved = joblib.load(MODEL_PATH)

    X = df[saved["feature_columns"]].replace(
        [np.inf, -np.inf], np.nan
    )
    y = df["_target"].astype("int8")

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = saved["pipeline"]

    print("Evaluating saved model...")
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    classes = list(model.classes_)
    attack_index = classes.index(1)
    attack_probabilities = probabilities[:, attack_index]

    print(f"\nAccuracy: {accuracy_score(y_test, predictions):.4%}")

    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        digits=4,
        zero_division=0,
    ))

    print("\nConfusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    print(
        "\nROC-AUC:",
        f"{roc_auc_score(y_test, attack_probabilities):.4f}",
    )


if __name__ == "__main__":
    main()
