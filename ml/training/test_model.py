
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_PATH = Path("ml/artifacts/binary_model.joblib")
DATA_PATH = Path("ml/artifacts/binary_sample.csv")


def main():
    print("Loading saved model...")
    saved = joblib.load(MODEL_PATH)

    model = saved["pipeline"]
    feature_columns = saved["feature_columns"]

    print(f"Expected features: {len(feature_columns)}")

    # Load a few rows strictly for an inference smoke test.
    df = pd.read_csv(DATA_PATH, nrows=10)

    X = df[feature_columns].replace(
        [np.inf, -np.inf], np.nan
    )

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    names = {0: "BENIGN", 1: "ATTACK"}

    for i, prediction in enumerate(predictions):
        print(
            f"Record {i + 1}: "
            f"predicted={names[int(prediction)]}, "
            f"attack_probability={probabilities[i][1]:.4f}, "
            f"actual={names[int(df['_target'].iloc[i])]}"
        )

    print("\nInference smoke test completed.")


if __name__ == "__main__":
    main()
