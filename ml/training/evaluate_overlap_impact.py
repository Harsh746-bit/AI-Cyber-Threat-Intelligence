
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

DATA_PATH = Path("ml/artifacts/binary_sample.csv")
MODEL_PATH = Path("ml/artifacts/binary_model.joblib")


def main():
    print("Loading data and saved model...", flush=True)
    df = pd.read_csv(DATA_PATH, low_memory=False)
    saved = joblib.load(MODEL_PATH)

    columns = saved["feature_columns"]
    X = df[columns].replace([np.inf, -np.inf], np.nan)
    y = df["_target"].astype("int8")

    train_idx, test_idx = train_test_split(
        np.arange(len(df)),
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("Finding overlapping rows...", flush=True)
    hashes = pd.util.hash_pandas_object(
        X, index=False
    ).to_numpy()

    train_hashes = set(hashes[train_idx])
    overlap = np.isin(hashes[test_idx], list(train_hashes))

    print("Predicting test set...", flush=True)
    predictions = saved["pipeline"].predict(X.iloc[test_idx])

    actual = y.iloc[test_idx].to_numpy()
    correct = predictions == actual

    for name, mask in [
        ("OVERLAPPING", overlap),
        ("NON-OVERLAPPING", ~overlap),
        ("ALL TEST ROWS", np.ones(len(test_idx), dtype=bool)),
    ]:
        count = int(mask.sum())
        accuracy = accuracy_score(actual[mask], predictions[mask])

        print(f"\n{name}")
        print(f"Rows: {count:,}")
        print(f"Accuracy: {accuracy:.4%}")
        print(f"Incorrect predictions: {int((~correct[mask]).sum()):,}")

    print(
        "\nNote: This uses the original random split and saved model. "
        "The non-overlapping subset is useful diagnostically, "
        "but is not an independent retraining evaluation."
    )


if __name__ == "__main__":
    main()
