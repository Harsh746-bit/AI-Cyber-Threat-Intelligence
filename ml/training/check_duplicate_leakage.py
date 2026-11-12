
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

DATA_PATH = Path("ml/artifacts/binary_sample.csv")
RANDOM_STATE = 42


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH, low_memory=False)

    excluded = {"Label", "_target"}
    feature_columns = [
        col
        for col in df.columns
        if col not in excluded
        and pd.api.types.is_numeric_dtype(df[col])
    ]

    X = df[feature_columns].replace(
        [np.inf, -np.inf], np.nan
    )
    y = df["_target"].astype("int8")

    train_idx, test_idx = train_test_split(
        np.arange(len(df)),
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Hash each feature row, ignoring its original dataframe index.
    row_hashes = pd.util.hash_pandas_object(
        X, index=False
    )

    train_hashes = row_hashes.iloc[train_idx]
    test_hashes = row_hashes.iloc[test_idx]

    train_unique = set(train_hashes)
    test_unique = set(test_hashes)
    shared_hashes = train_unique.intersection(test_unique)

    test_rows_overlapping = test_hashes.isin(
        train_unique
    ).sum()

    print("\n--- Duplicate Leakage Audit ---")
    print(f"Total rows: {len(df):,}")
    print(f"Training rows: {len(train_idx):,}")
    print(f"Test rows: {len(test_idx):,}")
    print(f"Unique training feature rows: {len(train_unique):,}")
    print(f"Unique test feature rows: {len(test_unique):,}")
    print(f"Shared unique row hashes: {len(shared_hashes):,}")
    print(
        "Test rows also present in training: "
        f"{test_rows_overlapping:,} "
        f"({test_rows_overlapping / len(test_idx):.2%})"
    )

    print(
        "\nNote: this checks exact feature-row duplicates only. "
        "It does not detect near-duplicates or related flows."
    )
    print(
        "Hash matches are a screening signal; inspect matching "
        "rows and labels before drawing conclusions."
    )


if __name__ == "__main__":
    main()
