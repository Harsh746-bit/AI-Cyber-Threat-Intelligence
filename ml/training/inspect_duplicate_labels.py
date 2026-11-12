
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

DATA_PATH = Path("ml/artifacts/binary_sample.csv")


def main():
    print("Loading dataset...", flush=True)
    df = pd.read_csv(DATA_PATH, low_memory=False)

    feature_columns = [
        c for c in df.columns
        if c not in {"Label", "_target"}
        and pd.api.types.is_numeric_dtype(df[c])
    ]

    X = df[feature_columns].replace(
        [np.inf, -np.inf], np.nan
    )
    y = df["_target"].astype("int8")

    train_idx, test_idx = train_test_split(
        np.arange(len(df)),
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("Hashing feature rows...", flush=True)
    hashes = pd.util.hash_pandas_object(
        X, index=False
    ).to_numpy()

    train_hashes = set(hashes[train_idx])
    test_hashes = hashes[test_idx]

    overlap_mask = np.isin(
        test_hashes, list(train_hashes)
    )

    overlap_indices = test_idx[overlap_mask]

    print("Analyzing duplicate labels...", flush=True)
    audit = pd.DataFrame({
        "hash": hashes[overlap_indices],
        "target": y.iloc[overlap_indices].to_numpy(),
    })

    # Compare labels across all occurrences of overlapping feature rows.
    train_audit = pd.DataFrame({
        "hash": hashes[train_idx],
        "target": y.iloc[train_idx].to_numpy(),
    })

    combined = pd.concat(
        [train_audit, audit], ignore_index=True
    )

    label_counts = combined.groupby("hash")["target"].nunique()

    conflicting_hashes = int((label_counts > 1).sum())
    shared_hash_count = len(set(hashes[overlap_indices]))

    print("\n--- Duplicate label audit ---")
    print("Overlapping test rows:", len(overlap_indices))
    print("Shared feature hashes:", shared_hash_count)
    print("Shared hashes with conflicting labels:", conflicting_hashes)
    print("\nOverlapping test-row labels:")
    print(y.iloc[overlap_indices].map({
        0: "BENIGN", 1: "ATTACK"
    }).value_counts().to_string())


if __name__ == "__main__":
    main()
