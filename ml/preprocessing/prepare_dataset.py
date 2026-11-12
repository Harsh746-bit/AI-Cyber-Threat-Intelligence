
from pathlib import Path

import numpy as np
import pandas as pd

DATASET_DIR = Path(
    r"D:\Projects\AI-CTIR\MachineLearningCSV\MachineLearningCVE"
)
OUTPUT_PATH = Path("ml/artifacts/binary_sample.csv")

CHUNK_SIZE = 50_000
SAMPLES_PER_CLASS_PER_CHUNK = 2_000
MAX_PER_CLASS = 100_000
RANDOM_STATE = 42


def main():
    files = sorted(DATASET_DIR.glob("*.csv"))

    if not files:
        raise SystemExit(f"No CSV files found in {DATASET_DIR}")

    sampled_chunks = []
    total_rows = 0

    for file_path in files:
        print(f"\nReading: {file_path.name}")

        for chunk in pd.read_csv(
            file_path,
            encoding="utf-8-sig",
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):
            chunk.columns = chunk.columns.str.strip()

            if "Label" not in chunk.columns:
                raise ValueError(
                    f"Missing Label column in {file_path.name}"
                )

            total_rows += len(chunk)

            # Standardize whitespace and capitalization for binary labels.
            labels = chunk["Label"].astype("string").str.strip().str.upper()
            chunk["Label"] = labels

            # Convert positive/negative infinity into missing values.
            feature_columns = [
                column for column in chunk.columns
                if column != "Label"
            ]

            for column in feature_columns:
                chunk[column] = pd.to_numeric(
                    chunk[column], errors="coerce"
                )

            chunk[feature_columns] = chunk[
                feature_columns
            ].replace([np.inf, -np.inf], np.nan)

            # Binary target: BENIGN vs every attack.
            chunk["_target"] = (
                chunk["Label"] != "BENIGN"
            ).astype("int8")

            for target in (0, 1):
                group = chunk[chunk["_target"] == target]

                if group.empty:
                    continue

                n = min(
                    len(group),
                    SAMPLES_PER_CLASS_PER_CHUNK,
                )

                sampled_chunks.append(
                    group.sample(
                        n=n,
                        random_state=RANDOM_STATE + total_rows + target,
                    )
                )

        print(f"Rows scanned so far: {total_rows:,}")

    if not sampled_chunks:
        raise SystemExit("No records were sampled.")

    sample = pd.concat(sampled_chunks, ignore_index=True)

    # Cap each binary class to keep the training sample manageable.
    balanced_parts = []

    for target in (0, 1):
        group = sample[sample["_target"] == target]

        if group.empty:
            raise SystemExit(
                f"No samples available for target class {target}"
            )

        n = min(len(group), MAX_PER_CLASS)

        balanced_parts.append(
            group.sample(n=n, random_state=RANDOM_STATE)
        )

    result = pd.concat(
        balanced_parts, ignore_index=True
    ).sample(frac=1, random_state=RANDOM_STATE)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT_PATH, index=False)

    print("\n" + "=" * 55)
    print(f"Rows scanned: {total_rows:,}")
    print(f"Sample saved: {OUTPUT_PATH}")
    print(f"Sample rows: {len(result):,}")
    print("\nBinary target counts (0=BENIGN, 1=ATTACK):")
    print(result["_target"].value_counts().sort_index())
    print("\nOriginal attack-label distribution:")
    print(result["Label"].value_counts().head(20))
    print("\nAudit:")
    print("Source CSV files were not modified.")
    print("Infinite values in sampled features were replaced by NaN.")
    print("Missing values will be handled during model training.")


if __name__ == "__main__":
    main()
