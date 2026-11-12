
from pathlib import Path

import pandas as pd


DATASET_DIR = Path(
    r"D:\Projects\AI-CTIR\MachineLearningCSV\MachineLearningCVE"
)

CHUNK_SIZE = 50_000


def main():
    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        raise SystemExit(f"No CSV files found in {DATASET_DIR}")

    print(f"Found {len(csv_files)} CSV files")

    reference_columns = None

    for file_path in csv_files:
        print("\n" + "=" * 80)
        print(f"FILE: {file_path.name}")
        print(f"SIZE: {file_path.stat().st_size / (1024 ** 2):.2f} MB")

        row_count = 0
        label_counts = {}
        missing_counts = {}
        non_numeric_feature_counts = {}
        columns = None

        for chunk in pd.read_csv(
            file_path,
            encoding="utf-8-sig",
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):
            chunk.columns = chunk.columns.str.strip()
            columns = list(chunk.columns)
            row_count += len(chunk)

            if "Label" in chunk.columns:
                labels = chunk["Label"].astype("string").str.strip()
                counts = labels.value_counts(dropna=False)

                for label, count in counts.items():
                    key = "<MISSING>" if pd.isna(label) else str(label)
                    label_counts[key] = label_counts.get(key, 0) + int(count)

            missing = chunk.isna().sum()

            for column, count in missing.items():
                missing_counts[column] = (
                    missing_counts.get(column, 0) + int(count)
                )

            feature_columns = [
                column for column in chunk.columns
                if column != "Label"
            ]

            for column in feature_columns:
                converted = pd.to_numeric(chunk[column], errors="coerce")
                invalid_count = int(
                    (converted.isna() & chunk[column].notna()).sum()
                )

                if invalid_count:
                    non_numeric_feature_counts[column] = (
                        non_numeric_feature_counts.get(column, 0)
                        + invalid_count
                    )

        print(f"Rows: {row_count:,}")
        print(f"Columns: {len(columns or [])}")

        if columns is None:
            continue

        print("\nColumns:")
        print(columns)

        if reference_columns is None:
            reference_columns = set(columns)
        else:
            missing_columns = sorted(reference_columns - set(columns))
            extra_columns = sorted(set(columns) - reference_columns)

            print("\nColumn consistency:")
            print(f"Missing compared with first file: {missing_columns}")
            print(f"Extra compared with first file: {extra_columns}")

        print("\nFull-file label distribution:")
        for label, count in sorted(
            label_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"  {label}: {count:,}")

        print("\nColumns with missing values:")
        found_missing = False

        for column, count in missing_counts.items():
            if count:
                print(f"  {column}: {count:,}")
                found_missing = True

        if not found_missing:
            print("  None")

        print("\nColumns with non-numeric values:")
        if non_numeric_feature_counts:
            for column, count in non_numeric_feature_counts.items():
                print(f"  {column}: {count:,}")
        else:
            print("  None detected")

    print("\nInspection complete. Source CSV files were not modified.")


if __name__ == "__main__":
    main()
