
from pathlib import Path

import numpy as np
import pandas as pd


DATASET_DIR = Path(
    r"D:\Projects\AI-CTIR\MachineLearningCSV\MachineLearningCVE"
)

CHUNK_SIZE = 50_000


def main():
    files = sorted(DATASET_DIR.glob("*.csv"))

    if not files:
        raise SystemExit(f"No CSV files found in {DATASET_DIR}")

    total_rows = 0
    total_infinite = 0
    infinite_by_column = {}

    for file_path in files:
        print(f"\nChecking: {file_path.name}")
        file_rows = 0
        file_infinite = 0

        for chunk in pd.read_csv(
            file_path,
            encoding="utf-8-sig",
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):
            chunk.columns = chunk.columns.str.strip()
            file_rows += len(chunk)

            numeric = chunk.select_dtypes(include=[np.number])

            if numeric.empty:
                continue

            counts = np.isinf(numeric.to_numpy()).sum(axis=0)

            for column, count in zip(numeric.columns, counts):
                count = int(count)

                if count:
                    infinite_by_column[column] = (
                        infinite_by_column.get(column, 0) + count
                    )
                    file_infinite += count

        total_rows += file_rows
        total_infinite += file_infinite

        print(f"Rows checked: {file_rows:,}")
        print(f"Infinite numeric values: {file_infinite:,}")

    print("\n" + "=" * 60)
    print(f"Total rows checked: {total_rows:,}")
    print(f"Total infinite numeric values: {total_infinite:,}")
    print("\nColumns containing infinite values:")

    if infinite_by_column:
        for column, count in sorted(
            infinite_by_column.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"  {column}: {count:,}")
    else:
        print("  None found")

    print("\nAudit complete. Source files were not modified.")


if __name__ == "__main__":
    main()
