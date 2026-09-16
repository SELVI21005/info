import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EMBER_DIR = PROJECT_ROOT / "ember_dataset_2018_2" / "ember2018"


def get_training_files():
    """Return all EMBER training JSONL files."""
    return sorted(EMBER_DIR.glob("train_features_*.jsonl"))


def read_records(file_path, limit=None):
    """
    Read EMBER records one line at a time.

    limit:
        Maximum number of records to read.
        None = read the complete file.
    """
    count = 0

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            yield record

            count += 1

            if limit is not None and count >= limit:
                break


def load_sample(limit=5):
    """Load a small sample for checking the dataset."""
    records = []

    for file_path in get_training_files():
        for record in read_records(file_path, limit=limit):
            records.append(record)

            if len(records) >= limit:
                return records

    return records


if __name__ == "__main__":
    print("EMBER directory:")
    print(EMBER_DIR)

    print("\nEMBER directory exists:", EMBER_DIR.exists())

    files = get_training_files()

    print("\nTraining files found:", len(files))

    for file_path in files:
        print("-", file_path.name)

    print("\nLoading a small sample...")

    samples = load_sample(3)

    for index, record in enumerate(samples, start=1):
        print(
            f"Sample {index}: "
            f"sha256={record.get('sha256')}, "
            f"label={record.get('label')}"
        )

    print("\nSample loading completed.")