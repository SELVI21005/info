import json
from pathlib import Path

import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from ember.features import PEFeatureExtractor


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EMBER_DIR = PROJECT_ROOT / "ember_dataset_2018_2" / "ember2018"

MODEL_PATH = Path(__file__).resolve().parent / "malware_rf_model.pkl"


# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------

BENIGN_LIMIT = 10000
MALWARE_LIMIT = 10000


# ---------------------------------------------------------
# EMBER FEATURE PROCESSING
# ---------------------------------------------------------

extractor = PEFeatureExtractor(feature_version=2)


def record_to_features(record):
    """
    Convert an EMBER JSON record into the same feature
    representation expected by the EMBER feature extractor.
    """

    raw_features = {
        "histogram": record.get("histogram", []),
        "byteentropy": record.get("byteentropy", []),
        "strings": record.get("strings", {}),
        "general": record.get("general", {}),
        "header": record.get("header", {}),
        "section": record.get("section", {}),
        "imports": record.get("imports", {}),
        "exports": record.get("exports", {}),
        "datadirectories": record.get("datadirectories", []),
    }

    vector = extractor.process_raw_features(raw_features)

    return np.asarray(vector, dtype=np.float32)


# ---------------------------------------------------------
# LOAD EMBER RECORDS
# ---------------------------------------------------------

def get_training_files():
    return sorted(EMBER_DIR.glob("train_features_*.jsonl"))


def load_balanced_dataset():
    benign = []
    malware = []

    print("Searching EMBER training files...")

    files = get_training_files()

    print(f"Training files found: {len(files)}")

    for file_path in files:

        print(f"Reading: {file_path.name}")

        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:

                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                label = record.get("label")

                if label == 0 and len(benign) < BENIGN_LIMIT:
                    benign.append(record)

                elif label == 1 and len(malware) < MALWARE_LIMIT:
                    malware.append(record)

                if (
                    len(benign) >= BENIGN_LIMIT
                    and len(malware) >= MALWARE_LIMIT
                ):
                    break

        if (
            len(benign) >= BENIGN_LIMIT
            and len(malware) >= MALWARE_LIMIT
        ):
            break

    print()
    print(f"Benign samples : {len(benign)}")
    print(f"Malware samples: {len(malware)}")

    return benign + malware


# ---------------------------------------------------------
# MAIN TRAINING
# ---------------------------------------------------------

def main():

    print("=" * 60)
    print("ThreatLens AI - EMBER Random Forest Training")
    print("=" * 60)

    records = load_balanced_dataset()

    if not records:
        print("ERROR: No training records found.")
        return

    print()
    print("Converting EMBER records to feature vectors...")

    X = []
    y = []

    for index, record in enumerate(records, start=1):

        try:
            features = record_to_features(record)

            X.append(features)
            y.append(int(record["label"]))

        except Exception as error:
            print(
                f"Skipping record {index} because of feature error: "
                f"{error}"
            )

        if index % 1000 == 0:
            print(f"Processed {index}/{len(records)} records")

    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int32)

    print()
    print("Dataset ready.")
    print("Samples :", X.shape[0])
    print("Features:", X.shape[1])
    print("Labels  :", np.unique(y))

    # -----------------------------------------------------
    # TRAIN / TEST SPLIT
    # -----------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print()
    print("Training samples:", len(X_train))
    print("Testing samples :", len(X_test))

    # -----------------------------------------------------
    # RANDOM FOREST
    # -----------------------------------------------------

    print()
    print("Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    print("Training completed.")

    # -----------------------------------------------------
    # EVALUATION
    # -----------------------------------------------------

    print()
    print("Evaluating model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )
    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )
    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    cm = confusion_matrix(y_test, predictions)

    tn, fp, fn, tp = cm.ravel()

    false_positive_rate = fp / (fp + tn)

    # -----------------------------------------------------
    # RESULTS
    # -----------------------------------------------------

    print()
    print("=" * 60)
    print("MODEL PERFORMANCE")
    print("=" * 60)

    print(f"Accuracy            : {accuracy * 100:.2f}%")
    print(f"Precision           : {precision * 100:.2f}%")
    print(f"Recall              : {recall * 100:.2f}%")
    print(f"F1 Score            : {f1 * 100:.2f}%")
    print(f"False Positive Rate : {false_positive_rate * 100:.2f}%")

    print()
    print("Confusion Matrix:")
    print()
    print("                 Predicted")
    print("                 Benign  Malware")
    print(f"Actual Benign    {tn:6d}  {fp:7d}")
    print(f"Actual Malware   {fn:6d}  {tp:7d}")

    # -----------------------------------------------------
    # SAVE MODEL
    # -----------------------------------------------------

    joblib.dump(model, MODEL_PATH)

    print()
    print("Model saved:")
    print(MODEL_PATH)

    print()
    print("Model size:", MODEL_PATH.stat().st_size, "bytes")

    print()
    print("=" * 60)
    print("TRAINING FINISHED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()