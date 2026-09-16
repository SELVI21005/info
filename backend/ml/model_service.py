from pathlib import Path

import joblib
import numpy as np

from ember.features import PEFeatureExtractor


# =========================================================
# MODEL PATH
# =========================================================

MODEL_PATH = Path(__file__).resolve().parent / "malware_rf_model.pkl"


# =========================================================
# EMBER FEATURE EXTRACTOR
# =========================================================

extractor = PEFeatureExtractor(feature_version=2)


# =========================================================
# MODEL FUNCTIONS
# =========================================================

def model_exists():
    """
    Check whether the trained Random Forest model exists.
    """
    return MODEL_PATH.exists()


def load_model():
    """
    Load the trained Random Forest model.
    """
    if not model_exists():
        return None

    return joblib.load(MODEL_PATH)


def predict(features):
    """
    Predict whether the extracted EMBER features
    represent a benign file or malware.
    """

    model = load_model()

    if model is None:
        return {
            "status": "model_not_available",
            "classification": "Unknown",
            "confidence": 0.0
        }

    # Convert features to NumPy float32
    features = np.asarray(
        features,
        dtype=np.float32
    )

    # Make prediction
    prediction = model.predict([features])[0]

    # Get probability for each class
    probabilities = model.predict_proba([features])[0]

    # Highest probability = confidence
    confidence = float(
        max(probabilities) * 100
    )

    # Convert prediction to classification
    classification = (
        "Malware"
        if int(prediction) == 1
        else "Benign"
    )

    return {
        "status": "success",
        "classification": classification,
        "confidence": round(confidence, 2)
    }


# =========================================================
# RAW FILE PREDICTION
# =========================================================

def predict_file(file_path):
    """
    Read a PE file as raw bytes, extract the real
    EMBER 2381-dimensional feature vector, and send
    it to the trained Random Forest model.
    """

    try:

        # -------------------------------------------------
        # STEP 1: Read the actual file bytes
        # -------------------------------------------------

        with open(file_path, "rb") as f:
            bytez = f.read()


        # -------------------------------------------------
        # STEP 2: Extract EMBER features
        # -------------------------------------------------

        features = extractor.feature_vector(bytez)


        # -------------------------------------------------
        # STEP 3: Convert to NumPy array
        # -------------------------------------------------

        features = np.asarray(
            features,
            dtype=np.float32
        )


        # -------------------------------------------------
        # STEP 4: Display feature count
        # -------------------------------------------------

        print(
            f"EMBER features extracted: {len(features)}"
        )


        # -------------------------------------------------
        # STEP 5: Verify feature dimension
        # -------------------------------------------------

        if len(features) != extractor.dim:

            return {
                "status": "feature_error",
                "classification": "Unknown",
                "confidence": 0.0,
                "error": (
                    f"Expected {extractor.dim} features, "
                    f"got {len(features)}"
                )
            }


        # -------------------------------------------------
        # STEP 6: Send features to Random Forest
        # -------------------------------------------------

        result = predict(features)


        # -------------------------------------------------
        # STEP 7: Add feature count to result
        # -------------------------------------------------

        result["feature_count"] = len(features)


        # -------------------------------------------------
        # STEP 8: Return result
        # -------------------------------------------------

        return result


    except Exception as error:

        return {
            "status": "prediction_error",
            "classification": "Unknown",
            "confidence": 0.0,
            "error": str(error)
        }