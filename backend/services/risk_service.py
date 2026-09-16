def calculate_risk_score(static_score, ml_result):
    """
    Combines static-analysis risk and ML classification
    into a final risk score from 0 to 100.
    """

    static_score = float(static_score or 0)

    ml_classification = ml_result.get(
        "classification",
        "Unknown"
    )

    confidence = float(
        ml_result.get("confidence", 0) or 0
    )

    # When ML is not available, use the static score.
    if ml_classification == "Unknown":
        return round(
            max(0, min(100, static_score)),
            2
        )

    # Malware prediction increases risk.
    if ml_classification == "Malware":

        ml_contribution = confidence * 0.50

        final_score = (
            static_score * 0.50
            + ml_contribution
        )

    # Benign prediction reduces risk.
    elif ml_classification == "Benign":

        ml_contribution = confidence * 0.30

        final_score = (
            static_score * 0.70
            - ml_contribution
        )

    else:
        final_score = static_score

    return round(
        max(0, min(100, final_score)),
        2
    )


def get_risk_level(score):
    """
    Converts numerical risk score into
    a human-readable risk level.
    """

    score = float(score)

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"


def should_create_alert(score):
    """
    Generates an alert for high-risk detections.
    """

    return float(score) >= 70


def get_risk_explanation(
    static_score,
    ml_result,
    final_score
):
    """
    Provides an explanation for the final
    risk decision.
    """

    explanations = []

    if static_score >= 70:
        explanations.append(
            "Strong suspicious indicators detected "
            "during static analysis."
        )

    elif static_score >= 40:
        explanations.append(
            "Multiple suspicious indicators detected "
            "during static analysis."
        )

    elif static_score > 0:
        explanations.append(
            "Some suspicious indicators were detected."
        )

    ml_classification = ml_result.get(
        "classification",
        "Unknown"
    )

    confidence = ml_result.get(
        "confidence",
        0
    )

    if ml_classification == "Malware":

        explanations.append(
            f"Machine learning classified the file "
            f"as malware with {confidence}% confidence."
        )

    elif ml_classification == "Benign":

        explanations.append(
            f"Machine learning classified the file "
            f"as benign with {confidence}% confidence."
        )

    else:

        explanations.append(
            "Machine learning prediction is not "
            "available yet."
        )

    if final_score >= 70:

        explanations.append(
            "High-risk alert generated."
        )

    elif final_score >= 40:

        explanations.append(
            "File requires further investigation."
        )

    else:

        explanations.append(
            "No high-risk alert required."
        )

    return explanations