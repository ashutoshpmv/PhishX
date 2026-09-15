from pathlib import Path

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "model"

XGB_MODEL_PATH = MODEL_DIR / "phishx_xgboost_url_v1.joblib"
CHAR_MODEL_PATH = MODEL_DIR / "phishx_char_model.joblib"


class ModelNotReadyError(RuntimeError):
    pass


def predict_ml(features: dict, url: str):
    """
    Hybrid ML prediction:
    - Character model: 80%
    - XGBoost URL model: 20%
    """

    if not CHAR_MODEL_PATH.exists():
        raise ModelNotReadyError(
            "Character model not found."
        )

    if not XGB_MODEL_PATH.exists():
        raise ModelNotReadyError(
            "XGBoost URL model not found."
        )

    # -----------------------------
    # Character model
    # -----------------------------

    char_bundle = joblib.load(
        CHAR_MODEL_PATH
    )

    char_model = char_bundle["model"]
    vectorizer = char_bundle["vectorizer"]

    char_vector = vectorizer.transform(
        [url]
    )

    char_probability = float(
        char_model.predict_proba(
            char_vector
        )[0][1]
    )

    # -----------------------------
    # XGBoost model
    # -----------------------------

    xgb_bundle = joblib.load(
        XGB_MODEL_PATH
    )

    xgb_model = xgb_bundle["model"]
    xgb_features = xgb_bundle["features"]

    values = [
        features.get(feature, 0)
        for feature in xgb_features
    ]

    frame = pd.DataFrame(
        [values],
        columns=xgb_features
    )

    xgb_probability = float(
        xgb_model.predict_proba(
            frame
        )[0][1]
    )

    # -----------------------------
    # Ensemble
    # -----------------------------

    ml_probability = (
        0.80 * char_probability
        + 0.20 * xgb_probability
    )

    return {
        "phishing_probability": ml_probability,
        "character_probability": char_probability,
        "xgboost_probability": xgb_probability,
    }


def combine_scores(
    ml_phishing_probability: float,
    trust_score: float
):
    """
    Final PhishX hybrid score:

    ML       = 65%
    DNS/SSL  = 35%

    trust_score is between 0.0 and 1.0.
    """

    ml_risk = ml_phishing_probability

    # trust_score:
    # 1.0 = fully trusted
    # 0.0 = no trust
    dns_ssl_risk = 1.0 - trust_score

    final_risk = (
        0.65 * ml_risk
        + 0.35 * dns_ssl_risk
    )

    if final_risk >= 0.70:
        verdict = "PHISHING"

    elif final_risk >= 0.40:
        verdict = "SUSPICIOUS"

    else:
        verdict = "SAFE"

    return {
        "ml_score": round(
            ml_risk,
            4
        ),

        "dns_ssl_risk": round(
            dns_ssl_risk,
            4
        ),

        "final_risk": round(
            final_risk,
            4
        ),

        "verdict": verdict
    }