from pathlib import Path

import joblib
import pandas as pd

from url_ml_features import extract_features


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "backend"
    / "model"
    / "phishx_char_model.joblib"
)


bundle = joblib.load(MODEL_PATH)

model = bundle["model"]
vectorizer = bundle["vectorizer"]


test_urls = [
    "https://google.com",
    "https://example.com",
    "https://github.com",
    "https://www.microsoft.com",
    "http://paypal-login-secure-verification.com/account/verify",
]


for url in test_urls:

    vector = vectorizer.transform([url])

    probability = float(
        model.predict_proba(vector)[0][1]
    )

    if probability >= 0.70:
        verdict = "PHISHING"
    elif probability >= 0.40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    print("\n" + "-" * 70)
    print("URL:", url)
    print(f"Phishing probability: {probability * 100:.2f}%")
    print("Verdict:", verdict)