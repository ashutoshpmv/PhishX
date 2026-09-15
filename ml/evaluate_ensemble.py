from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from url_ml_features import extract_features, FEATURE_NAMES


BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "data" / "balanced_urls.csv"

MODEL_DIR = BASE_DIR.parent / "backend" / "model"

XGB_PATH = MODEL_DIR / "phishx_xgboost_url_v1.joblib"
CHAR_PATH = MODEL_DIR / "phishx_char_model.joblib"


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

df = df[["url", "label"]].dropna()

df["url"] = df["url"].astype(str).str.strip()

df = df[df["url"] != ""]

df = df.drop_duplicates(subset=["url"])

df["target"] = df["label"].map({
    "legitimate": 0,
    "phishing": 1
})

X_urls = df["url"]
y = df["target"].astype(int)


# SAME SPLIT AS TRAINING
_, X_test, _, y_test = train_test_split(
    X_urls,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# --------------------------------------------------
# LOAD MODELS
# --------------------------------------------------

print("\nLoading models...")

xgb_bundle = joblib.load(XGB_PATH)
char_bundle = joblib.load(CHAR_PATH)

xgb_model = xgb_bundle["model"]
char_model = char_bundle["model"]
vectorizer = char_bundle["vectorizer"]


# --------------------------------------------------
# XGBOOST FEATURES
# --------------------------------------------------

print("\nExtracting XGBoost features...")

feature_rows = [
    extract_features(url)
    for url in X_test
]

X_test_features = pd.DataFrame(
    feature_rows,
    columns=FEATURE_NAMES
)


# --------------------------------------------------
# MODEL PROBABILITIES
# --------------------------------------------------

print("\nCalculating probabilities...")

xgb_prob = xgb_model.predict_proba(
    X_test_features
)[:, 1]


char_vectors = vectorizer.transform(X_test)

char_prob = char_model.predict_proba(
    char_vectors
)[:, 1]


# --------------------------------------------------
# ENSEMBLE
# --------------------------------------------------

ensemble_prob = (
    0.80 * char_prob
    + 0.20 * xgb_prob
)


# --------------------------------------------------
# TEST MULTIPLE THRESHOLDS
# --------------------------------------------------

print("\n" + "=" * 60)
print("PHISHX ENSEMBLE RESULTS")
print("=" * 60)


for threshold in [0.40, 0.45, 0.50, 0.55, 0.60]:

    predictions = (
        ensemble_prob >= threshold
    ).astype(int)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions
    )

    recall = recall_score(
        y_test,
        predictions
    )

    f1 = f1_score(
        y_test,
        predictions
    )

    print(
        f"\nThreshold: {threshold:.2f}"
    )

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1       : {f1:.4f}"
    )


# --------------------------------------------------
# ROC-AUC
# --------------------------------------------------

auc = roc_auc_score(
    y_test,
    ensemble_prob
)

print(
    f"\nROC-AUC: {auc:.4f}"
)


# --------------------------------------------------
# BEST THRESHOLD CONFUSION MATRIX
# --------------------------------------------------

best_threshold = 0.50

best_predictions = (
    ensemble_prob >= best_threshold
).astype(int)

print(
    "\nConfusion Matrix (threshold 0.50):"
)

print(
    confusion_matrix(
        y_test,
        best_predictions
    )
)

print("\nEvaluation complete.")