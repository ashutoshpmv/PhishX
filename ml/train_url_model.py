import sys
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
    classification_report,
    confusion_matrix,
)

from xgboost import XGBClassifier

from url_ml_features import extract_features, FEATURE_NAMES


# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "data" / "balanced_urls.csv"

MODEL_DIR = BASE_DIR.parent / "backend" / "model"

MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "phishx_xgboost_url.joblib"


# --------------------------------------------------
# LOAD DATASET
# --------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Original dataset size: {len(df):,}")

print("\nOriginal class distribution:")
print(df["label"].value_counts())


# --------------------------------------------------
# CLEAN DATA
# --------------------------------------------------

df = df[["url", "label"]].dropna()

df["url"] = df["url"].astype(str).str.strip()

df = df[df["url"] != ""]

before_duplicates = len(df)

df = df.drop_duplicates(subset=["url"])

duplicates_removed = before_duplicates - len(df)

print(f"\nDuplicates removed: {duplicates_removed}")

print(f"Final dataset size: {len(df):,}")


# --------------------------------------------------
# LABEL ENCODING
# --------------------------------------------------

label_map = {
    "legitimate": 0,
    "phishing": 1,
}

df["target"] = df["label"].map(label_map)

if df["target"].isna().any():
    print("\nUnexpected labels found:")
    print(df.loc[df["target"].isna(), "label"].value_counts())
    sys.exit(1)


# --------------------------------------------------
# FEATURE EXTRACTION
# --------------------------------------------------

print("\nExtracting URL features...")

feature_rows = []

total = len(df)

for index, url in enumerate(df["url"]):

    feature_rows.append(
        extract_features(url)
    )

    if (index + 1) % 25000 == 0:
        print(
            f"Processed {index + 1:,} / {total:,} URLs"
        )


X = pd.DataFrame(
    feature_rows,
    columns=FEATURE_NAMES
)

y = df["target"].astype(int)


print("\nFeature matrix:")
print(X.shape)

print("\nFeatures:")
print(FEATURE_NAMES)


# --------------------------------------------------
# TRAIN / TEST SPLIT
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# --------------------------------------------------
# XGBOOST MODEL
# --------------------------------------------------

print("\nTraining XGBoost model...")

model = XGBClassifier(
    n_estimators=400,
    max_depth=8,
    learning_rate=0.08,
    subsample=0.90,
    colsample_bytree=0.90,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    n_jobs=-1,
    random_state=42,
)


model.fit(
    X_train,
    y_train,
)


# --------------------------------------------------
# PREDICTIONS
# --------------------------------------------------

print("\nEvaluating model...")

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]


# --------------------------------------------------
# METRICS
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
)

recall = recall_score(
    y_test,
    y_pred,
)

f1 = f1_score(
    y_test,
    y_pred,
)

roc_auc = roc_auc_score(
    y_test,
    y_probability,
)


print("\n" + "=" * 60)
print("PHISHX URL XGBOOST RESULTS")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Phishing",
        ],
    )
)


print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        y_pred,
    )
)


# --------------------------------------------------
# FEATURE IMPORTANCE
# --------------------------------------------------

importance = pd.Series(
    model.feature_importances_,
    index=FEATURE_NAMES,
).sort_values(
    ascending=False
)


print("\nTop Feature Importance:")
print(importance.head(15))


# --------------------------------------------------
# SAVE MODEL
# --------------------------------------------------

bundle = {
    "model": model,
    "features": FEATURE_NAMES,
    "label_map": label_map,
    "dataset_size": len(df),
    "duplicates_removed": duplicates_removed,
}

joblib.dump(
    bundle,
    MODEL_PATH,
)

print("\nModel saved to:")

print(MODEL_PATH)

print("\nTraining complete.")