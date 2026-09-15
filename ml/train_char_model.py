from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)


BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "data" / "balanced_urls.csv"

MODEL_DIR = BASE_DIR.parent / "backend" / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "phishx_char_model.joblib"


# -----------------------------
# LOAD DATA
# -----------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

df = df[["url", "label"]].dropna()

df["url"] = df["url"].astype(str).str.strip()

df = df[df["url"] != ""]

df = df.drop_duplicates(subset=["url"])

print(f"Dataset size: {len(df):,}")


# -----------------------------
# LABELS
# -----------------------------

df["target"] = (
    df["label"]
    .map({
        "legitimate": 0,
        "phishing": 1
    })
)

X = df["url"]
y = df["target"].astype(int)


# -----------------------------
# TRAIN TEST SPLIT
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training samples: {len(X_train):,}")
print(f"Testing samples : {len(X_test):,}")


# -----------------------------
# TF-IDF CHARACTER FEATURES
# -----------------------------

print("\nBuilding character n-gram features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=2,
    max_features=300000,
    sublinear_tf=True
)

X_train_vec = vectorizer.fit_transform(X_train)

X_test_vec = vectorizer.transform(X_test)

print("Training matrix:", X_train_vec.shape)
print("Testing matrix :", X_test_vec.shape)


# -----------------------------
# LOGISTIC REGRESSION
# -----------------------------

print("\nTraining character model...")

model = LogisticRegression(
    C=4.0,
    max_iter=300,
    solver="liblinear",
    random_state=42
)

model.fit(
    X_train_vec,
    y_train
)


# -----------------------------
# EVALUATION
# -----------------------------

print("\nEvaluating...")

y_pred = model.predict(X_test_vec)

y_probability = model.predict_proba(X_test_vec)[:, 1]


accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

roc_auc = roc_auc_score(
    y_test,
    y_probability
)


print("\n" + "=" * 60)
print("PHISHX CHARACTER MODEL RESULTS")
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
            "Phishing"
        ]
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# -----------------------------
# SAVE MODEL
# -----------------------------

bundle = {
    "model": model,
    "vectorizer": vectorizer,
    "dataset_size": len(df)
}

joblib.dump(
    bundle,
    MODEL_PATH
)

print("\nModel saved to:")

print(MODEL_PATH)

print("\nTraining complete.")