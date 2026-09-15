from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier


BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "phishing.csv"
MODEL_DIR = BASE_DIR.parent / "backend" / "model"
MODEL_FILE = MODEL_DIR / "phishx_xgboost.joblib"


def main():

    print("Loading dataset...")

    df = pd.read_csv(DATA_FILE)

    print(f"Dataset shape: {df.shape}")

    # Result is the target column
    TARGET = "Result"

    if TARGET not in df.columns:
        raise ValueError("Target column 'Result' not found.")

    # Convert all columns to numeric
    for column in df.columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df = df.dropna()

    # Separate features and target
    X = df.drop(columns=[TARGET])
    y = df[TARGET]

    # Dataset uses:
    # -1 = legitimate
    #  1 = phishing
    #
    # Convert to:
    # 0 = legitimate
    # 1 = phishing
    y = (y == 1).astype(int)

    print(f"Features: {X.shape[1]}")
    print(f"Samples: {X.shape[0]}")

    print("\nClass distribution:")
    print(y.value_counts())

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("\nTraining XGBoost model...")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    # Predictions
    probabilities = model.predict_proba(X_test)[:, 1]

    predictions = (probabilities >= 0.5).astype(int)

    # Metrics
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    auc = roc_auc_score(y_test, probabilities)

    print("\n" + "=" * 50)
    print("PHISHX XGBOOST MODEL RESULTS")
    print("=" * 50)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {auc:.4f}")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"]
    ))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # Feature importance
    importance = pd.DataFrame({
        "feature": X.columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        by="importance",
        ascending=False
    )

    print("\nTop 10 Important Features:")
    print(importance.head(10).to_string(index=False))

    # Save model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "features": list(X.columns),
        "dataset_features": list(X.columns),
        "target": TARGET,
        "label_mapping": {
            "0": "Legitimate",
            "1": "Phishing"
        },
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": auc,
        }
    }

    joblib.dump(bundle, MODEL_FILE)

    print("\nModel saved successfully:")
    print(MODEL_FILE)


if __name__ == "__main__":
    main()