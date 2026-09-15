import pandas as pd
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parent / "data" / "balanced_urls.csv"

df = pd.read_csv(DATASET_PATH)

print("\nDataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate URLs:")
print(df["url"].duplicated().sum())