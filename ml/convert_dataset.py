from pathlib import Path
import pandas as pd
from scipy.io import arff


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

INPUT_FILE = DATA_DIR / "Training Dataset.arff"
OUTPUT_FILE = DATA_DIR / "phishing.csv"


def main():
    print("Loading ARFF dataset...")

    data, meta = arff.loadarff(INPUT_FILE)

    df = pd.DataFrame(data)

    # Convert byte/string values into normal strings
    for column in df.columns:
        if df[column].dtype == object:
            df[column] = df[column].apply(
                lambda x: x.decode("utf-8") if isinstance(x, bytes) else x
            )

    print("\nDataset loaded successfully!")
    print("Rows:", len(df))
    print("Columns:", len(df.columns))

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nFirst 5 rows:")
    print(df.head())

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nCSV saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()