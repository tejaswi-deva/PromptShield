
import pandas as pd
from pathlib import Path

dataset_path = Path(__file__).resolve().parent / "test_cases.csv"

if not dataset_path.exists():
    print("ERROR: test_cases.csv was not found.")
    raise SystemExit(1)

df = pd.read_csv(dataset_path)

required_columns = {
    "test_id",
    "category",
    "document",
    "expected_label",
}

missing_columns = required_columns - set(df.columns)

if missing_columns:
    print("ERROR: Missing columns:", missing_columns)
    raise SystemExit(1)

if df.isnull().any().any():
    print("ERROR: The dataset contains empty values.")
    raise SystemExit(1)

if df["test_id"].duplicated().any():
    print("ERROR: Duplicate test IDs found.")
    raise SystemExit(1)

valid_labels = {"MALICIOUS", "BENIGN"}

if not set(df["expected_label"]).issubset(valid_labels):
    print("ERROR: Unexpected labels found.")
    raise SystemExit(1)

print("PROMPTSHIELD DATASET VALIDATION")
print("-" * 35)
print("Dataset:", dataset_path.name)
print("Total test cases:", len(df))
print("\nCases by expected label:")
print(df["expected_label"].value_counts())
print("\nCases by category:")
print(df["category"].value_counts())
print("\nDataset validation successful!")
