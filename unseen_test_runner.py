import pandas as pd
from pathlib import Path
from detector import scan_document, classify_label

# --------------------------------------------------

# CONFIGURATION

# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATASET_FILE = BASE_DIR / "unseen_test_cases.csv"
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_FILE = RESULTS_DIR / "unseen_evaluation_results.csv"

# The decision boundary is defined in detector.py (classify_label).
# MALICIOUS_THRESHOLD is imported implicitly via classify_label().

# --------------------------------------------------

# EVALUATION

# --------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("PROMPTSHIELD - UNSEEN TEST EVALUATION")
    print("=" * 60)

    if not DATASET_FILE.exists():
        print(f"ERROR: Dataset not found: {DATASET_FILE}")
        return

    dataset = pd.read_csv(DATASET_FILE)

    required_columns = {
        "test_id",
        "category",
        "expected_label",
        "text",
    }

    missing_columns = required_columns - set(dataset.columns)

    if missing_columns:
        print("ERROR: Missing columns:", sorted(missing_columns))
        return

    dataset["expected_label"] = (
        dataset["expected_label"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    invalid_labels = set(dataset["expected_label"]) - {
        "MALICIOUS",
        "BENIGN",
    }

    if invalid_labels:
        print("ERROR: Invalid expected labels:", invalid_labels)
        return

    records = []

    for _, row in dataset.iterrows():

        text = str(row["text"])
        detection = scan_document(text)

        risk_score = int(detection["risk_score"])

        predicted_label = classify_label(risk_score)

        records.append({
            "test_id": row["test_id"],
            "category": row["category"],
            "expected_label": row["expected_label"],
            "predicted_label": predicted_label,
            "risk_level": detection["risk_level"],
            "risk_score": risk_score,
            "matched_categories": ", ".join(
                detection["matched_categories"]
            ),
            "correct": predicted_label == row["expected_label"],
            "text": text,
        })

    results = pd.DataFrame(records)

    # --------------------------------------------------
    # METRICS
    # --------------------------------------------------

    actual = results["expected_label"]
    predicted = results["predicted_label"]

    tp = int(((actual == "MALICIOUS") & (predicted == "MALICIOUS")).sum())
    fn = int(((actual == "MALICIOUS") & (predicted == "BENIGN")).sum())
    tn = int(((actual == "BENIGN") & (predicted == "BENIGN")).sum())
    fp = int(((actual == "BENIGN") & (predicted == "MALICIOUS")).sum())

    total = len(results)

    accuracy = (tp + tn) / total * 100 if total else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0
    false_positive_rate = fp / (fp + tn) * 100 if (fp + tn) else 0

    # --------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------

    print(f"\nTotal test cases:       {total}")
    print(f"True positives (TP):    {tp}")
    print(f"False negatives (FN):   {fn}")
    print(f"True negatives (TN):    {tn}")
    print(f"False positives (FP):   {fp}")

    print("\nPerformance Metrics")
    print("-" * 40)
    print(f"Accuracy:               {accuracy:.2f}%")
    print(f"Precision:              {precision:.2f}%")
    print(f"Recall / Detection:     {recall:.2f}%")
    print(f"False-positive rate:    {false_positive_rate:.2f}%")

    print("\nIndividual Test Results")
    print("-" * 60)

    print(
        results[
            [
                "test_id",
                "expected_label",
                "predicted_label",
                "risk_level",
                "risk_score",
                "correct",
            ]
        ].to_string(index=False)
    )

    # --------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results.to_csv(OUTPUT_FILE, index=False)

    print("\nResults saved to:")
    print(OUTPUT_FILE)

    errors = results[~results["correct"]]

    if errors.empty:
        print("\nAll test cases matched their expected labels.")
    else:
        print(f"\nMisclassified test cases: {len(errors)}")
        print(errors[["test_id", "expected_label", "predicted_label"]].to_string(index=False))

    print("\nNote: This is a small, manually created evaluation set.")
    print("Its results do not establish real-world security effectiveness.")
    print("=" * 60)

if __name__ == "__main__":
    main()
