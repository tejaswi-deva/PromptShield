
import pandas as pd
from pathlib import Path

# Import your existing detector and simulated assistant.
from detector import scan_document, classify_label
from assistant import simulate_assistant


DATASET_PATH = Path(__file__).parent / "test_cases.csv"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def run_evaluation():
    """Run the security evaluation against every dataset case."""

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    dataset = pd.read_csv(DATASET_PATH)

    required_columns = {
        "test_id",
        "category",
        "document",
        "expected_label",
    }

    missing = required_columns - set(dataset.columns)

    if missing:
        raise ValueError(
            f"Dataset is missing columns: {sorted(missing)}"
        )

    results = []

    for _, case in dataset.iterrows():
        test_id = case["test_id"]
        category = case["category"]
        document = str(case["document"])
        expected_label = str(case["expected_label"]).upper()

        # Run the detector.
        detection = scan_document(document)

        predicted_label = classify_label(detection["risk_score"])

        # Simulate assistant behavior without and with mitigation.
        baseline = simulate_assistant(
            document,
            mitigation_enabled=False,
        )

        protected = simulate_assistant(
            document,
            mitigation_enabled=True,
        )

        results.append({
            "test_id": test_id,
            "category": category,
            "expected_label": expected_label,
            "predicted_label": predicted_label,
            "risk_level": detection["risk_level"],
            "risk_score": detection["risk_score"],
            "matched_categories": ", ".join(
                detection["matched_categories"]
            ),
            "detector_correct": (
                predicted_label == expected_label
            ),
            "baseline_attack_success": (
                baseline["attack_succeeded"]
            ),
            "protected_attack_success": (
                protected["attack_succeeded"]
            ),
            "mitigation_blocked": (
                baseline["attack_succeeded"]
                and not protected["attack_succeeded"]
            ),
            "baseline_response": baseline["response"],
            "protected_response": protected["response"],
        })

    results_df = pd.DataFrame(results)

    output_path = RESULTS_DIR / "evaluation_results.csv"
    results_df.to_csv(output_path, index=False)

    # Evaluate detector classification.
    malicious = results_df[
        results_df["expected_label"] == "MALICIOUS"
    ]

    benign = results_df[
        results_df["expected_label"] == "BENIGN"
    ]

    true_positives = (
        malicious["predicted_label"] == "MALICIOUS"
    ).sum()

    false_negatives = (
        malicious["predicted_label"] == "BENIGN"
    ).sum()

    false_positives = (
        benign["predicted_label"] == "MALICIOUS"
    ).sum()

    true_negatives = (
        benign["predicted_label"] == "BENIGN"
    ).sum()

    detection_rate = (
        true_positives / len(malicious) * 100
        if len(malicious) else 0
    )

    false_positive_rate = (
        false_positives / len(benign) * 100
        if len(benign) else 0
    )

    baseline_successes = results_df[
        "baseline_attack_success"
    ].sum()

    protected_successes = results_df[
        "protected_attack_success"
    ].sum()

    mitigation_reduction = (
        (baseline_successes - protected_successes)
        / baseline_successes * 100
        if baseline_successes else 0
    )

    print("\nPROMPTSHIELD EVALUATION REPORT")
    print("=" * 40)
    print(f"Total test cases: {len(results_df)}")
    print(f"Malicious cases: {len(malicious)}")
    print(f"Benign cases: {len(benign)}")

    print("\nDetector results")
    print("-" * 40)
    print(f"True positives: {true_positives}")
    print(f"False negatives: {false_negatives}")
    print(f"False positives: {false_positives}")
    print(f"True negatives: {true_negatives}")
    print(f"Detection rate: {detection_rate:.2f}%")
    print(f"False-positive rate: {false_positive_rate:.2f}%")

    print("\nSimulated assistant results")
    print("-" * 40)
    print(f"Baseline attack successes: {baseline_successes}")
    print(f"Protected attack successes: {protected_successes}")
    print(f"Simulated reduction: {mitigation_reduction:.2f}%")

    print(f"\nDetailed results saved to:\n{output_path}")

    return results_df


if __name__ == "__main__":
    run_evaluation()

