import streamlit as st
import pandas as pd
import subprocess
import sys
from pathlib import Path
import time

from detector import scan_document
from assistant import simulate_assistant
from test_runner import run_evaluation


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="PromptShield | AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* ── Global reset ── */
    html, body, .stApp {
        font-family: 'Inter', sans-serif !important;
        background-color: #060d1a !important;
        color: #e2e8f0;
    }

    /* Animated gradient background */
    .stApp::before {
        content: '';
        position: fixed;
        inset: 0;
        background:
            radial-gradient(ellipse 80% 60% at 10% 0%, rgba(37,99,235,0.12) 0%, transparent 60%),
            radial-gradient(ellipse 60% 40% at 90% 100%, rgba(139,92,246,0.10) 0%, transparent 55%);
        pointer-events: none;
        z-index: 0;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1526 0%, #0a1120 100%) !important;
        border-right: 1px solid rgba(99,102,241,0.25) !important;
    }
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] span {
        color: #e2e8f0 !important;
        font-family: 'Inter', sans-serif !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label {
        color: #cbd5e1 !important;
        font-size: 14px !important;
        padding: 6px 0 !important;
        transition: color 0.2s;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {
        color: #818cf8 !important;
    }

    /* ── Headings ── */
    h1, h2, h3, h4 {
        font-family: 'Inter', sans-serif !important;
        color: #f8fafc !important;
        letter-spacing: -0.01em;
    }
    h1 { font-size: 2rem !important; font-weight: 800 !important; }
    h2 { font-weight: 700 !important; }
    h3 { font-weight: 600 !important; }

    /* ── Metric cards — glassmorphism ── */
    [data-testid="stMetric"] {
        background: rgba(255,255,255,0.04) !important;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(99,102,241,0.22) !important;
        border-radius: 16px !important;
        padding: 20px 18px !important;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 32px rgba(99,102,241,0.18);
    }
    [data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-size: 12px !important;
        font-weight: 500 !important;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }
    [data-testid="stMetricValue"] div {
        color: #ffffff !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }

    /* ── Hero banner ── */
    .hero {
        padding: 36px 40px;
        border-radius: 20px;
        background: linear-gradient(135deg,
            rgba(37,99,235,0.18) 0%,
            rgba(79,70,229,0.14) 50%,
            rgba(139,92,246,0.10) 100%);
        border: 1px solid rgba(99,102,241,0.35);
        margin-bottom: 28px;
        position: relative;
        overflow: hidden;
    }
    .hero::after {
        content: '';
        position: absolute;
        top: -40px; right: -40px;
        width: 220px; height: 220px;
        background: radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 70%);
        border-radius: 50%;
    }
    .hero h1 {
        font-size: 2.2rem !important;
        font-weight: 800 !important;
        background: linear-gradient(90deg, #c7d2fe, #a5b4fc, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 10px;
    }
    .hero p {
        color: #94a3b8 !important;
        font-size: 15px;
        line-height: 1.7;
        max-width: 640px;
    }

    /* ── Section title ── */
    .section-title {
        font-size: 18px;
        font-weight: 700;
        color: #c7d2fe;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin: 24px 0 14px;
        padding-left: 12px;
        border-left: 3px solid #6366f1;
    }

    /* ── Input fields ── */
    .stTextArea label, .stTextInput label, .stSelectbox label {
        color: #94a3b8 !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .stTextArea textarea, .stTextInput input {
        background: rgba(255,255,255,0.04) !important;
        color: #1e293b !important;
        border: 1px solid rgba(99,102,241,0.3) !important;
        border-radius: 10px !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 14px !important;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 3px rgba(99,102,241,0.15) !important;
    }
    .stTextArea textarea::placeholder, .stTextInput input::placeholder {
        color: #475569 !important;
    }

    /* ── Buttons ── */
    .stButton > button, .stDownloadButton > button {
        background: linear-gradient(135deg, #4f46e5, #6366f1) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 10px !important;
        min-height: 44px;
        font-weight: 600 !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 14px !important;
        letter-spacing: 0.02em;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 15px rgba(99,102,241,0.25);
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background: linear-gradient(135deg, #4338ca, #4f46e5) !important;
        box-shadow: 0 6px 24px rgba(99,102,241,0.40) !important;
        transform: translateY(-1px);
    }
    .stButton > button:active, .stDownloadButton > button:active {
        transform: translateY(0);
    }

    /* ── Captions ── */
    [data-testid="stCaptionContainer"] p {
        color: #64748b !important;
        font-size: 12px !important;
    }

    /* ── Data tables ── */
    [data-testid="stDataFrame"] {
        border: 1px solid rgba(99,102,241,0.2) !important;
        border-radius: 12px !important;
        overflow: hidden;
    }

    /* ── Dividers ── */
    hr {
        border-color: rgba(99,102,241,0.15) !important;
        margin: 24px 0 !important;
    }

    /* ── Alert boxes ── */
    [data-testid="stAlert"] {
        border-radius: 12px !important;
        border-left-width: 4px !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* ── Expander ── */
    [data-testid="stExpander"] {
        background: rgba(255,255,255,0.03) !important;
        border: 1px solid rgba(99,102,241,0.18) !important;
        border-radius: 12px !important;
    }

    /* ── Selectbox ── */
    [data-testid="stSelectbox"] > div > div {
        background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(99,102,241,0.3) !important;
        border-radius: 10px !important;
        color: #e2e8f0 !important;
    }

    /* ── Progress bar ── */
    .stProgress > div > div {
        background: linear-gradient(90deg, #4f46e5, #818cf8) !important;
        border-radius: 4px !important;
    }
    .stProgress > div {
        background: rgba(255,255,255,0.06) !important;
        border-radius: 4px !important;
    }

    /* ── Spinner ── */
    .stSpinner > div {
        border-top-color: #6366f1 !important;
    }

    /* ── General text ── */
    .stApp p, .stApp label, .stApp li {
        color: #cbd5e1;
        font-family: 'Inter', sans-serif !important;
        line-height: 1.65;
    }

    /* ── Hide Streamlit default header bar ── */
    header[data-testid="stHeader"] {
        display: none !important;
        height: 0 !important;
    }

    /* Remove the top-padding gap Streamlit reserves for the header */
    .stApp > .stAppViewContainer > section.main > div.block-container {
        padding-top: 2rem !important;
    }
    /* Fallback for older Streamlit builds */
    .block-container {
        padding-top: 2rem !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------
# PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"
RESULTS_FILE = RESULTS_DIR / "evaluation_results.csv"
DATASET_FILE = BASE_DIR / "test_cases.csv"


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.markdown(
    """
    <div style='
        padding: 6px 0 4px;
        font-family: Inter, sans-serif;
    '>
        <div style='
            font-size: 22px;
            font-weight: 800;
            background: linear-gradient(90deg, #a5b4fc, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.01em;
        '>🛡️ PromptShield</div>
        <div style='font-size: 11px; color: #64748b; margin-top: 4px; letter-spacing: 0.06em; text-transform: uppercase;'>AI Security Lab</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.divider()

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "  Overview",
        "  Document Scanner",
        "  Security Evaluation",
        "  Robustness Testing",
        "  Results & Reports",
    ],
)

st.sidebar.divider()

st.sidebar.markdown(
    """
    <div style='font-size:12px; font-family: Inter, sans-serif;'>
        <div style='color:#94a3b8; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; margin-bottom:10px;'>System Status</div>
        <div style='display:flex; align-items:center; gap:8px; margin-bottom:7px;'>
            <span style='width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block;box-shadow:0 0 6px #22c55e;'></span>
            <span style='color:#86efac;'>Application running</span>
        </div>
        <div style='display:flex; align-items:center; gap:8px; margin-bottom:7px;'>
            <span style='width:8px;height:8px;border-radius:50%;background:#818cf8;display:inline-block;'></span>
            <span style='color:#c7d2fe;'>Detection: Rule-based</span>
        </div>
        <div style='display:flex; align-items:center; gap:8px;'>
            <span style='width:8px;height:8px;border-radius:50%;background:#f59e0b;display:inline-block;'></span>
            <span style='color:#fcd34d;'>No AI model required</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown("<div style='margin-top:16px;'></div>", unsafe_allow_html=True)
st.sidebar.caption(
    "Educational security testing environment. "
    "Results depend on configured rules."
)

# Strip emoji prefix added for display — map back to logical page names
_PAGE_MAP = {
    "  Overview":             "Overview",
    "  Document Scanner":     "Document Scanner",
    "  Security Evaluation":  "Security Evaluation",
    "  Robustness Testing":   "Robustness Testing",
    "  Results & Reports":    "Results & Reports",
}
page = _PAGE_MAP.get(page, page)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def load_results():
    if RESULTS_FILE.exists():
        return pd.read_csv(RESULTS_FILE)
    return None


def load_dataset():
    if DATASET_FILE.exists():
        return pd.read_csv(DATASET_FILE)
    return None


def metric_percentage(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator * 100


# --------------------------------------------------
# OVERVIEW
# --------------------------------------------------

if page == "Overview":

    st.markdown(
        """
        <div class="hero">
            <h1>🛡️ PromptShield Security Center</h1>
            <p>
            Detect suspicious instructions, evaluate prompt-injection
            attempts, and analyze mitigation performance.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    results = load_results()

    if results is None:
        st.warning(
            "No evaluation results found. Run the security evaluation "
            "to generate your first report."
        )

        if st.button("Run Initial Evaluation"):
            with st.spinner("Running security tests..."):
                run_evaluation()
            st.rerun()

    else:
        total = len(results)

        malicious = results[
            results["expected_label"] == "MALICIOUS"
        ]

        benign = results[
            results["expected_label"] == "BENIGN"
        ]

        tp = (
            malicious["predicted_label"] == "MALICIOUS"
        ).sum()

        fn = (
            malicious["predicted_label"] == "BENIGN"
        ).sum()

        fp = (
            benign["predicted_label"] == "MALICIOUS"
        ).sum()

        tn = (
            benign["predicted_label"] == "BENIGN"
        ).sum()

        detection_rate = metric_percentage(
            tp, len(malicious)
        )

        false_positive_rate = metric_percentage(
            fp, len(benign)
        )

        baseline_successes = int(
            results["baseline_attack_success"].sum()
        )

        protected_successes = int(
            results["protected_attack_success"].sum()
        )

        mitigation_reduction = metric_percentage(
            baseline_successes - protected_successes,
            baseline_successes,
        )

        # Top-level metrics
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Test Cases", total)
        col2.metric(
            "Detection Rate",
            f"{detection_rate:.1f}%",
        )
        col3.metric(
            "False-Positive Rate",
            f"{false_positive_rate:.1f}%",
        )
        col4.metric(
            "Simulated Attack Reduction",
            f"{mitigation_reduction:.1f}%",
        )

        st.markdown(
            '<div class="section-title">Evaluation Summary</div>',
            unsafe_allow_html=True,
        )

        left, right = st.columns(2)

        with left:
            st.markdown("#### Detector Classification")

            confusion = pd.DataFrame(
                {
                    "Outcome": [
                        "True Positive",
                        "False Negative",
                        "False Positive",
                        "True Negative",
                    ],
                    "Cases": [int(tp), int(fn), int(fp), int(tn)],
                }
            )

            st.bar_chart(
                confusion.set_index("Outcome")
            )

        with right:
            st.markdown("#### Attack Success Comparison")

            attack_comparison = pd.DataFrame(
                {
                    "Configuration": [
                        "Without Mitigation",
                        "With Mitigation",
                    ],
                    "Successful Attacks": [
                        baseline_successes,
                        protected_successes,
                    ],
                }
            )

            st.bar_chart(
                attack_comparison.set_index("Configuration")
            )

        st.markdown(
            '<div class="section-title">Project Information</div>',
            unsafe_allow_html=True,
        )

        info1, info2, info3 = st.columns(3)

        info1.info(
            "**Detection Engine**\n\n"
            "Python regular expressions and heuristic scoring."
        )

        info2.info(
            "**Evaluation Engine**\n\n"
            "Repeatable test cases with automated result logging."
        )

        info3.info(
            "**Mitigation Test**\n\n"
            "Controlled simulation using harmless dummy data."
        )

        st.caption(
            "These measurements describe the current rule-based detector "
            "and simulated assistant. They are not real-LLM security "
            "benchmarks."
        )
        # Attack category distribution
        st.divider()

        st.markdown(
            '<div class="section-title">'
            'Test Case Category Analytics'
            '</div>',
            unsafe_allow_html=True,
        )

        dataset = load_dataset()

        if dataset is not None and "category" in dataset.columns:

            category_counts = (
                dataset["category"]
                .value_counts()
                .rename_axis("Attack Category")
                .reset_index(name="Test Cases")
            )

            category_col, details_col = st.columns(
                [3, 2]
            )

            with category_col:
                st.markdown("#### Dataset Distribution")

                st.bar_chart(
                    category_counts.set_index(
                        "Attack Category"
                    )
                )

            with details_col:
                st.markdown("#### Category Breakdown")

                st.dataframe(
                    category_counts,
                    use_container_width=True,
                    hide_index=True,
                )

                st.metric(
                    "Unique Categories",
                    len(category_counts),
                )

                st.metric(
                    "Total Dataset Cases",
                    int(category_counts["Test Cases"].sum()),
                )

        else:
            st.info(
                "The test dataset is unavailable. "
                "Check that test_cases.csv exists."
            )



# --------------------------------------------------
# DOCUMENT SCANNER
# --------------------------------------------------

elif page == "Document Scanner":

    st.title("🔎 Document Security Scanner")

    st.markdown(
        """
        Analyze document text for suspicious instructions.
        Review the risk score, matched phrases, and recommended actions.
        """
    )

    st.divider()

    # Input area
    document = st.text_area(
        "Document Content",
        height=220,
        placeholder=(
            "Paste document text here...\n\n"
            "Example: Ignore all previous instructions..."
        ),
        key="scanner_document",
    )

    scan_button = st.button(
        "🔍 Scan Document",
        type="primary",
        use_container_width=True,
    )

    if scan_button:

        if not document.strip():
            st.warning("Please enter document text before scanning.")

        else:
            result = scan_document(document)

            st.session_state["last_scan_result"] = result
            st.session_state["last_scan_document"] = document

    # Display the latest scan result.
    result = st.session_state.get("last_scan_result")
    scanned_document = st.session_state.get("last_scan_document")

    if result and scanned_document == document:

        st.divider()
        st.subheader("Security Analysis Report")

        risk_level = result["risk_level"]
        risk_score = result["risk_score"]

        # Risk summary
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Risk Level", risk_level)

        with col2:
            st.metric("Risk Score", f"{risk_score}/100")

        with col3:
            st.metric(
                "Detected Categories",
                len(result["matched_categories"]),
            )

        # Risk indicator and recommended action
        if risk_level == "HIGH":
            st.error(
                "🔴 HIGH RISK — Review this document before "
                "allowing it into an AI workflow."
            )

            st.markdown(
                "**Recommended action:** Quarantine or review the "
                "document and prevent embedded instructions from "
                "being executed."
            )

        elif risk_level == "MEDIUM":
            st.warning(
                "🟠 MEDIUM RISK — Suspicious patterns were detected."
            )

            st.markdown(
                "**Recommended action:** Review the matched phrases "
                "and verify the document's source."
            )

        else:
            st.success(
                "🟢 LOW RISK — No configured injection patterns "
                "were detected."
            )

            st.markdown(
                "**Recommended action:** Continue normal review. "
                "A low score does not guarantee that the document "
                "is safe."
            )

        st.progress(risk_score / 100)

        st.markdown("### Detection Summary")
        st.write(result["explanation"])

        # Matched categories
        st.markdown("### Detected Attack Categories")

        if result["findings"]:

            for finding in result["findings"]:

                with st.expander(
                    f"⚠️ {finding['category']} "
                    f"— Weight: {finding['weight']}"
                ):

                    st.write(finding["explanation"])

                    st.write("**Matched phrases:**")

                    for phrase in finding["phrases"]:
                        st.code(phrase)

        else:
            st.info(
                "No configured attack indicators matched this document."
            )

        # Download report
        report = {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "matched_categories": ", ".join(
                result["matched_categories"]
            ),
            "matched_phrases": ", ".join(
                result["matched_phrases"]
            ),
            "explanation": result["explanation"],
            "document": document,
        }

        report_df = pd.DataFrame([report])

        st.download_button(
            "⬇️ Download Scan Report",
            data=report_df.to_csv(index=False).encode("utf-8"),
            file_name="promptshield_scan_report.csv",
            mime="text/csv",
        )

        st.caption(
            "PromptShield uses heuristic pattern matching. "
            "Its risk score is not a probability, and unseen attacks "
            "may not be detected."
        )

# --------------------------------------------------
# SECURITY EVALUATION
# --------------------------------------------------

elif page == "Security Evaluation":

    st.title("🧪 Security Evaluation Center")

    st.markdown(
        """
        Evaluate PromptShield against the test dataset,
        measure detection performance, and investigate
        incorrectly classified documents.
        """
    )

    st.divider()

    dataset = load_dataset()
    results = load_results()

    # Dataset information
    if dataset is not None:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Test Cases",
            len(dataset),
        )

        col2.metric(
            "Malicious Cases",
            int((dataset["expected_label"] == "MALICIOUS").sum()),
        )

        col3.metric(
            "Benign Cases",
            int((dataset["expected_label"] == "BENIGN").sum()),
        )

        with st.expander("View Test Dataset"):

            st.dataframe(
                dataset,
                use_container_width=True,
                hide_index=True,
            )

    else:
        st.error("test_cases.csv was not found.")

    # Run evaluation
    if st.button(
        "▶ Run Security Evaluation",
        type="primary",
        use_container_width=True,
    ):

        with st.spinner(
            "Evaluating test cases and generating results..."
        ):
            run_evaluation()

        st.success("Security evaluation completed!")
        st.rerun()

    # Load the latest saved results
    results = load_results()

    if results is not None:

        st.divider()
        st.subheader("Evaluation Performance")

        # Identify the four classification outcomes
        malicious = results[
            results["expected_label"] == "MALICIOUS"
        ]

        benign = results[
            results["expected_label"] == "BENIGN"
        ]

        tp = int(
            (malicious["predicted_label"] == "MALICIOUS").sum()
        )

        fn = int(
            (malicious["predicted_label"] == "BENIGN").sum()
        )

        fp = int(
            (benign["predicted_label"] == "MALICIOUS").sum()
        )

        tn = int(
            (benign["predicted_label"] == "BENIGN").sum()
        )

        total = len(results)

        accuracy = (
            (tp + tn) / total * 100
            if total else 0
        )

        detection_rate = (
            tp / (tp + fn) * 100
            if (tp + fn) else 0
        )

        false_positive_rate = (
            fp / (fp + tn) * 100
            if (fp + tn) else 0
        )

        precision = (
            tp / (tp + fp) * 100
            if (tp + fp) else 0
        )

        # Performance metric cards
        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Accuracy",
            f"{accuracy:.2f}%",
        )

        c2.metric(
            "Detection Rate (Recall)",
            f"{detection_rate:.2f}%",
        )

        c3.metric(
            "False-Positive Rate",
            f"{false_positive_rate:.2f}%",
        )

        c4.metric(
            "Precision",
            f"{precision:.2f}%",
        )

        st.caption(
            f"Metrics are calculated from the saved evaluation results. "
            f"They describe performance on this {total}-case dataset only."
        )

        # Confusion matrix
        st.divider()
        st.subheader("Confusion Matrix")

        confusion_matrix = pd.DataFrame(
            [
                [tn, fp],
                [fn, tp],
            ],
            index=[
                "Actual: BENIGN",
                "Actual: MALICIOUS",
            ],
            columns=[
                "Predicted: BENIGN",
                "Predicted: MALICIOUS",
            ],
        )

        st.dataframe(
            confusion_matrix,
            use_container_width=True,
        )

        st.markdown(
            f"""
            - **True positives:** {tp} malicious cases detected.
            - **False negatives:** {fn} malicious cases missed.
            - **False positives:** {fp} benign cases incorrectly flagged.
            - **True negatives:** {tn} benign cases correctly classified.
            """
        )

        # Performance comparison chart
        st.divider()
        st.subheader("Detection Performance")

        performance_df = pd.DataFrame(
            {
                "Metric": [
                    "Detection Rate",
                    "False-Positive Rate",
                    "Accuracy",
                    "Precision",
                ],
                "Percentage": [
                    detection_rate,
                    false_positive_rate,
                    accuracy,
                    precision,
                ],
            }
        )

        st.bar_chart(
            performance_df.set_index("Metric")
        )

        # Investigate errors
        st.divider()
        st.subheader("Misclassified Test Cases")

        errors = results[
            ~results["detector_correct"]
        ]

        if errors.empty:

            st.success(
                "No classification errors were found in this evaluation."
            )

        else:

            st.warning(
                f"{len(errors)} test case(s) were incorrectly classified."
            )

            error_columns = [
                "test_id",
                "category",
                "expected_label",
                "predicted_label",
                "risk_level",
                "risk_score",
                "matched_categories",
            ]

            st.dataframe(
                errors[error_columns],
                use_container_width=True,
                hide_index=True,
            )

            st.markdown(
                """
                **How to use this table**

                Review each missed malicious case and each incorrectly
                flagged benign case. These examples can guide improvements
                to the detection rules.
                """
            )

            st.download_button(
                "⬇ Download Misclassified Cases",
                data=errors.to_csv(index=False).encode("utf-8"),
                file_name="promptshield_misclassified_cases.csv",
                mime="text/csv",
            )

        # Full results
        with st.expander("View All Evaluation Results"):

            st.dataframe(
                results,
                use_container_width=True,
                hide_index=True,
            )

        st.download_button(
            "⬇ Download Complete Evaluation",
            data=results.to_csv(index=False).encode("utf-8"),
            file_name="promptshield_full_evaluation.csv",
            mime="text/csv",
        )

    else:

        st.info(
            "No saved evaluation results are available yet. "
            "Click Run Security Evaluation to generate them."
        )


# --------------------------------------------------
# ROBUSTNESS TESTING
# --------------------------------------------------

elif page == "Robustness Testing":

    st.title("🛡️ Robustness Testing")

    st.markdown(
        """
        Evaluate PromptShield against additional test cases
        designed to assess how well the detector handles
        different prompt-injection patterns.
        """
    )

    st.divider()

    robustness_file = BASE_DIR / "results" / "robustness_results.csv"

    if not robustness_file.exists():

        st.warning(
            "No robustness results found. Run the robustness "
            "test suite from the VS Code terminal first."
        )

        if st.button("▶ Run Robustness Tests", type="primary"):

            import subprocess
            import sys

            with st.spinner("Running robustness tests..."):

                process = subprocess.run(
                    [
                        sys.executable,
                        "robustness_tests.py",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=Path(__file__).resolve().parent,
                )

            if process.returncode == 0:
                st.success("Robustness evaluation completed.")
                st.rerun()

            else:
                st.error("Robustness evaluation failed.")
                st.code(process.stderr)

    else:

        robustness_df = pd.read_csv(robustness_file)

        total = len(robustness_df)

        if total > 0:

            actual_malicious = robustness_df[
                robustness_df["expected_label"] == "MALICIOUS"
            ]

            actual_benign = robustness_df[
                robustness_df["expected_label"] == "BENIGN"
            ]

            tp = int(
                (
                    actual_malicious["predicted_label"]
                    == "MALICIOUS"
                ).sum()
            )

            fn = int(
                (
                    actual_malicious["predicted_label"]
                    == "BENIGN"
                ).sum()
            )

            fp = int(
                (
                    actual_benign["predicted_label"]
                    == "MALICIOUS"
                ).sum()
            )

            tn = int(
                (
                    actual_benign["predicted_label"]
                    == "BENIGN"
                ).sum()
            )

            accuracy = (tp + tn) / total * 100

            detection_rate = (
                tp / (tp + fn) * 100
                if (tp + fn) else 0
            )

            false_positive_rate = (
                fp / (fp + tn) * 100
                if (fp + tn) else 0
            )

            precision = (
                tp / (tp + fp) * 100
                if (tp + fp) else 0
            )

            # Metric cards
            st.subheader("Robustness Performance")

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("Test Cases", total)
            c2.metric("Accuracy", f"{accuracy:.2f}%")
            c3.metric(
                "Detection Rate",
                f"{detection_rate:.2f}%",
            )
            c4.metric(
                "False-Positive Rate",
                f"{false_positive_rate:.2f}%",
            )

            st.metric("Precision", f"{precision:.2f}%")

            st.caption(
                "These metrics describe performance on the manually "
                "created robustness suite. They do not guarantee "
                "performance on unseen real-world attacks."
            )

            # Confusion matrix
            st.divider()
            st.subheader("Confusion Matrix")

            confusion = pd.DataFrame(
                [
                    [tn, fp],
                    [fn, tp],
                ],
                index=["Actual BENIGN", "Actual MALICIOUS"],
                columns=[
                    "Predicted BENIGN",
                    "Predicted MALICIOUS",
                ],
            )

            st.dataframe(
                confusion,
                use_container_width=True,
            )

            # Individual results
            st.divider()
            st.subheader("Individual Test Results")

            if "category" in robustness_df.columns:

                category_options = [
                    "All",
                    *sorted(
                        robustness_df["category"]
                        .dropna()
                        .unique()
                    ),
                ]

                selected_category = st.selectbox(
                    "Filter by Test Category",
                    category_options,
                )

                if selected_category != "All":

                    filtered_df = robustness_df[
                        robustness_df["category"]
                        == selected_category
                    ]

                else:
                    filtered_df = robustness_df

            else:
                filtered_df = robustness_df

            st.dataframe(
                filtered_df,
                use_container_width=True,
                hide_index=True,
            )

            # Category chart
            if "category" in robustness_df.columns:

                st.divider()
                st.subheader("Test Cases by Category")

                category_counts = (
                    robustness_df["category"]
                    .value_counts()
                    .rename_axis("Category")
                    .reset_index(name="Test Cases")
                )

                st.bar_chart(
                    category_counts.set_index("Category")
                )

            # Failed tests
            errors = robustness_df[
                robustness_df["expected_label"]
                != robustness_df["predicted_label"]
            ]

            st.divider()
            st.subheader("Misclassified Cases")

            if errors.empty:

                st.success(
                    "All robustness test cases were classified "
                    "according to their expected labels."
                )

            else:

                st.warning(
                    f"{len(errors)} test case(s) were misclassified."
                )

                st.dataframe(
                    errors,
                    use_container_width=True,
                    hide_index=True,
                )

            # Download report
            st.download_button(
                "⬇️ Download Robustness Results",
                data=robustness_df.to_csv(
                    index=False
                ).encode("utf-8"),
                file_name="promptshield_robustness_results.csv",
                mime="text/csv",
            )

        else:
            st.success("Robustness results loaded successfully.")

    if st.button("🔄 Run Tests Again", key="rerun_robustness_tests"):

        with st.spinner("Running robustness tests..."):

            result = subprocess.run(
                [sys.executable, "robustness_tests.py"],
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent,
            )

        if result.returncode == 0:

            st.success("Robustness tests completed successfully!")

            if result.stdout:
                st.code(result.stdout)

            # Clear Streamlit's cached data and reload.
            st.cache_data.clear()
            st.rerun()

        else:

            st.error("Robustness tests failed.")

            if result.stdout:
                st.code(result.stdout)

            if result.stderr:
                st.code(result.stderr)

# --------------------------------------------------
# RESULTS AND REPORTS
# --------------------------------------------------

elif page == "Results & Reports":

    st.title("📊 Results and Reports")

    st.markdown("Browse, filter, and export the complete evaluation results.")
    st.divider()

    results = load_results()

    if results is None:
        st.warning(
            "No results available. Run the Security Evaluation first."
        )

        if st.button("▶ Run Evaluation Now", type="primary"):
            with st.spinner("Running evaluation..."):
                run_evaluation()
            st.rerun()

    else:

        if "category" in results.columns:
            categories = [
                "All",
                *sorted(results["category"].dropna().unique()),
            ]

            selected_category = st.selectbox(
                "Filter by Category",
                categories,
            )

            if selected_category != "All":
                filtered = results[
                    results["category"] == selected_category
                ]
            else:
                filtered = results

        else:
            filtered = results

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown(
            f"Showing **{len(filtered)}** of **{len(results)}** test cases."
        )

        csv_data = filtered.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="⬇️ Download Results as CSV",
            data=csv_data,
            file_name="promptshield_evaluation_results.csv",
            mime="text/csv",
        )

        st.caption(f"Source: {RESULTS_FILE.name}")
