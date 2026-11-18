import os

import requests
import streamlit as st
from dotenv import load_dotenv

from codesentinel.report_generator import html_report, json_report
from codesentinel.models import AnalysisReport


load_dotenv()
st.set_page_config(page_title="CodeSentinel", page_icon="CS", layout="wide")

st.markdown(
    """
    <style>
    :root {
      --ink: #172c2b;
      --muted: #647a76;
      --paper: #f2f5f1;
      --panel: #ffffff;
      --line: #d9e2dd;
      --teal: #087f72;
      --lime: #d9f36a;
      --amber: #d68725;
    }
    .stApp { background: var(--paper); color: var(--ink); }
    [data-testid="stHeader"] { background: transparent; }
    .block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 4rem; }
    h1, h2, h3 { color: var(--ink); letter-spacing: 0; }
    h1 { font-family: Georgia, 'Times New Roman', serif; font-size: 2.45rem; }
    .eyebrow { color: var(--teal); font: 700 0.72rem/1.2 'Trebuchet MS', sans-serif; text-transform: uppercase; }
    .lede { color: var(--muted); font-size: 1.02rem; max-width: 720px; }
    div[data-testid="stMetric"] { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 14px 16px; }
    div[data-testid="stMetricLabel"] { color: var(--muted); }
    div[data-testid="stMetricValue"] { color: var(--ink); }
    .stButton > button[kind="primary"] { background: var(--teal); border-color: var(--teal); color: white; }
    .stButton > button, .stDownloadButton > button { border-radius: 5px; }
    div[data-baseweb="input"] > div { background: white; border-color: var(--line); }
    div[data-testid="stExpander"] { background: var(--panel); border: 1px solid var(--line); border-radius: 5px; }
    hr { border-color: var(--line); }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="eyebrow">Read-only repository audit</div>', unsafe_allow_html=True)
st.title("CodeSentinel")
st.markdown(
    '<p class="lede">Architecture-agnostic code review for security risks, unfinished work, and measurable maintenance issues.</p>',
    unsafe_allow_html=True,
)

api_url = os.getenv("CODESENTINEL_API_URL", "http://127.0.0.1:8000").rstrip("/")
with st.form("repository-form", clear_on_submit=False):
    repository_url = st.text_input(
        "Public GitHub repository URL",
        placeholder="https://github.com/owner/repository",
        max_chars=500,
    )
    analyze_clicked = st.form_submit_button("Analyze repository", type="primary")

if analyze_clicked:
    if not repository_url.strip():
        st.error("Enter a public GitHub repository URL.")
    else:
        try:
            with st.spinner("Downloading and auditing the repository. Source code is not executed."):
                response = requests.post(
                    f"{api_url}/analyze",
                    json={"repository_url": repository_url.strip()},
                    timeout=(10, 240),
                )
            if response.ok:
                st.session_state["analysis_report"] = response.json()
                st.session_state.pop("analysis_error", None)
            else:
                try:
                    detail = response.json().get("detail", "Analysis request failed.")
                except ValueError:
                    detail = "Analysis request failed. Check that the local API is running."
                st.session_state["analysis_error"] = str(detail)[:500]
        except requests.RequestException:
            st.session_state["analysis_error"] = (
                f"Could not reach the analysis API at {api_url}. Start the service with `python run.py`."
            )

if st.session_state.get("analysis_error"):
    st.error(st.session_state["analysis_error"])

report_data = st.session_state.get("analysis_report")
if report_data:
    try:
        report = AnalysisReport.model_validate(report_data)
    except Exception:
        st.error("The API returned an invalid report. Run the analysis again.")
        st.stop()

    st.divider()
    repository = report.repository
    st.subheader(f"{repository.owner}/{repository.name}")
    st.text(f"Branch: {repository.default_branch}  |  Files analyzed: {repository.analyzed_files}  |  Skipped: {repository.skipped_files}")
    language_summary = ", ".join(f"{name} ({count})" for name, count in repository.languages.items()) or "No source language detected"
    st.text(f"Languages: {language_summary}")

    severity_columns = st.columns(5)
    for column, severity in zip(severity_columns, ("Critical", "High", "Medium", "Low", "Informational")):
        column.metric(severity, report.severity_counts.get(severity, 0))

    score_column, detail_column = st.columns([1, 2])
    score_column.metric("Project health", f"{report.health_score}/100")
    detail_column.caption(report.score_explanation)
    detail_column.caption("AI review: completed" if report.ai_reviewed else "AI review: not used; findings are from static analysis")

    download_json, download_html, repository_link = st.columns([1, 1, 1])
    download_json.download_button(
        "Download JSON report",
        data=json_report(report),
        file_name=f"{repository.name}-codesentinel.json",
        mime="application/json",
    )
    download_html.download_button(
        "Download HTML report",
        data=html_report(report),
        file_name=f"{repository.name}-codesentinel.html",
        mime="text/html",
    )
    repository_link.link_button("Open repository", repository.url)

    if report.warnings:
        with st.expander("Analysis notes", expanded=False):
            for warning in report.warnings:
                st.text(warning)

    st.subheader("Findings")
    categories = [
        ("Security", "security"),
        ("Code quality", "slop"),
        ("Coding gaps", "gap"),
        ("Loose ends", "loose_end"),
    ]
    tabs = st.tabs([label for label, _ in categories])
    for tab, (label, category) in zip(tabs, categories):
        with tab:
            category_findings = [finding for finding in report.findings if finding.category == category]
            if not category_findings:
                st.info(f"No {label.lower()} findings were detected by the configured checks.")
            for finding in category_findings:
                location = f"{finding.file}:{finding.line}" if finding.line else finding.file
                with st.expander(f"{finding.severity.value} · {finding.title} · {location}"):
                    st.caption(f"{finding.rule_id} · confidence: {finding.confidence}")
                    st.text(finding.explanation)
                    st.markdown("**Suggested fix**")
                    st.text(finding.recommendation)
                    if finding.related_findings:
                        st.caption("Related review items: " + ", ".join(finding.related_findings))
    st.caption("Findings are static-analysis signals, not proof of exploitability. Verify each issue in context.")