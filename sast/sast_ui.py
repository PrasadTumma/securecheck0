import streamlit as st
import json
import os
import tempfile
import logging
from typing import List, Dict, Optional
from sast.sast_file_router import FileRouter
from sast.sast_report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Map of extensions to display names
EXT_LANGUAGE_MAP = {
    "py": "python",
    "java": "java",
    "js": "javascript",
    "c": "c",
    "cpp": "cpp",
    "cs": "csharp",
    "go": "go",
    "rb": "ruby",
    "php": "php",
    "ts": "typescript",
    "kt": "kotlin"
}

def render_sast_tab(session_state):
    st.title("SAST Analysis")

    ai_enabled = st.checkbox("Enable AI Suggestions (OpenAI)", value=True)

    # Session state setup
    if "sast_results" not in session_state:
        session_state.sast_results = None
    if "sast_uploaded_file_path" not in session_state:
        session_state.sast_uploaded_file_path = None
    if "sast_uploaded_file_name" not in session_state:
        session_state.sast_uploaded_file_name = None

    uploaded_file = st.file_uploader("Upload a source code file", type=list(EXT_LANGUAGE_MAP.keys()))

    if st.button("Run SAST Scan"):
        if uploaded_file:
            try:
                uploaded_bytes = uploaded_file.read()
                file_content = uploaded_bytes.decode("utf-8")
                st.code(file_content)

                os.makedirs("temp_uploads", exist_ok=True)
                temp_path = os.path.join("temp_uploads", uploaded_file.name)
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.write(file_content)

                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                    tmp_file.write(uploaded_bytes)
                    uploaded_file_path = tmp_file.name

                router = FileRouter()
                route_result = router.route_file(temp_path, ai_enabled=ai_enabled)

                if not isinstance(route_result, dict) or "results" not in route_result:
                    st.error("An error occurred while routing or analyzing the file.")
                    return

                session_state.sast_results = {
                    "findings": route_result["results"],
                    "language": route_result.get("language", "text"),
                    "temp_path": temp_path,
                    "uploaded_file_path": uploaded_file_path
                }
                session_state.sast_uploaded_file_name = uploaded_file.name
                st.success("SAST scan completed.")

            except Exception as e:
                logger.exception("SAST scan failed.")
                st.error(f"An error occurred while scanning the file: {str(e)}")

    # --- Display Results ---
    if session_state.sast_results:
        findings = session_state.sast_results["findings"]
        language = session_state.sast_results["language"]
        temp_path = session_state.sast_results["temp_path"]
        uploaded_file_path = session_state.sast_results["uploaded_file_path"]

        if not findings:
            st.warning("No findings detected in the uploaded file.")
            return

        tool_versions = {
            "semgrep": "0.70.0",
            "spotbugs": "4.7.3",
            "bandit": "1.7.4",
            "eslint": "7.32.0",
            "openai": "1.0.0"
        }

        fix_verified = "no"

        for idx, finding in enumerate(findings, 1):
            vuln = finding.get("vulnerability", {})
            fixes = finding.get("fixes", {})
            ai_fix = fixes.get("ai_suggestion", {}).get("suggestion", "")
            static_fix = fixes.get("static_fix", "")
            confidence = finding.get("confidence", {})

            with st.expander(f"Finding #{idx}: {vuln.get('vulnerability_name', 'Unknown')} (Line {vuln.get('line_number')})"):
                st.markdown(f"**Description:** {vuln.get('description', 'N/A')}")
                st.markdown(f"**Tool:** `{finding.get('tool', 'N/A')}`")
                st.markdown(f"**CWE ID:** `{finding.get('cwe_id', 'N/A')}`")
                st.markdown(f"**Severity:** `{finding.get('severity', 'N/A')}`")
                st.markdown(f"**AI Enabled:** `{ai_enabled}`")

                st.markdown("----")
                st.markdown("### Static Fix")
                if static_fix:
                    st.code(static_fix, language=language)
                else:
                    st.warning("No static fix available for this finding.")

                if ai_enabled:
                    st.markdown("### AI Suggestion")
                    if ai_fix:
                        st.code(ai_fix, language=language)
                    else:
                        st.info("No AI suggestion available.")

                    st.markdown("### Confidence Assessment")
                    if isinstance(confidence, dict):
                        st.markdown(f"**Confidence Level:** {confidence.get('confidence_level', 'Unknown')}")
                        st.caption(confidence.get("message", "No explanation available"))
                    else:
                        st.markdown(f"**Confidence Level:** {confidence}")

        st.subheader("Raw Findings (Debug)")
        st.json(findings)

        report_generator = ReportGenerator(
            file_path=temp_path,
            findings=findings,
            fix_verified=fix_verified,
            tool_versions=tool_versions,
            source_code_path=uploaded_file_path
        )
        report = report_generator.generate_report()

        json_path = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
        pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        html_path = tempfile.NamedTemporaryFile(delete=False, suffix=".html").name

        report_generator.export_to_json(report, json_path)
        report_generator.export_to_pdf(report, pdf_path)
        report_generator.export_to_html(report, html_path)

        st.success("SAST report generated successfully!")

        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        st.download_button("Download JSON Report", data=open(json_path).read(), file_name="sast_report.json", mime="application/json")
        st.download_button("Download PDF Report", data=open(pdf_path, "rb").read(), file_name="sast_report.pdf", mime="application/pdf")
        st.download_button("Download HTML Report", data=html_content, file_name="sast_report.html", mime="text/html")

    st.markdown("---")
    if st.button("Reset SAST Scan"):
        session_state.sast_scan_done = False
        session_state.sast_result = None
        st.experimental_rerun()


# For testing without Streamlit CLI
if __name__ == "__main__":
    render_sast_tab()
