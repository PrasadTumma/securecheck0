import streamlit as st
import os
import json
import logging
from dast.scans.ffuf_scan import FFUFScanner
from dast.scans.nuclei_scan import NucleiScanner
from dast.scans.dastardly_scan import DastardlyScanner
from dast.dast_report_generator import generate_dast_report
from dast.dast_ai_suggestion import generate_dast_remediation_plan

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def render_dast_tab(session_state) -> None:
    st.title("DAST Analysis")

    url = st.text_input("Enter the URL of the deployed application:")
    har_file = st.file_uploader("Upload HAR file (required for Dastardly)", type=["har"])
    allow_ai = st.checkbox("Enable AI Suggestions", value=True)

    if "dast_results" not in session_state:
        session_state.dast_results = None
    if "dast_ai_prompt" not in session_state:
        session_state.dast_ai_prompt = ""

    if st.button("Run DAST Scan"):
        if url and har_file is not None:
            try:
                har_path = "har_upload/traffic.har"
                os.makedirs(os.path.dirname(har_path), exist_ok=True)
                with open(har_path, "wb") as f:
                    f.write(har_file.read())

                st.info("Running FFUF...")
                ffuf_scanner = FFUFScanner(url)
                ffuf_results = ffuf_scanner.run_ffuf()
                logger.info("FFUF scan completed.")

                st.info("Running Nuclei on discovered endpoints...")
                har_based_scanner = NucleiScanner.from_har(har_path)
                ffuf_endpoints = [entry["url"] for entry in ffuf_results]
                combined_endpoints = sorted(set(ffuf_endpoints + har_based_scanner.endpoints))
                nuclei_scanner = NucleiScanner(combined_endpoints)
                nuclei_results = nuclei_scanner.run_nuclei()
                logger.info("Nuclei scan completed.")

                st.info("Running Dastardly...")
                dastardly_output_path = "reports/dastardly-report.html"
                dastardly_scanner = DastardlyScanner(har_path, "reports", url)
                dastardly_scanner.run_dastardly()
                dastardly_results = dastardly_scanner.findings or []
                logger.info("Dastardly scan completed.")

                st.success("DAST Scans Completed")

                ai_fix = {}
                ai_prompt = ""
                if allow_ai:
                    try:
                        st.info("Generating AI-based remediation plan...")
                        ai_result = generate_dast_remediation_plan(ffuf_results, nuclei_results, allow_ai=allow_ai)
                        ai_fix = ai_result.get("grouped_by_cwe", {})
                        ai_prompt = ai_result.get("prompt", "AI could not generate suggestions.")
                        logger.info("AI remediation plan ready.")
                    except Exception as ai_err:
                        logger.warning(f"AI generation failed: {ai_err}")
                        ai_prompt = "AI suggestions unavailable due to error."

                session_state.dast_results = {
                    "ffuf": ffuf_results,
                    "nuclei": nuclei_results,
                    "dastardly": dastardly_results,
                    "ai_fix": ai_fix
                }
                session_state.dast_ai_prompt = ai_prompt

            except Exception as scan_err:
                logger.error("DAST scan failed: %s", str(scan_err))
                st.error("An error occurred during DAST scan execution.")

    if session_state.dast_results:
        with st.expander("View AI Prompt for Remediation Suggestions"):
            st.code(session_state.dast_ai_prompt, language="markdown")

        try:
            report = generate_dast_report(
                session_state.dast_results["ffuf"],
                session_state.dast_results["nuclei"],
                session_state.dast_results["dastardly"],
                session_state.dast_results["ai_fix"]
            )
            st.success("Final DAST Report Ready")
            st.download_button("Download DAST Report (JSON)", json.dumps(report, indent=2).encode(), "dast_report.json")

            st.markdown("---")
            st.header("Vulnerability Findings")
            for finding in report.get("findings", []):
                severity = finding.get("severity", "LOW").upper()
                badge_color = {
                    "CRITICAL": "#e74c3c",
                    "HIGH": "#e67e22",
                    "MEDIUM": "#f1c40f",
                    "LOW": "#2ecc71"
                }.get(severity, "#7f8c8d")

                st.markdown(f"### {finding.get('cwe_id', 'Unknown')} — {finding.get('vulnerability', 'No title')}")
                st.markdown(f"<span style='background-color:{badge_color}; color:white; padding:3px 8px; border-radius:3px;'>{severity}</span>", unsafe_allow_html=True)
                st.markdown(f"**Tool:** {finding.get('tool', 'N/A')}")
                st.markdown(f"**Endpoint:** {finding.get('endpoint', 'N/A')}")
                st.markdown(f"**Status Code:** {finding.get('status_code', 'N/A')}")
                
                if finding.get("static_fix"):
                    st.markdown("**Static Fix Suggestion:**")
                    st.code(finding["static_fix"], language="markdown")

                if finding.get("cwe_id", "").startswith("CWE-"):
                    cwe_number = finding["cwe_id"].split("-")[1]
                    cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
                    st.markdown(f"[View CWE Details]({cwe_url})")

            st.markdown("---")
            st.header("AI Remediation Suggestions")
            ai_fixes = report.get("ai_remediation", {})
            if ai_fixes:
                for cwe_id, fixes in ai_fixes.items():
                    st.subheader(cwe_id)
                    for fix in fixes:
                        st.markdown(f"- {fix.get('remediation') or fix.get('risk') or 'No suggestion'}")
            else:
                st.markdown("No AI suggestions available.")

        except Exception as rerr:
            logger.error(f"Report generation failed: {rerr}")
            st.warning("Failed to generate full DAST report.")

        dastardly_output_path = "reports/dastardly-report.html"
        if os.path.exists(dastardly_output_path):
            with open(dastardly_output_path, "r") as f:
                html_content = f.read()
            st.download_button("Download Raw Dastardly Report (HTML)", html_content, "dastardly-report.html")

    st.markdown("---")
    if st.button("Reset DAST Scan"):
        session_state.dast_scan_done = False
        session_state.dast_results = None
        st.experimental_rerun()
