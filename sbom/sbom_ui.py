import streamlit as st
import os
import logging
import asyncio
import tempfile
import base64
from sbom.sbom_runner import run_sbom_analysis
from sbom.sbom_report_generator import SBOMReportGenerator
from sbom.sbom_parser import SBOMParser
from sbom.sbom_visualizer import SBOMVisualizer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def render_sbom_tab(session_state) -> None:
    st.title("SBOM Analysis")

    if "sbom_result" not in session_state:
        session_state.sbom_result = None

    with st.expander("What to upload and what happens in the background?", expanded=True):
        st.markdown("""
        **Welcome to Software Bill of Materials Analysis**

        You can upload either:
        - A `requirements.txt` file (Python dependencies), or
        - A **text file** containing the name of a Docker container image like `python:3.10-slim` or `ubuntu:latest`.

        ---
        **Scan Options**

        - **Quick Scan**: Fast, uses local pip install. Basic metadata + known vulnerabilities.
        - **Detailed Scan**: Slow, uses Docker to emulate a full environment. Includes system-level packages, compiled binaries, and hidden transitive dependencies. Ideal for production.

        _You don't need to do anything manually - It is handled behind the scenes._
        """)

    scan_choice = st.radio("Choose scan type:", ["Quick Scan (File-based)", "Detailed Scan (Docker-Based)"])
    use_docker = scan_choice == "Detailed Scan (Docker-Based)"

    uploaded_file = st.file_uploader("Upload your requirements.txt or a file containing Docker image name:", type=["txt"])

    if uploaded_file:
        if st.button("Run SBOM Scan"):
            try:
                st.info("Uploaded file detected. Checking contents...")
                content = uploaded_file.getvalue().decode("utf-8").strip()

                if content.startswith(("FROM ", "python:", "ubuntu:", "debian:", "alpine:")) or ":" in content:
                    input_mode = "image"
                    image_or_file = content
                else:
                    input_mode = "file"
                    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".txt") as f:
                        f.write(content)
                        f.flush()
                        image_or_file = f.name

                st.success(f"Input type detected: {'Container Image' if input_mode == 'image' else 'Python Requirements File'}")

                with st.spinner("Generating SBOM with Syft + Grype..."):
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    raw_result = loop.run_until_complete(run_sbom_analysis(image_or_file, use_docker=use_docker))

                if input_mode == "file" and os.path.exists(image_or_file):
                    os.unlink(image_or_file)

                if "error" in raw_result:
                    raise Exception(raw_result["error"])

                syft_data = raw_result["sbom"]
                grype_data = raw_result["vulnerabilities"]

                with st.spinner("Parsing and ranking vulnerabilities..."):
                    parser = SBOMParser(syft_data, grype_data)
                    parsed_data = parser.parse()

                with st.spinner("Generating Dependency Risk Tiles..."):
                    visualizer = SBOMVisualizer(parsed_data)
                    visualizer.generate_png("reports/sbom_risk_tree")

                    with open("reports/sbom_risk_tree.png", "rb") as f:
                        base64_png = base64.b64encode(f.read()).decode("utf-8")

                    tile_html = visualizer.generate_tile_html()

                    visuals = {
                        "tiles": tile_html,
                        "base64_png": f"data:image/png;base64,{base64_png}"
                    }

                session_state.sbom_result = {
                    "parsed_data": parsed_data,
                    "visuals": visuals
                }
                st.success("SBOM scan completed and cached.")
            except Exception as e:
                logger.error("An error occurred during SBOM analysis: %s", str(e))
                st.error("An error occurred during SBOM analysis. Please check logs for details.")

    # --- Display Results ---
    if session_state.sbom_result:
        parsed_data = session_state.sbom_result["parsed_data"]
        visuals = session_state.sbom_result["visuals"]

        st.success("Final SBOM Report Ready")
        st.subheader("Parsed SBOM Summary")
        st.json(parsed_data)

        report_generator = SBOMReportGenerator(
            sbom_data=parsed_data,
            vulnerabilities=parsed_data.get("vulnerabilities", []),
            visuals=visuals
        )
        report_generator.generate_reports(output_prefix="reports/sbom")

        st.success("SBOM Reports generated successfully.")
        st.download_button("Download SBOM Report (JSON)", open("reports/sbom_report.json", "rb").read(), "sbom_report.json")
        st.download_button("Download SBOM Report (PDF)", open("reports/sbom_report.pdf", "rb").read(), "sbom_report.pdf")
        st.download_button("Download SBOM Report (HTML)", open("reports/sbom_report.html", "rb").read(), "sbom_report.html")

        st.subheader("Dependency Risk Tree (Tile View)")
        st.components.v1.html(visuals["tiles"], height=700, scrolling=True)

    st.markdown("---")
    if st.button("Reset SBOM Scan"):
        session_state.sbom_scan_done = False
        session_state.sbom_result = None
        st.experimental_rerun()

# Run directly (for testing outside Streamlit)
if __name__ == "__main__":
    render_sbom_tab()
