import streamlit as st

# Import all UI tabs from their respective modules
from sast.sast_ui import render_sast_tab
from sbom.sbom_ui import render_sbom_tab
from dast.dast_ui import render_dast_tab
from learn.learn_ui import render_learn_tab

# Optional: These can be integrated with actual CWE findings for Learn Tab
from learn.cwe_lessons import CWELessons

# Initialize lesson database for Learn tab
cwe_lessons_instance = CWELessons()
lesson_db = cwe_lessons_instance.lessons

# For now, simulate detected CWEs as examples
example_static_cwes = ["CWE-79", "CWE-89"]
example_dynamic_cwes = ["CWE-22", "CWE-352"]

def main():
    # Page Configuration
    st.set_page_config(
        page_title="SecureCheck - Secure Coding Analysis Suite",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # --- Initialize Streamlit Session State ---
    if "sast_scan_done" not in st.session_state:
        st.session_state.sast_scan_done = False
    if "dast_scan_done" not in st.session_state:
        st.session_state.dast_scan_done = False
    if "sbom_scan_done" not in st.session_state:
        st.session_state.sbom_scan_done = False
    if "sast_result" not in st.session_state:
        st.session_state.sast_result = None
    if "sbom_result" not in st.session_state:
        st.session_state.sbom_result = None
    if "dast_result" not in st.session_state:
        st.session_state.dast_result = None

    # Sidebar Navigation
    st.sidebar.title("SecureCheck")
    st.sidebar.markdown("Select a module to begin:")

    tab = st.sidebar.radio(
        "Modules",
        ["Welcome", "SAST", "SBOM", "DAST", "Learn"],
        key="main_tab"
    )

    # Main Tab Renderer
    if tab == "Welcome":
        st.title("Welcome to SecureCheck")
        st.markdown("""
        SecureCheck is a developer-focused secure coding suite that helps you:
        - Detect and fix source code vulnerabilities using SAST
        - Audit and visualize third-party package vulnerabilities using SBOM
        - Simulate DAST scans on live endpoints
        - Learn common CWEs and secure coding practices

        Built with: Python, Streamlit, Bandit, Semgrep, SpotBugs, Syft, Grype, FFUF, Nuclei, Dastardly, OpenAI
        """)
    elif tab == "SAST":
        render_sast_tab(st.session_state)
    elif tab == "SBOM":
        render_sbom_tab(st.session_state)
    elif tab == "DAST":
        render_dast_tab(st.session_state)
    elif tab == "Learn":
        render_learn_tab(example_static_cwes, example_dynamic_cwes, lesson_db)

# Entry Point
if __name__ == "__main__":
    main()
