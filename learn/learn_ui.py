import streamlit as st
from typing import List, Dict, Any

def render_learn_tab(static_cwes: List[str], dynamic_cwes: List[str], lesson_db: Dict[str, Any]) -> None:
    """Render the Learn Tab with static and dynamic CWEs."""
    st.header("Learn Tab")
    
    st.subheader("Static Analysis CWEs")
    if not static_cwes:
        st.info("No static analysis CWEs detected.")
    for cwe in static_cwes:
        show_lesson(cwe, lesson_db)
    
    st.subheader("Dynamic Analysis CWEs")
    if not dynamic_cwes:
        st.info("No dynamic analysis CWEs detected.")
    for cwe in dynamic_cwes:
        show_lesson(cwe, lesson_db)

def show_lesson(cwe_id: str, lesson_db: Dict[str, Any]) -> None:
    """Display a lesson for a given CWE ID."""
    lesson = lesson_db.get(cwe_id)
    if lesson:
        with st.expander(f"{cwe_id}: {lesson.get('title', f'No title for {cwe_id}')}"):
            st.write("**Summary**:", lesson.get("summary", "No summary available."))
            st.write("**Impact**:", lesson.get("impact", "No impact information available."))
            st.write("**Mitigation**:", lesson.get("mitigation", "No mitigation information available."))
            st.write("**Examples**:")
            st.code(lesson["examples"].get("bad", "No bad example available."), language="python")
            st.code(lesson["examples"].get("good", "No good example available."), language="python")
    else:
        st.warning(f"No lesson found for CWE ID: {cwe_id}")

# Example usage
if __name__ == "__main__":
    # This part is for testing purposes and should be replaced with actual data in production
    lesson_db = {
        "CWE-79": {
            "title": "Cross-site Scripting (XSS)",
            "summary": "Untrusted input used in the output without sanitization.",
            "impact": "XSS can lead to data theft, session hijacking, and other malicious activities.",
            "mitigation": "Always sanitize and validate user input before rendering it in the output.",
            "examples": {
                "bad": "response.write(user_input);",
                "good": "response.write(escape(user_input));"
            }
        }
    }
    static_cwes = ["CWE-79"]
    dynamic_cwes = []  # Populate with dynamic CWEs as needed
    render_learn_tab(static_cwes, dynamic_cwes, lesson_db)
