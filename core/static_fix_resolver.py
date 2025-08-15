import os
import json
import re
import logging
import difflib

logger = logging.getLogger(__name__)

# Path to static fix JSON database
STATIC_FIX_DB_PATH = os.path.join(os.path.dirname(__file__), "static_fix.json")


def extract_cwe_number(text: str) -> str:
    """
    Extract numeric CWE ID from text like 'CWE-79'.
    """
    match = re.search(r"(\d+)", text or "")
    return match.group(1) if match else ""


def load_fix_db() -> list:
    """
    Load static fixes from the local JSON database.
    Returns a list of CWE fix records.
    """
    try:
        with open(STATIC_FIX_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("cwes", [])  # Expected top-level key: "cwes"
    except Exception as e:
        logger.error(f"Failed to load static fix database: {e}")
        return []


def get_static_fix(cwe_id: str = "", vuln_name: str = "", description: str = "") -> str:
    """
    Get a static fix using:
    1. Exact match on CWE ID (preferred)
    2. Fuzzy match on vulnerability name
    3. Fuzzy match on description
    Returns a formatted fix string or default message.
    """
    try:
        fixes = load_fix_db()
        cwe_number = extract_cwe_number(cwe_id)

        # 1. Exact CWE match
        for item in fixes:
            item_cwe = extract_cwe_number(item.get("cwe_id", ""))
            if item_cwe and item_cwe == cwe_number:
                return format_fix(item)

        # Normalize inputs
        vuln_name = (vuln_name or "").strip().lower()
        description = (description or "").strip().lower()

        # 2. Fuzzy match on name
        if vuln_name:
            name_map = {item.get("name", "").strip().lower(): item for item in fixes if item.get("name")}
            best_match = difflib.get_close_matches(vuln_name, name_map.keys(), n=1, cutoff=0.7)
            if best_match:
                return format_fix(name_map[best_match[0]])

        # 3. Fuzzy match on description
        if description:
            desc_map = {item.get("description", "").strip().lower(): item for item in fixes if item.get("description")}
            best_match = difflib.get_close_matches(description, desc_map.keys(), n=1, cutoff=0.7)
            if best_match:
                return format_fix(desc_map[best_match[0]])

        return "No static fix found for this issue."

    except Exception as e:
        logger.error(f"Error in get_static_fix(): {e}")
        return "Static fix lookup failed."


def format_fix(item: dict) -> str:
    """
    Format a fix entry for display.
    """
    fix = item.get("static_fix", "No fix provided.")
    reference = item.get("reference_url", "N/A")
    return f"**Fix Recommendation:**\n{fix}\n\n**Reference:** {reference}"
