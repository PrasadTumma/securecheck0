import json
import logging
import sys
import os
import re
import shutil
from typing import List, Dict, Optional
from difflib import SequenceMatcher

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from sast.wrappers.semgrep_wrapper import run_semgrep
from sast.wrappers.spotbugs_wrapper import run_spotbugs

from sast.sast_ai_suggestion import AISuggestion, apply_fix
from sast.sast_confidence import ConfidenceLevel
from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def find_servlet_api_jar() -> str:
    search_dirs = [
        "./libs",
        "/usr/share/java",
        "/usr/local/share/java",
        "/home/avni/securecheck/libs"
    ]
    for path in search_dirs:
        if os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.startswith("servlet-api") and filename.endswith(".jar"):
                    full_path = os.path.join(path, filename)
                    logger.info(f"Found servlet-api jar: {full_path}")
                    return full_path
    logger.warning("No servlet-api jar found.")
    return ""

def normalize_spotbugs(finding: dict) -> dict:
    return {
        "line_number": finding.get("line_number"),
        "cwe_id": finding.get("cwe_id") or "SPOTBUGS-RULE",
        "description": finding.get("description"),
        "severity": finding.get("severity", "medium").lower(),
        "tool": "SpotBugs"
    }


def normalize_semgrep(finding: dict) -> dict:
    return {
        "line_number": finding.get("line"),
        "cwe_id": str(finding.get("cwe_id")) if finding.get("cwe_id") else None,
        "description": finding.get("message"),
        "severity": finding.get("severity", "warning").lower(),
        "tool": "Semgrep"
    }


def extract_java_context(code: str, line_number: int, window: int = 3) -> str:
    lines = code.splitlines()
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return "\n".join(lines[start:end]).strip()


def rename_java_file_for_compilation(original_path: str) -> str:
    with open(original_path, "r") as f:
        content = f.read()
    match = re.search(r'public\s+class\s+(\w+)', content)
    if not match:
        return original_path
    class_name = match.group(1)
    new_path = os.path.join(os.path.dirname(original_path), f"{class_name}.java")
    if new_path != original_path:
        shutil.copyfile(original_path, new_path)
        return new_path
    return original_path


def are_similar(msg1: str, msg2: str, threshold: float = 0.85) -> bool:
    return SequenceMatcher(None, msg1 or "", msg2 or "").ratio() > threshold


def deduplicate_java_findings(findings: List[Dict]) -> List[Dict]:
    deduped = []
    for f in findings:
        is_duplicate = False
        for existing in deduped:
            if (
                f.get("line_number") == existing.get("line_number") and
                (f.get("cwe_id") or "").lower() == (existing.get("cwe_id") or "").lower() and
                are_similar(f.get("description", ""), existing.get("description", ""))
            ):
                is_duplicate = True
                break
        if not is_duplicate:
            deduped.append(f)
    return deduped

def get_java_lib_path() -> Optional[str]:
    possible_paths = [
        "./libs/servlet-api-2.5.jar",
        "/usr/share/java/servlet-api.jar",
        "/usr/share/servlet-api/servlet-api.jar",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

def handle_java(file_path: str, ai_enabled: bool = True, static_fix_enabled: bool = True, confidence_threshold: float = 0.0) -> List[Dict]:
    try:
        with open(file_path, 'r') as file:
            code = file.read()

        adjusted_path = rename_java_file_for_compilation(file_path)

        # Get servlet jar if present, and always add JDK lib path
        servlet_jar = find_servlet_api_jar()
        java_lib_path = get_java_lib_path()

        # Build combined classpath
        if servlet_jar and java_lib_path:
            combined_classpath = f"{servlet_jar}:{java_lib_path}"
        elif servlet_jar:
            combined_classpath = servlet_jar
        elif java_lib_path:
            combined_classpath = java_lib_path
        else:
            combined_classpath = None

        spotbugs = [normalize_spotbugs(f) for f in run_spotbugs(adjusted_path, classpath=combined_classpath)]
        semgrep = [normalize_semgrep(f) for f in run_semgrep(file_path, language="java")]

        combined = spotbugs + semgrep
        logger.info(f"Combined: {len(combined)} findings")

        deduped = deduplicate_java_findings(combined)
        logger.info(f"Deduplicated: {len(deduped)} findings")

        ai_allowed = ai_enabled and os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes"
        if not ai_allowed:
            logger.info("User declined AI fix generation.")

        final_report = []
        processed_lines = set()

        for vuln in deduped:
            line_number = vuln.get("line_number")
            if not line_number or line_number in processed_lines:
                continue
            processed_lines.add(line_number)

            context = extract_java_context(code, line_number)
            cwe_id = vuln.get("cwe_id", "")
            vuln_info = {
                "line_number": line_number,
                "vulnerability_name": cwe_id or vuln.get("description", "Unknown").split(":")[0],
                "description": vuln.get("description"),
                "context": context
            }

            # Normalize CWE number (e.g., 327 from CWE-327)
            cwe_number = ""
            if cwe_id and cwe_id.upper().startswith("CWE-"):
                parts = cwe_id.upper().split("-")
                if len(parts) == 2 and parts[1].isdigit():
                    cwe_number = parts[1]

            static_fix = (
                get_static_fix(cwe_number)
                or get_static_fix(vuln_info.get("vulnerability_name", ""))
                or get_static_fix(vuln_info.get("description", ""))
                or "No static fix available for this finding."
            )

            if ai_allowed:
                try:
                    ai_suggestion = AISuggestion(vuln_info)
                    suggestion_result = ai_suggestion.generate_suggestion(code)
                    fixed_code = apply_fix(code, suggestion_result, line_number)
                    confidence_checker = ConfidenceLevel(vuln_info, suggestion_result.get("suggestion", ""))
                    confidence_result = confidence_checker.compute_confidence()
                except RuntimeError as err:
                    logger.warning(f"Aborting AI suggestions: {err}")
                    suggestion_result = {
                        "suggestion": "",
                        "confidence_level": "N/A",
                        "note": str(err)
                    }
                    confidence_result = "N/A"
            else:
                suggestion_result = {
                    "suggestion": "",
                    "confidence_level": "N/A",
                    "note": "User declined AI-based fix generation."
                }
                confidence_result = "N/A"

            report_entry = {
                "vulnerability": vuln_info,
                "fixes": {
                    "ai_suggestion": suggestion_result,
                    "static_fix": static_fix,
                    "note": "Both AI and static fixes provided." if suggestion_result.get("suggestion") and static_fix else
                            "Only static fix available." if static_fix else
                            "Only AI fix available." if suggestion_result.get("suggestion") else
                            "No fix available."
                },
                "confidence": confidence_result,
                "line": line_number,
                "message": vuln_info["description"],
                "tool": vuln.get("tool", "Unknown"),
                "severity": vuln.get("severity", "unknown"),
                "cwe_id": str(cwe_id or "N/A")
            }

            final_report.append(report_entry)

        return final_report

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error processing {file_path}: {str(e)}")
        return []

if __name__ == "__main__":
    test_file = "Example.java"
    result = handle_java(test_file)
    print(json.dumps(result, indent=2))
