import json
import logging
import sys
import os
from typing import List, Dict, Optional
from difflib import SequenceMatcher

# Dynamic path setup
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from sast.wrappers.semgrep_wrapper import run_semgrep
from sast.wrappers.devskim_wrapper import run_devskim

# AI + Confidence
from sast.sast_ai_suggestion import AISuggestion, apply_fix
from sast.sast_confidence import ConfidenceLevel

# OWASP static fix
from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Normalizers ---

def normalize_devskim(finding: dict) -> dict:
    return {
        "line_number": finding.get("startLine"),
        "cwe_id": finding.get("ruleId"),
        "description": finding.get("message"),
        "severity": finding.get("severity", "medium").lower(),
        "tool": "DevSkim"
    }

def normalize_semgrep(finding: dict) -> dict:
    raw_cwe = finding.get("cwe_id", "")
    cwe_id = raw_cwe.split(":")[0].strip() if raw_cwe.startswith("CWE-") else None
    return {
        "line_number": finding.get("line"),
        "cwe_id": cwe_id,
        "description": finding.get("message"),
        "severity": finding.get("severity", "warning").lower(),
        "tool": "Semgrep"
    }

# --- Utilities ---

def are_similar(msg1: str, msg2: str, threshold: float = 0.85) -> bool:
    return SequenceMatcher(None, msg1 or "", msg2 or "").ratio() > threshold

def deduplicate_csharp_findings(findings: List[Dict]) -> List[Dict]:
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

def extract_csharp_context(code: str, line_number: int, window: int = 3) -> str:
    lines = code.splitlines()
    if not line_number:
        return ""
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return "\n".join(lines[start:end]).strip()

# --- Handler ---

def handle_csharp(file_path: str) -> List[Dict]:
    try:
        with open(file_path, "r") as file:
            code = file.read()

        devskim = [normalize_devskim(f) for f in run_devskim(file_path)]
        semgrep = [normalize_semgrep(f) for f in run_semgrep(file_path, "csharp")]

        all_findings = devskim + semgrep
        logger.info(f"Combined findings: {len(all_findings)}")

        deduped = deduplicate_csharp_findings(all_findings)
        logger.info(f"Deduplicated findings: {len(deduped)}")

        ai_allowed = os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes"
        if not ai_allowed:
            logger.info("User declined AI fix generation.")

        final_report = []
        processed_lines = set()

        for vuln in deduped:
            line_number = vuln.get("line_number")
            if not line_number or line_number in processed_lines:
                continue
            processed_lines.add(line_number)

            context = extract_csharp_context(code, line_number)
            vuln_info = {
                "line_number": line_number,
                "vulnerability_name": vuln.get("cwe_id") or vuln.get("tool"),
                "description": vuln.get("description", ""),
                "context": context
            }

            # Normalize and try to extract CWE number (e.g., 79 from CWE-79)
            cwe_number = ""
            if cwe_id and cwe_id.upper().startswith("CWE-"):
                parts = cwe_id.upper().split("-")
                if len(parts) == 2 and parts[1].isdigit():
                    cwe_number = parts[1]

            # Try fix in order: CWE number → vuln name → full description
            static_fix = (
                get_static_fix(cwe_number)
                or get_static_fix(vuln.get("vulnerability_name", ""))
                or get_static_fix(description)
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
                    logger.warning(f"Aborting further AI suggestions: {err}")
                    ai_allowed = False
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
                "cwe_id": str(vuln.get("cwe_id", "N/A"))
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
    test_file = "Example.cs"
    result = handle_csharp(test_file)
    print(json.dumps(result, indent=2))