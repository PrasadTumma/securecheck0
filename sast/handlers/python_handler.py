import json
import logging
import sys
import os
from typing import List, Dict
from difflib import SequenceMatcher


# Ensure parent directory of sast is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from sast.wrappers.semgrep_wrapper import run_semgrep
from sast.wrappers.bandit_wrapper import run_bandit
from core.static_fix_resolver import get_static_fix

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sast.sast_ai_suggestion import AISuggestion, apply_fix
from sast.sast_confidence import ConfidenceLevel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def normalize_bandit(finding: dict) -> dict:
    return {
        "line_number": finding.get("line_number") or finding.get("line"),
        "description": finding.get("issue_text") or finding.get("message"),
        "severity": (finding.get("issue_severity") or finding.get("severity") or "low").lower(),
        "cwe_id": f"CWE-{finding['issue_cwe'].get('id')}" if finding.get("issue_cwe", {}).get("id") else None,
        "tool": "Bandit"
    }

def normalize_semgrep(finding: dict) -> dict:
    return {
        "line_number": finding.get("line"),
        "description": finding.get("message"),
        "severity": {
            "INFO": "low",
            "WARNING": "medium",
            "ERROR": "high"
        }.get(finding.get("severity", "WARNING").upper(), "medium"),
        "cwe_id": finding.get("cwe_id").split(":")[0] if finding.get("cwe_id") else None,
        "tool": "Semgrep"
    }

def extract_python_context(code: str, line_number: int, window: int = 3) -> str:
    lines = code.splitlines()
    if not line_number:
        return ""
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return "\n".join(lines[start:end]).strip()

def are_similar(msg1, msg2, threshold=0.85):
    return SequenceMatcher(None, msg1 or "", msg2 or "").ratio() > threshold

def deduplicate_python_findings(findings: List[Dict]) -> List[Dict]:
    deduped = []
    for f in findings:
        is_duplicate = False
        for existing in deduped:
            if (
                f.get("line_number") == existing.get("line_number") and
                (f.get("cwe_id") or "").lower() == (existing.get("cwe_id") or "").lower() and
                are_similar(f.get("description", ""), existing.get("description", ""))
            ):
                prefer = "Semgrep" if f.get("tool") == "Semgrep" else existing.get("tool")
                if prefer == "Semgrep":
                    deduped.remove(existing)
                    deduped.append(f)
                is_duplicate = True
                break
        if not is_duplicate:
            deduped.append(f)
    return deduped


def handle_python(file_path: str, ai_enabled: bool = True) -> List[Dict]:
    try:
        with open(file_path, 'r') as file:
            code = file.read()

        bandit_results = [normalize_bandit(f) for f in run_bandit(file_path)]
        semgrep_results = [normalize_semgrep(f) for f in run_semgrep(file_path, language="python")]
        all_findings = bandit_results + semgrep_results
        logger.info(f"Combined results: {len(all_findings)} findings")

        deduped = deduplicate_python_findings(all_findings)
        logger.info(f"Deduplicated results: {len(deduped)} findings")

        final_report = []
        processed_entries = set()

        for vuln in deduped:
            line_number = vuln.get("line_number", 0)
            entry_key = (line_number, vuln.get("cwe_id"), vuln.get("description"))
            if entry_key in processed_entries:
                continue
            processed_entries.add(entry_key)

            # Skip low severity bandit results
            if vuln.get("tool") == "Bandit" and vuln.get("severity", "").lower() == "low":
                continue

            context = extract_python_context(code, line_number)
            cwe_id = vuln.get("cwe_id", "")
            description = vuln.get("description", "")

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

            vulnerability_info = {
                "line_number": line_number,
                "vulnerability_name": cwe_id or description.split(":")[0],
                "description": description,
                "context": context,
                "tool": vuln.get("tool", "Unknown"),
                "cwe_id": cwe_id or "N/A"
            }

            if ai_enabled and os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes":
                try:
                    ai_suggestion = AISuggestion(vulnerability_info)
                    suggestion_result = ai_suggestion.generate_suggestion(code)
                    apply_fix(code, suggestion_result, line_number)
                    confidence_checker = ConfidenceLevel(vulnerability_info, suggestion_result.get("suggestion", ""))
                    confidence_result = confidence_checker.compute_confidence()
                except RuntimeError as err:
                    logger.warning(f"AI suggestion failed: {err}")
                    ai_enabled = False
                    suggestion_result = {
                        "suggestion": "",
                        "confidence_level": "N/A",
                        "note": str(err)
                    }
                    confidence_result = {"confidence_level": "N/A", "message": str(err)}
            else:
                suggestion_result = {
                    "suggestion": "",
                    "confidence_level": "N/A",
                    "note": "User declined AI-based fix generation."
                }
                confidence_result = {"confidence_level": "N/A", "message": "AI was disabled or skipped."}

            report_entry = {
                "vulnerability": vulnerability_info,
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
                "message": description,
                "tool": vuln.get("tool", "Unknown"),
                "severity": vuln.get("severity", "unknown"),
                "cwe_id": cwe_id or "N/A"
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
    test_file = "example.py"
    result = handle_python(test_file)
    print(json.dumps(result, indent=2))