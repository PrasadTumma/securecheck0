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
from sast.wrappers.eslint_wrapper import run_eslint

from sast.sast_ai_suggestion import AISuggestion, apply_fix
from sast.sast_confidence import ConfidenceLevel
from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Normalizers ---

def normalize_eslint(finding: dict) -> dict:
    return {
        "line_number": finding.get("line"),
        "cwe_id": None,
        "description": f"{finding.get('ruleId')}: {finding.get('message')}",
        "severity": {1: "medium", 2: "high"}.get(finding.get("severity"), "low"),
        "tool": "ESLint"
    }

def normalize_semgrep(finding: dict) -> dict:
    return {
        "line_number": finding.get("line"),
        "cwe_id": finding.get("cwe_id"),
        "description": finding.get("message"),
        "severity": finding.get("severity", "warning").lower(),
        "tool": "Semgrep"
    }

# --- Utilities ---

def extract_js_context(code: str, line_number: int, window: int = 3) -> str:
    lines = code.splitlines()
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return "\n".join(lines[start:end]).strip()

def are_similar(msg1: str, msg2: str, threshold: float = 0.85) -> bool:
    return SequenceMatcher(None, msg1 or "", msg2 or "").ratio() > threshold

def deduplicate_js_findings(findings: List[Dict]) -> List[Dict]:
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

# --- Handler ---

def handle_javascript(filepath: str, ai_enabled: bool = False, include_static_fixes: bool = True) -> List[Dict]:
    try:
        with open(filepath, 'r') as f:
            code = f.read()

        eslint = [normalize_eslint(f) for f in run_eslint(filepath) if isinstance(f, dict)]
        semgrep = [normalize_semgrep(f) for f in run_semgrep(filepath, language="javascript") if isinstance(f, dict)]

        combined = eslint + semgrep
        logger.info(f"Combined: {len(combined)} findings")

        deduped = deduplicate_js_findings(combined)
        logger.info(f"Deduplicated: {len(deduped)} findings")

        ai_allowed = ai_enabled and os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes"
        if not ai_allowed:
            logger.info("AI suggestions are disabled.")

        report = []
        processed_lines = set()

        for vuln in deduped:
            line_number = vuln.get("line_number")
            if not line_number or line_number in processed_lines:
                continue
            processed_lines.add(line_number)

            context = extract_js_context(code, line_number)
            description = vuln.get("description", "")
            cwe_id = vuln.get("cwe_id") or ""
            vuln_name = cwe_id or description.split(":")[0]

            vuln_info = {
                "line_number": line_number,
                "vulnerability_name": vuln_name,
                "description": description,
                "context": context
            }

            # Normalize and try to extract CWE number
            cwe_number = ""
            if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-"):
                parts = cwe_id.upper().split("-")
                if len(parts) == 2 and parts[1].isdigit():
                    cwe_number = parts[1]

            # Try fix in order: CWE number → vuln name → description
            static_fix = (
                get_static_fix(cwe_number)
                or get_static_fix(vuln_name)
                or get_static_fix(description)
                or "No static fix available for this finding."
            ) if include_static_fixes else ""

            if ai_allowed:
                try:
                    ai_suggestion = AISuggestion(vuln_info)
                    suggestion_result = ai_suggestion.generate_suggestion(code)
                    fixed_code = apply_fix(code, suggestion_result, line_number)
                    confidence_checker = ConfidenceLevel(vuln_info, suggestion_result.get("suggestion", ""))
                    confidence_result = confidence_checker.compute_confidence()
                except RuntimeError as err:
                    logger.warning(f"AI fix failed: {err}")
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
                    "note": "AI suggestions disabled."
                }
                confidence_result = "N/A"

            report_entry = {
                "vulnerability": vuln_info,
                "fixes": {
                    "ai_suggestion": suggestion_result,
                    "static_fix": {"fix": static_fix},
                    "note": (
                        "Both AI and static fixes provided." if suggestion_result.get("suggestion") and static_fix else
                        "Only static fix available." if static_fix else
                        "Only AI fix available." if suggestion_result.get("suggestion") else
                        "No fix available."
                    )
                },
                "confidence": confidence_result,
                "line": line_number,
                "message": description,
                "tool": vuln.get("tool", "Unknown"),
                "severity": vuln.get("severity", "unknown"),
                "cwe_id": cwe_id or "N/A"
            }

            report.append(report_entry)

        return report

    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return []
    except Exception as e:
        logger.error(f"Error processing {filepath}: {str(e)}")
        return []

if __name__ == "__main__":
    result = handle_javascript("example.js")
    print(json.dumps(result, indent=2))
