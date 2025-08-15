import json
import logging
from typing import List, Dict, Any
from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DASTParser:
    def __init__(self, ffuf_findings: List[Dict[str, Any]], dastardly_findings: List[Dict[str, Any]], nuclei_findings: List[Dict[str, Any]]):
        self.ffuf_findings = ffuf_findings
        self.dastardly_findings = dastardly_findings
        self.nuclei_findings = nuclei_findings

    def normalize_findings(self) -> List[Dict[str, Any]]:
        """Normalize findings from all tools into a common schema with static fixes."""
        normalized_findings = []

        # Normalize FFUF findings
        for finding in self.ffuf_findings:
            static_fix = get_static_fix(finding.get("description", "") or finding.get("url", ""))
            normalized_findings.append({
                "tool": "ffuf",
                "endpoint": finding.get("url"),
                "status_code": finding.get("status", None),
                "vulnerability": None,
                "cwe_id": None,
                "fixes": {
                    "static_fix": static_fix
                }
            })

        # Normalize Dastardly findings
        for finding in self.dastardly_findings:
            static_fix = get_static_fix(finding.get("cwe_id") or finding.get("description", ""))
            normalized_findings.append({
                "tool": "dastardly",
                "endpoint": finding.get("url"),
                "status_code": None,
                "vulnerability": finding.get("description"),
                "cwe_id": finding.get("cwe_id"),
                "fixes": {
                    "static_fix": static_fix
                }
            })

        # Normalize Nuclei findings
        for finding in self.nuclei_findings:
            static_fix = get_static_fix(finding.get("cwe_id") or finding.get("description", ""))
            normalized_findings.append({
                "tool": "nuclei",
                "endpoint": finding.get("url"),
                "status_code": None,
                "vulnerability": finding.get("description"),
                "cwe_id": finding.get("cwe_id"),
                "fixes": {
                    "static_fix": static_fix
                }
            })

        logger.info(f"Normalized findings: {len(normalized_findings)} entries created.")
        return normalized_findings

    def separate_ai_remediation(self, ai_suggestions: str) -> Dict[str, Any]:
        """Separate AI remediation suggestions by CWE."""
        try:
            suggestions = json.loads(ai_suggestions)
            grouped_suggestions = {}

            for suggestion in suggestions:
                cwe_id = suggestion.get("cwe")
                if cwe_id not in grouped_suggestions:
                    grouped_suggestions[cwe_id] = []
                grouped_suggestions[cwe_id].append(suggestion)

            logger.info("AI remediation suggestions grouped by CWE.")
            return grouped_suggestions
        except json.JSONDecodeError:
            logger.error("Failed to parse AI suggestions JSON.")
            raise
        except Exception as e:
            logger.error(f"An error occurred while separating AI suggestions: {str(e)}")
            raise


# Example usage
if __name__ == "__main__":
    ffuf_findings = [
        {"url": "/admin", "status": 200},
        {"url": "/login", "status": 200},
    ]
    dastardly_findings = [
        {"url": "/search?q=", "description": "Reflected XSS", "cwe_id": "CWE-79"},
        {"url": "/login", "description": "SQL Injection", "cwe_id": "CWE-89"},
    ]
    nuclei_findings = [
        {"url": "/download?file=../../etc/passwd", "description": "Path Traversal", "cwe_id": "CWE-22"},
    ]

    try:
        dast_parser = DASTParser(ffuf_findings, dastardly_findings, nuclei_findings)
        normalized_findings = dast_parser.normalize_findings()
        print(json.dumps(normalized_findings, indent=4))

        ai_suggestions = json.dumps([
            {"cwe": "CWE-79", "remediation": "Sanitize user input."},
            {"cwe": "CWE-89", "remediation": "Use prepared statements."},
            {"cwe": "CWE-22", "remediation": "Implement proper access controls."}
        ])
        grouped_suggestions = dast_parser.separate_ai_remediation(ai_suggestions)
        print(json.dumps(grouped_suggestions, indent=4))

    except Exception as e:
        logger.error(f"DAST parsing failed: {str(e)}")
