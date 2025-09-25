import json
import openai
import logging
import re
from collections import defaultdict
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
VALID_CWE_PATTERN = re.compile(r"^CWE-\d+$")

# Try importing OpenAI v1.0.0 client
#try:
 #   from openai import OpenAI
  #  openai_client = OpenAI()  # Automatically uses OPENAI_API_KEY from env
   # OPENAI_AVAILABLE = True
#except ImportError:
 #   logger.warning("OpenAI SDK not installed or incompatible. AI generation will be skipped.")
  #  OPENAI_AVAILABLE = False'''


class AISuggestionGenerator:
    def __init__(self, ffuf_findings: List[Dict[str, Any]], dastardly_findings: List[Dict[str, Any]], nuclei_findings: List[Dict[str, Any]]):
        """
        Initialize the AI suggestion generator with findings from the three tools.
        
        :param ffuf_findings: Findings from the FFUF scan.
        :param dastardly_findings: Findings from the Dastardly scan.
        :param nuclei_findings: Findings from the Nuclei scan.
        """
        self.ffuf_findings = ffuf_findings or []
        self.dastardly_findings = dastardly_findings or []
        self.nuclei_findings = nuclei_findings or []

    def _is_valid_cwe(self, cwe_id: str) -> bool:  
        """Check if CWE ID is valid (non-empty and follows CWE-XXX format)."""  
        return bool(cwe_id and VALID_CWE_PATTERN.match(cwe_id))

    def group_findings_by_cwe(self) -> Dict[str, List[Dict[str, Any]]]:
        grouped_findings = defaultdict(list)

        for finding in self.ffuf_findings:
            cwe_id = finding.get("cwe_id", "").strip()
            if not self._is_valid_cwe(cwe_id):
                logger.warning(f"Invalid or missing CWE in FFUF finding: {finding}")
                continue
            grouped_findings[cwe_id].append({
                "endpoint": finding.get("url"),
                "risk": "Potential exposure (enumerated endpoint)"
            })

        for finding in self.dastardly_findings:
            cwe_id = finding.get("cwe_id", "").strip()
            if not self._is_valid_cwe(cwe_id):
                logger.warning(f"Invalid or missing CWE in Dastardly finding: {finding}")
                continue
            grouped_findings[cwe_id].append({
                "endpoint": finding.get("url"),
                "risk": "Vulnerability detected (from Dastardly)"
            })

        for finding in self.nuclei_findings:
            cwe_id = finding.get("cwe", "").strip()
            if not self._is_valid_cwe(cwe_id):
                logger.warning(f"Invalid or missing CWE in Nuclei finding: {finding}")
                continue
            grouped_findings[cwe_id].append({
                "endpoint": finding.get("matched_url"),
                "risk": finding.get("description", "Detected issue from Nuclei")
            })

        return grouped_findings

    def generate_summary(self, grouped_findings: Dict[str, List[Dict[str, Any]]]) -> str:
        if not grouped_findings:
            return "No CWE-classified findings were identified across FFUF, Dastardly, or Nuclei."

        summary = []
        for cwe_id, findings in grouped_findings.items():
            summary.append(f"{len(findings)} instance(s) of {cwe_id}")
        return "We detected:\n- " + "\n- ".join(summary)

    def generate_representative_findings(self, grouped_findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        representatives = []
        for cwe_id, findings in grouped_findings.items():
            if findings:
                representatives.append({
                    "cwe": cwe_id,
                    "endpoint": findings[0]["endpoint"],
                    "risk": findings[0]["risk"]
                })
        return representatives

    def create_ai_prompt(self) -> str:
        grouped_findings = self.group_findings_by_cwe()
        summary = self.generate_summary(grouped_findings)
        representative_findings = self.generate_representative_findings(grouped_findings)
        structured_json = json.dumps(representative_findings, indent=2)

        prompt = (
            f"{summary}\n\n"
            f"These are example findings from a web app. Provide **server-side remediation suggestions per CWE**:\n"
            f"{structured_json}\n"
        )
        return prompt

    def get_ai_suggestions(self, allow_ai: bool = True) -> str:
        if not allow_ai or not OPENAI_AVAILABLE:
            logger.info("AI suggestions skipped (disabled or unavailable).")
            return "AI suggestion skipped — disabled or unavailable."

        prompt = self.create_ai_prompt()
        logger.info("Generated AI prompt for remediation suggestions.")

        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a security expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
            )
            return response.choices[0].message.content.strip()
        except openai.OpenAIError as e:
            logger.warning(f"AI suggestion skipped due to OpenAI error: {e}")
            return "AI suggestion skipped due to OpenAI API error."
        except Exception as e:
            logger.warning(f"AI suggestion skipped due to unexpected error: {e}")
            return "AI suggestion skipped due to unexpected error."

def generate_dast_remediation_plan(ffuf_results, nuclei_results, dastardly_results=None) -> dict:
    try:
        suggester = AISuggestionGenerator(
            ffuf_findings=ffuf_results,
            dastardly_findings=dastardly_results or [],
            nuclei_findings=nuclei_results
        )
        ai_prompt = suggester.get_ai_suggestions(allow_ai=allow_ai)
        grouped = suggester.group_findings_by_cwe()
        return {
            "prompt": ai_prompt,
            "grouped_by_cwe": grouped
        }
    except Exception as e:
        logger.error(f"Error generating AI remediation plan: {e}")
        return {}

# Example standalone use
if __name__ == "__main__":
    ffuf = [{"url": "/login.jsp", "cwe_id": "CWE-79"}]
    dast = [{"url": "/search.jsp", "cwe_id": "CWE-79"}]
    nuclei = [{"matched_url": "/download?file=../../etc/passwd", "cwe": "CWE-22", "description": "Path traversal"}]

    try:
        gen = AISuggestionGenerator(ffuf, dast, nuclei)
        print(gen.get_ai_suggestions())
    except Exception as ex:
        logger.error(f"Example test failed: {ex}")
