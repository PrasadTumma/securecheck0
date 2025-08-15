import logging
from typing import Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfidenceLevel:
    def __init__(self, vulnerability_info: Dict, suggestion_text: str):
        """
        Initialize with vulnerability information and AI-generated suggestion.
        """
        self.vuln = vulnerability_info
        self.suggestion = suggestion_text or ""

    
    def compute_confidence(self) -> Dict:
        """
        Compute confidence based on static heuristics.
        """
        try:
            score = 0
            explanation = []

            # Rule 1: CWE ID is present
            cwe = self.vuln.get("cwe_id")
            if cwe and isinstance(cwe, str) and "CWE" in cwe:
                score += 2
                explanation.append("CWE ID provided")

            # Rule 2: Trusted tools
            trusted_tools = ["Bandit", "SpotBugs", "Semgrep", "DevSkim"]
            if self.vuln.get("tool") in trusted_tools:
                score += 1
                explanation.append(f"Tool '{self.vuln.get('tool')}' is trusted")

            # Rule 3: Fix includes security terms
            keywords = ["sanitize", "validate", "escape", "parameter", "secure", "hash", "encrypt", "input"]
            if any(kw in self.suggestion.lower() for kw in keywords):
                score += 1
                explanation.append("Security keywords present in suggestion")

            # Rule 4: Long & informative suggestion
            if len(self.suggestion.splitlines()) >= 4:
                score += 1
                explanation.append("Suggestion includes detailed code")

            # Rule 5: CWE matches severity level (basic)
            if self.vuln.get("severity") == "error" and cwe:
                score += 1
                explanation.append("High severity aligned with CWE")

            # Rule 6: Fix includes contextual code
            if "{" in self.suggestion or "}" in self.suggestion or ";" in self.suggestion:
                score += 1
                explanation.append("Fix contains contextual syntax")

            # Final confidence assignment
            if score >= 5:
                level = "High"
            elif score >= 3:
                level = "Medium"
            else:
                level = "Low"

            return {
                "confidence_level": level,
                "score": score,
                "message": "; ".join(explanation)
            }

        except Exception as e:
            logger.error(f"Error computing heuristic confidence: {str(e)}")
            return {
                "confidence_level": "Unknown",
                "score": 0,
                "message": "Failed to compute confidence"
            }

# Example usage
if __name__ == "__main__":
    vuln_info = {
        "line_number": 18,
        "cwe_id": "CWE-89",
        "description": "Possible SQL injection",
        "tool": "Semgrep",
        "severity": "error"
    }

    suggestion_text = """
    # Suggested Fix:
    using (SqlConnection conn = new SqlConnection("..."))
    {
        SqlCommand cmd = new SqlCommand("...", conn);
        cmd.Parameters.AddWithValue("@user", userInput);
        ...
    }
    """

    checker = ConfidenceLevel(vuln_info, suggestion_text)
    result = checker.compute_confidence()
    print(result)