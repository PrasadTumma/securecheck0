from openai import OpenAI, OpenAIError, AuthenticationError, RateLimitError
import os
import logging
from sast.sast_confidence import ConfidenceLevel

# Configure logger
logger = logging.getLogger(__name__)

# Environment toggle
AI_ENABLED = os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes"
processed_lines = set()  # Track processed lines to avoid repeated requests

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
logger.info(f"OPENAI API KEY LOADED: {bool(client.api_key)}")

class AISuggestion:
    def __init__(self, vulnerability_info):
        """
        Initialize with vulnerability information.
        :param vulnerability_info: Dictionary containing details about the vulnerability.
        """
        self.vulnerability_info = vulnerability_info

    def extract_context(self, code: str, window: int = 3) -> str:
        """Extract context lines around the vulnerable line."""
        try:
            line_number = self.vulnerability_info.get("line_number")
            if not line_number:
                logger.warning("Line number not provided.")
                return None

            lines = code.splitlines()
            start = max(0, line_number - window - 1)
            end = min(len(lines), line_number + window)
            return "\n".join(lines[start:end]).strip()
        except Exception as e:
            logger.error(f"Error extracting context: {e}")
            return None

    def get_ai_suggestion(self, context: str) -> str:
        """Call OpenAI API to generate a suggestion based on context."""
        try:
            prompt = (
                "You are a secure code assistant. Analyze the following code "
                "and suggest a secure fix for any vulnerability:\n\n"
                f"{context}\n\n"
                "Respond only with the fixed code. Do not include explanations or repeated context."
            )

            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=300
            )

            return response.choices[0].message.content.strip()

        except AuthenticationError:
            raise RuntimeError("AI suggestion failed: Invalid or missing OpenAI API key.")
        except RateLimitError:
            raise RuntimeError("AI suggestion failed: Rate limit or quota exhausted.")
        except OpenAIError as e:
            raise RuntimeError(f"AI suggestion failed: {e}")

    def generate_suggestion(self, code: str) -> dict:
        """Generate suggestion for the given code and vulnerability."""
        line_number = self.vulnerability_info.get("line_number")

        if not AI_ENABLED:
            return {
                "suggestion": "",
                "confidence_level": "N/A",
                "note": "AI suggestion disabled by user environment toggle."
            }

        if line_number in processed_lines:
            return {
                "suggestion": "",
                "confidence_level": "duplicate",
                "note": f"Line {line_number} already processed for AI."
            }

        context = self.extract_context(code)
        if not context:
            return {
                "suggestion": "",
                "confidence_level": "N/A",
                "note": "Insufficient context for suggestion."
            }

        suggestion = self.get_ai_suggestion(context)
        processed_lines.add(line_number)

        # Ensure fallback if cwe_id is missing
        vuln_for_confidence = {
            "cwe_id": self.vulnerability_info.get("cwe_id") or "N/A",
            "description": self.vulnerability_info.get("description") or "Unknown issue",
            "line_number": self.vulnerability_info.get("line_number"),
            "context": context
        }

        confidence_checker = ConfidenceLevel(vuln_for_confidence, suggestion)
        confidence_result = confidence_checker.compute_confidence()

        return {
            "vulnerability": self.vulnerability_info,
            "suggestion": suggestion,
            "confidence_level": confidence_result.get("confidence_level", "Unknown")
        }

def apply_fix(original_code: str, suggestion_result: dict, line_number: int) -> str:
    """Inserts the suggestion as a comment into the source code."""
    try:
        if not line_number or "suggestion" not in suggestion_result:
            return original_code

        lines = original_code.splitlines()
        idx = int(line_number) - 1

        if 0 <= idx < len(lines):
            fix_lines = [f"# {line}" for line in suggestion_result["suggestion"].splitlines()]
            comment_block = ["# Suggested Fix:"] + fix_lines
            lines = lines[:idx] + comment_block + lines[idx:]
            return "\n".join(lines)
        else:
            return original_code
    except Exception as e:
        logger.error(f"Error applying fix: {e}")
        return original_code
