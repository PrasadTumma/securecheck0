import subprocess
import json
import logging
import shutil
import os
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_eslint(file_path: str) -> List[Dict]:
    """
    Run ESLint on the specified JavaScript file and return normalized findings.
    
    :param file_path: Path to the JavaScript file to analyze.
    :return: A list of normalized findings.
    """
    try:
        if shutil.which("eslint") is None:
            logger.error("ESLint is not installed or not in PATH.")
            return []

        # Define the ESLint command with JSON output
        eslint_command = ["eslint", file_path, "--format", "json"]
        logger.info(f"Running ESLint on {file_path}")

        # Run ESLint and capture stdout
        result = subprocess.run(eslint_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode not in (0, 1):  # ESLint exits with 1 on lint errors, not a crash
            logger.error(f"ESLint failed: {result.stderr}")
            return []

        raw_output = result.stdout
        results = json.loads(raw_output)

        severity_map = {
            1: "MEDIUM",
            2: "HIGH"
        }

        findings = []
        for file_result in results:
            for message in file_result.get("messages", []):
                severity_level = message.get("severity", 1)
                finding = {
                    "line": message.get("line"),
                    "message": message.get("message"),
                    "title": message.get("message"),
                    "cwe_id": message.get("ruleId", None),
                    "tool": "Eslint",
                    "severity": severity_map.get(severity_level, "Unknown"),
                    "fix": {"fix": "No static fix found for this issue."}
                }
                findings.append(finding)

        logger.info(f"ESLint findings for {file_path}: {findings}")
        return findings

    except json.JSONDecodeError:
        logger.error("Failed to decode ESLint output as JSON.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while running ESLint: {str(e)}")
        return []

# Example usage
if __name__ == "__main__":
    test_file = "example.js"  # Replace with your JS test file
    results = run_eslint(test_file)
    print(json.dumps(results, indent=4))
