import subprocess
import json
import logging
import shutil
import os
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_semgrep(file_path: str, language: str) -> List[Dict]:
    """
    Run Semgrep on the specified file and return normalized findings.
    
    :param file_path: Path to the file to analyze.
    :param language: The programming language of the file.
    :return: A list of normalized findings.
    """
    try:
        if shutil.which("semgrep") is None:
            logger.error("Semgrep is not installed.")
            return []
        output_path = "semgrep_output.json"
        config_map = {
            "python": "p/ci",
            "java": "java",
            "javascript": "javascript",
            "js": "javascript",
            "html": "html",
            "csharp": "csharp",
            "cs": "csharp"
            }
        config = config_map.get(language.lower(), "auto")

        # Run the Semgrep command
        semgrep_command = ["semgrep", "scan", "--config", "auto", "--json", "--output", output_path, file_path]

        logger.info(f"Running Semgrep on {file_path} for language: {language}")
        subprocess.run(semgrep_command, check=True)

        if not os.path.exists(output_path):
            logger.error("Semgrep output file not created.")
            return []
        
        # Load and parse the output file
        with open(output_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        findings = []
        for result in raw.get("results", []):
            findings.append({
                "line": result.get("start", {}).get("line", 0),
                "message": result.get("extra", {}).get("message", "No message provided"),
                "cwe_id": result.get("extra", {}).get("metadata", {}).get("cwe", [None])[0],  # safe extraction
                "tool": "Semgrep",
                "severity": result.get("extra", {}).get("severity", "INFO").upper()
            })

        logger.info(f"Semgrep findings for {file_path}: {findings}")
        return findings

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running Semgrep on {file_path}: {e.stderr}")
        return []
    except json.JSONDecodeError:
        logger.error("Failed to decode Semgrep output as JSON.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while running Semgrep: {str(e)}")
        return []

def parse_semgrep_output(output: str) -> List[Dict]:
    """
    Parse the output from Semgrep and return a list of normalized findings.
    
    :param output: The raw output from Semgrep.
    :param language: The programming language of the file.
    :return: A list of normalized findings.
    """
    findings = []
    try:
        # Load the output as JSON
        data = json.loads(output)

        # Normalize findings
        for result in results.get("results", []):
            finding = {
                "line": result.get("start", {}).get("line"),
                "message": result.get("extra", {}).get("message", "No message provided"),
                "cwe_id": result.get("extra", {}).get("metadata", {}).get("cwe", None),
                "tool": "Semgrep",
                "severity": result.get("extra", {}).get("severity", "INFO").upper()  # Normalize severity
            }
            findings.append(finding)

    except Exception as e:
        logger.error(f"Error parsing Semgrep output: {str(e)}")

    return findings

# Example usage
if __name__ == "__main__":
    test_file = "example.py"  # Replace with your test file path
    results = run_semgrep(test_file, language="python")
    print(json.dumps(results, indent=4))
