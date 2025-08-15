import subprocess
import json
import os
import logging
import shutil
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_bandit(file_path: str) -> List[Dict]:
    """
    Run Bandit on the specified Python file and return normalized findings.
    
    :param file_path: Path to the Python file to analyze.
    :return: A list of normalized findings.
    """
    try:
        if shutil.which("bandit") is None:
            logger.error("Bandit is not installed.")
            return []

        # Define the Bandit command
        bandit_command = ["bandit", "-f", "json", "-q", file_path]

        # Run the Bandit command
        logger.info(f"Running Bandit on {file_path}")
        result = subprocess.run(bandit_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if result.returncode not in (0, 1):  # 0 = no findings, 1 = findings found
            logger.warning(f"Bandit exited with code {result.returncode}. stderr: {result.stderr.strip()}")
            return []

        return parse_bandit_output(result.stdout)

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running Bandit on {file_path}: {e.stderr}")
        return []
    except json.JSONDecodeError:
        logger.error("Failed to decode Bandit output as JSON.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while running Bandit: {str(e)}")
        return []

def parse_bandit_output(output: str) -> List[Dict]:
    """
    Parse the output from Bandit and return a list of normalized findings.
    
    :param output: The raw output from Bandit.
    :return: A list of normalized findings.
    """
    findings = []
    try:
        # Load the output as JSON
        data = json.loads(output)
        for item in data.get("results", []):
            findings.append ({
                "line": item.get("line_number"),
                "message": item.get("issue_text", "No message provided"),
                "cwe_id": f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else None,  # Assuming Bandit provides CWE IDs
                "tool": "Bandit",
                "severity": item.get("severity", "LOW").lower()  # Normalize severity
            })
            
    except json.JSONDecodeError:
        logger.error("Failed to decode Bandit output as JSON.")
    except Exception as e:
        logger.error(f"Error parsing Bandit output: {str(e)}")

    return findings

# Example usage
if __name__ == "__main__":
    test_file = "example.py"  # Replace with your test file path
    results = run_bandit(test_file)
    print(json.dumps(results, indent=4))
