import subprocess
import json
import os
import logging
import shutil
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_devskim(file_path: str) -> List[Dict]:
    """
    Run DevSkim on the specified file and return normalized findings.
    
    :param file_path: Path to the file to analyze.
    :return: A list of normalized findings.
    """
    try:
        if shutil.which("devskim") is None:
            logger.error("DevSkim is not installed or not in PATH.")
            return []

        # Define the DevSkim command
        output_path = "devskim_output.json"
        devskim_command = ["devskim", "analyze", "-I", file_path, "-f", "sarif", "-O", output_path]

        # Run the DevSkim command
        logger.info(f"Running DevSkim on {file_path}")
        subprocess.run(devskim_command, check=True)

        if not os.path.exists(output_path):
            logger.error("DevSkim output file not created.")
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
                "tool": "DevSkim",
                "severity": result.get("extra", {}).get("severity", "INFO").upper()
            })

        logger.info(f"DevSkim findings for {file_path}: {findings}")
        return findings

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running DevSkim on {file_path}: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode DevSkim output: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while running DevSkim: {str(e)}")
        return []

def parse_devskim_sarif(sarif_data: dict) -> List[Dict]:
    """
    Parse SARIF data from DevSkim and normalize it.
    
    :param sarif_data: Parsed SARIF JSON from DevSkim output.
    :return: A list of normalized findings.
    """
    findings = []
    try:
        runs = sarif_data.get("runs", [])
        if not runs:
            return []

        for run in runs:
            results = run.get("results", [])
            for result in results:
                message = result.get("message", {}).get("text", "No message provided")
                level = result.get("level", "warning").upper()
                locations = result.get("locations", [])
                line_number = None

                if locations:
                    region = locations[0].get("physicalLocation", {}).get("region", {})
                    line_number = region.get("startLine", None)

                # Get CWE ID if available
                rule_id = result.get("ruleId", "")
                cwe_id = None
                if "ruleIndex" in result:
                    try:
                        rule_index = result["ruleIndex"]
                        cwe_id = run["tool"]["driver"]["rules"][rule_index].get("properties", {}).get("problem.severity", None)
                    except Exception:
                        cwe_id = None

                findings.append({
                    "line": line_number,
                    "message": message,
                    "cwe_id": cwe_id,
                    "tool": "DevSkim",
                    "severity": level
                })

    except Exception as e:
        logger.error(f"Error parsing DevSkim SARIF output: {str(e)}")

    return findings

# Example usage
if __name__ == "__main__":
    test_file = "example.cs"  # Replace with your test file path
    results = run_devskim(test_file)
    print(json.dumps(results, indent=4))
