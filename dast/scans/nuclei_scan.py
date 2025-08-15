import subprocess
import json
import logging
import os
from typing import List, Dict, Any
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        NUCLEI_TEMPLATE_PATH = os.path.expanduser(config.get("nuclei_templates_path", "~/nuclei-templates"))
except Exception:
    NUCLEI_TEMPLATE_PATH = os.path.expanduser("~/nuclei-templates")
    logger.warning(f"Could not load config.json. Using fallback: {NUCLEI_TEMPLATE_PATH}")

def has_templates(path: str) -> bool:
    for root, _, files in os.walk(path):
        if any(f.endswith(".yaml") for f in files):
            return True
    return False

class NucleiScanner:
    def __init__(self, endpoints: List[str]):
        self.endpoints = sorted(set(ep.strip() for ep in endpoints if ep.startswith("http")))
        self.output_file = "nuclei_output.jsonl"

    @classmethod
    def from_har(cls, har_path: str) -> "NucleiScanner":
        endpoints = []
        try:
            with open(har_path, "r") as f:
                har_data = json.load(f)
                entries = har_data.get("log", {}).get("entries", [])
                for entry in entries:
                    url = entry.get("request", {}).get("url", "").strip()
                    if url.startswith("http"):
                        endpoints.append(url)
            logger.info(f"Extracted {len(endpoints)} URLs from HAR file.")
        except Exception as e:
            logger.error(f"Failed to parse HAR file for Nuclei: {str(e)}")
        return cls(endpoints)

    def run_nuclei(self) -> List[Dict[str, Any]]:
        if not self.endpoints:
            logger.warning("No endpoints provided for Nuclei scan.")
            return []

        if not os.path.isdir(NUCLEI_TEMPLATE_PATH) or not has_templates(NUCLEI_TEMPLATE_PATH):
            logger.warning(f"No valid Nuclei templates found in: {NUCLEI_TEMPLATE_PATH}")
            return []

        logger.info(f"Running Nuclei scan on {len(self.endpoints)} endpoints...")

        try:
            temp_file = self._write_temp_endpoint_file()
            command = [
                "nuclei",
                "-list", temp_file,
                "-t", NUCLEI_TEMPLATE_PATH,
                "-jsonl",
                "-o", self.output_file,
                "-severity", "info,low,medium,high,critical",
                "-c", "50",
                "-retries", "5",
                "-timeout", "30",
                "-rate-limit", "100",
                "-ni",
                "-H", "User-Agent: Mozilla/5.0",
            ]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Nuclei returned non-zero exit status {result.returncode}")
                logger.error(f"STDERR:\n{result.stderr}")
                return []

            return self.parse_nuclei_output()
        except Exception as e:
            logger.error(f"Unexpected error running Nuclei: {str(e)}")
            return []

    def _write_temp_endpoint_file(self) -> str:
        try:
            temp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt")
            for ep in self.endpoints:
                temp.write(ep + "\n")
            temp.close()
            return temp.name
        except Exception as e:
            logger.error(f"Failed to write temp endpoint file: {str(e)}")
            raise

    def parse_nuclei_output(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(self.output_file, 'r') as f:
                for line in f:
                    result = json.loads(line)
                    info = result.get("info", {})
                    classification = info.get("classification", {})
                    findings.append({
                        "template_id": result.get("templateID"),
                        "name": info.get("name"),
                        "description": info.get("description", ""),
                        "severity": info.get("severity", "unknown").upper(),
                        "cve": classification.get("cve", []),
                        "cwe_id": classification.get("cweId", ""),  # Use cwe_id consistently
                        "cwe": classification.get("cweId", ""),     # Keep legacy for safety
                        "matched_url": result.get("matched"),       # Needed for report generator
                        "url": result.get("matched"),
                        "host": result.get("host"),
                        "timestamp": result.get("timestamp")
                    })

            logger.info(f"Nuclei scan complete. {len(findings)} findings parsed.")
            return findings
        except Exception as e:
            logger.error(f"Error parsing nuclei results: {str(e)}")
            return []

# Example usage
if __name__ == "__main__":
    har_path = "har_upload/traffic.har"
    scanner = NucleiScanner.from_har(har_path)
    results = scanner.run_nuclei()
    print(json.dumps(results, indent=2))

