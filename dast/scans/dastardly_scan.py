import subprocess
import json
import logging
import os
import socket
from urllib.parse import urlparse
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def translate_localhost_url(user_url: str) -> str:
    parsed = urlparse(user_url)
    if parsed.hostname in ["localhost", "127.0.0.1"]:
        new_host = "host.docker.internal" if is_docker_internal_reachable() else "172.17.0.1"
        return user_url.replace(parsed.hostname, new_host)
    return user_url

def is_docker_internal_reachable() -> bool:
    try:
        socket.gethostbyname("host.docker.internal")
        return True
    except socket.error:
        return False

def extract_valid_start_url(har_path: str) -> str:
    try:
        with open(har_path, 'r') as f:
            har_data = json.load(f)
            entries = har_data.get("log", {}).get("entries", [])
            for entry in entries:
                url = entry.get("request", {}).get("url", "")
                if not url.startswith("http"):
                    continue
                if "login" in url.lower() or "auth" in url.lower():
                    continue
                response = entry.get("response", {})
                status = response.get("status", 0)
                if 300 <= status < 400:
                    continue
                return url
    except Exception as e:
        logger.warning(f"Failed to extract valid BURP_START_URL from HAR: {str(e)}")
    return ""

def extract_findings_from_dastardly_report(html_path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        if not os.path.exists(html_path):
            return findings

        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        import re
        pattern = re.compile(r"Path: (.*?) Issue Type: (.*?) Severity: (.*?)", re.IGNORECASE)
        matches = pattern.findall(content)

        for path, vuln, severity in matches:
            findings.append({
                "endpoint": path.strip(),
                "vulnerability": vuln.strip(),
                "cwe_id": "CWE-79" if "xss" in vuln.lower() else "Unknown",
                "severity": severity.strip()
            })
    except Exception as e:
        logger.warning(f"Failed to parse Dastardly HTML report: {str(e)}")
    return findings

class DastardlyScanner:
    def __init__(self, traffic_file: str, report_dir: str, base_url: str):
        """
        Initialize the Dastardly scanner with the traffic file and target base URL.
        
        :param traffic_file: The HAR file containing the traffic.
        :param report_dir: The directory to save reports.
        :param base_url: The base URL to scan.
        """
        self.traffic_file = os.path.realpath(traffic_file)
        self.report_dir = os.path.realpath(report_dir)
        self.base_url = base_url  # Will be dynamically picked later
        self.report_file_path = os.path.join(self.report_dir, "dastardly-report.html")
        self.json_report_path = os.path.join(self.report_dir, "dastardly_report.json")
        self.findings: List[Dict[str, Any]] = []

    def run_dastardly(self) -> None:
        try:
            logger.info(f"Running Dastardly scan on {self.base_url} using traffic file: {self.traffic_file}")
            os.makedirs(self.report_dir, exist_ok=True)

            if not os.path.exists(self.traffic_file):
                raise FileNotFoundError(f"HAR file not found: {self.traffic_file}")

            start_url = extract_valid_start_url(self.traffic_file)
            if not start_url:
                raise ValueError("No valid BURP_START_URL found in HAR. Scan aborted.")
            start_url = translate_localhost_url(start_url)

            command = [
                "docker", "run", "--rm",
                "-v", f"{self.report_dir}:/dastardly/reports",
                "-v", f"{self.traffic_file}:/dastardly/input/traffic.har",
                "-e", f"BURP_START_URL={start_url}",
                "-e", "BURP_REPORT_FILE_PATH=/dastardly/reports/dastardly-report.html",
                "public.ecr.aws/portswigger/dastardly"
            ]

            subprocess.run(command, check=True)
            logger.info("Dastardly scan completed.")

            subprocess.run(["docker", "rmi", "-f", "public.ecr.aws/portswigger/dastardly"], check=False)

            self.findings = extract_findings_from_dastardly_report(self.report_file_path)
            self.create_placeholder_json_report()

        except subprocess.CalledProcessError as e:
            logger.error(f"Dastardly Docker execution failed: {e}")
            self.create_placeholder_json_report(success=False, error=str(e))
        except Exception as e:
            logger.error(f"Dastardly general error: {e}")
            self.create_placeholder_json_report(success=False, error=str(e))

    def create_placeholder_json_report(self, success=True, error: str = "") -> None:
        try:
            result = {
                "tool": "dastardly",
                "status": "completed" if success else "failed",
                "report_link": self.report_file_path if success else "",
                "error": error,
                "findings": self.findings
            }
            with open(self.json_report_path, 'w') as json_file:
                json.dump(result, json_file, indent=4)
            logger.info(f"JSON placeholder written to: {self.json_report_path}")
        except Exception as e:
            logger.error(f"Failed to write JSON placeholder: {str(e)}")

# Example usage
if __name__ == "__main__":
    traffic_file = "har_upload/traffic.har"
    report_directory = "reports"
    base_url = "http://localhost:3000"  # fallback only

    try:
        dastardly_scanner = DastardlyScanner(traffic_file, report_directory, base_url)
        dastardly_scanner.run_dastardly()
    except Exception as e:
        logger.error(f"DAST Dastardly scan failed: {e}")
