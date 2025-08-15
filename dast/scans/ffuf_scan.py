import subprocess
import json
import logging
import os
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dynamically resolve path to wordlist relative to this script
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "SecLists", "Discovery", "Web-Content", "common.txt")

def ensure_seclists():
    """
    Ensure SecLists exists locally. If not found, clone it automatically.
    Checks both the script directory and /usr/share/seclists.
    """
    local_path = os.path.join(os.path.dirname(__file__), "SecLists")
    system_path = "/usr/share/seclists"

    if os.path.exists(local_path) or os.path.exists(system_path):
        logger.info("[*] SecLists found.")
        return

    logger.info("[*] SecLists not found. Downloading...")
    try:
        subprocess.run([
            "git", "clone", "--depth=1",
            "https://github.com/danielmiessler/SecLists.git",
            local_path
        ], check=True)
        logger.info("[*] SecLists successfully downloaded.")
    except Exception as e:
        logger.error(f"Failed to download SecLists: {e}")
        raise RuntimeError("SecLists installation failed, FFUF scan cannot proceed.")

class FFUFScanner:
    WORDLISTS = [
        os.path.join(os.path.dirname(__file__), "SecLists", "Discovery", "Web-Content", "common.txt"),
        os.path.join(os.path.dirname(__file__), "SecLists", "Discovery", "Web-Content", "admin-panels.txt"),
        os.path.join(os.path.dirname(__file__), "SecLists", "Discovery", "Web-Content", "api", "api-endpoints.txt"),
        os.path.join(os.path.dirname(__file__), "SecLists", "Discovery", "Web-Content", "raft-large-files.txt"),
    ]
    def __init__(self, url: str, wordlist: str = None):
        """
        Initialize the FFUF scanner with the target URL and optional wordlist.
        
        :param url: The URL to scan.
        :param wordlist: The path to the wordlist file.
        """
        # Ensure Seclists is available before continuing
        ensure_seclists()

        self.url = self._sanitize_url(url)
        self.wordlist = wordlist or self.get_default_wordlist()
        self.output_file = "ffuf_output.json"

    def get_default_wordlist(self) -> str:
        """Return the path to the default wordlist."""
        if os.path.exists(DEFAULT_WORDLIST):
            return DEFAULT_WORDLIST
        fallback = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if os.path.exists(fallback):
            return fallback
        logger.error("No valid wordlist found.")
        raise FileNotFoundError("No default wordlist available.")

    def _sanitize_url(self, url: str) -> str:
        """Ensure the base URL is clean and doesn't end with a trailing / or /FUZZ."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    def run_ffuf(self) -> List[Dict[str, Any]]:
        """Run FFUF and return parsed valid endpoints."""
        all_endpoints = []
        for wordlist_path in self.WORDLISTS:
            if not os.path.exists(wordlist_path):
                logger.warning(f"Skipping missing wordlist: {wordlist_path}")
                continue

            logger.info(f"Running FFUF on: {self.url} using wordlist {os.path.basename(wordlist_path)}")
            command = [
                "ffuf",
                "-u", f"{self.url}/FUZZ",
                "-w", wordlist_path,
                "-o", self.output_file,
                "-of", "json",
                "-t", "50",
                "-rate", "150",
                "-timeout", "10",
                "-mc", "200,204,301,302,403",
                "-fc", "404",
                "-ac",
                "-recursion",
                "-H", "User-Agent: Mozilla/5.0",
                "-H", "X-Forwarded-For: 127.0.0.1"
            ]

            try:
                subprocess.run(command, check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"FFUF failed on wordlist {wordlist_path}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error running FFUF: {e}")
                continue

            endpoints = self.parse_ffuf_output(self.output_file)
            all_endpoints.extend(endpoints)

        # Deduplicate
        unique = {entry["url"]: entry for entry in all_endpoints}.values()
        logger.info(f"Total unique FFUF endpoints discovered: {len(unique)}")
        return list(unique)

    def parse_ffuf_output(self, filename: str) -> List[Dict[str, Any]]:
        if not os.path.exists(filename):
            logger.warning(f"No FFUF output found at: {filename}")
            return []

        try:
            with open(filename, 'r') as f:
                results = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse FFUF output: {e}")
            return []

        valid = []
        seen = set()
        for result in results.get("results", []):
            url = result.get("url")
            status = result.get("status")
            length = result.get("length", 0)

            if length <= 10 or url in seen:
                continue
            seen.add(url)

            valid.append({
                "tool": "ffuf",
                "url": url,
                "status": status,
                "length": length,
                "words": result.get("words"),
                "lines": result.get("lines"),
                "redirect": result.get("redirectlocation", ""),
                "input": result.get("input", {}),
                "cwe_id": None  # PATCHED: to prevent AI module from rejecting the entry
            })

        logger.info(f"FFUF discovered {len(valid)} valid endpoints from this run.")
        return valid

# Example usage
if __name__ == "__main__":
    try:
        scanner = FFUFScanner("http://testphp.vulnweb.com")
        endpoints = scanner.run_ffuf()
        print(json.dumps(endpoints, indent=2))
    except Exception as e:
        logger.error(f"DAST FFUF scan failed: {e}")

