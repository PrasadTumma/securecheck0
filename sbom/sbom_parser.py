import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SBOMParser:
    def __init__(self, syft_data: Dict, grype_data: Dict):
        """
        Initialize with Syft and Grype data.
        
        :param syft_data: Raw JSON output from Syft
        :param grype_data: Raw JSON output from Grype
        """
        self.syft_data = syft_data
        self.grype_data = grype_data
        self.timestamp = datetime.now().isoformat()
 
    def _parse_component(self, component: Dict) -> Optional[Dict]:
        name = component.get("name", "").strip()
        if not name or name == "unknown":
            return None  # Skip invalid components
        return {
            "name": name,
            "version": component.get("version", "unknown"),
            "type": component.get("type", "unknown"),
            "purl": component.get("purl"),
            "locations": [loc.get("path", "unknown") for loc in component.get("locations", [])]
        }

    def _parse_vulnerability(self, match: Dict) -> Dict:
        vuln_info = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vuln_id = vuln_info.get("id", "unknown")
        severity = vuln_info.get("severity", "unknown").upper()
        return {
            "vulnerability_id": vuln_id,
            "severity": severity,
            "description": vuln_info.get("description", "No description available"),
            "cvss_score": self._get_cvss_score(vuln_info),
            "affected_package": artifact.get("name", "unknown"),
            "version": artifact.get("version", "unknown"),
            "fix_versions": vuln_info.get("fix", {}).get("versions", []),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        }

    def _get_cvss_score(self, vuln_info: Dict) -> Optional[float]:
        try:
            cvss_list = vuln_info.get("metrics", {}).get("cvss", [])
            if isinstance(cvss_list, list) and len(cvss_list) > 0:
                best = sorted(cvss_list, key=lambda x: x.get("score", 0), reverse=True)[0]
                return float(best.get("score"))
            return None
        except Exception as e:
            logger.warning(f"Error extracting CVSS score: {str(e)}")
            return None

    def _map_vulnerabilities_to_components(self) -> Dict[str, List[Dict]]:
        mapping = {}
        for match in self.grype_data.get("matches", []):
            artifact = match.get("artifact", {})
            key = artifact.get("purl") or artifact.get("name")
            if not key:
                continue
            if key not in mapping:
                mapping[key] = []
            mapping[key].append(self._parse_vulnerability(match))
        return mapping

    def parse(self) -> Dict:
        try:
            parsed = {
                "metadata": {
                    "timestamp": self.timestamp,
                    "tool_versions": {
                        "syft": self.syft_data.get("descriptor", {}).get("version", "unknown"),
                        "grype": self.grype_data.get("descriptor", {}).get("version", "unknown")
                    },
                    "target": self.syft_data.get("source", {}).get("target", {})
                },
                "components": [],
                "vulnerabilities": [],
                "summary": {}
            }

            component_vulns = self._map_vulnerabilities_to_components()
            all_components = self.syft_data.get("artifacts", [])

            for raw_comp in all_components:
                comp = self._parse_component(raw_comp)
                if not comp:
                    continue
                key = comp.get("purl") or comp.get("name")
                comp["vulnerabilities"] = component_vulns.get(key, [])
                parsed["components"].append(comp)

            for vuln_list in component_vulns.values():
                parsed["vulnerabilities"].extend(vuln_list)

            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            parsed["vulnerabilities"].sort(key=lambda v: severity_rank.get(v["severity"], 99))
            parsed["components"].sort(key=lambda c: c["name"].lower())

            parsed["summary"] = {
                "total_components": len(parsed["components"]),
                "total_vulnerabilities": len(parsed["vulnerabilities"]),
                "critical": sum(1 for v in parsed["vulnerabilities"] if v["severity"] == "CRITICAL"),
                "high": sum(1 for v in parsed["vulnerabilities"] if v["severity"] == "HIGH"),
                "medium": sum(1 for v in parsed["vulnerabilities"] if v["severity"] == "MEDIUM"),
                "low": sum(1 for v in parsed["vulnerabilities"] if v["severity"] == "LOW")
            }

            return parsed
        except Exception as e:
            logger.error(f"Error parsing SBOM data: {str(e)}")
            return {
                "error": f"Failed to parse SBOM data: {str(e)}",
                "timestamp": self.timestamp
            }

# Example usage
if __name__ == "__main__":
    with open("syft_output.json") as f:
        syft_data = json.load(f)

    with open("grype_output.json") as f:
        grype_data = json.load(f)

    parser = SBOMParser(syft_data, grype_data)
    parsed_report = parser.parse()
    print(json.dumps(parsed_report, indent=4))
