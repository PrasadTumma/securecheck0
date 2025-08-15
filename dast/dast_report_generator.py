import json
import logging
from datetime import datetime
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader
import os
from typing import List, Dict, Any
from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sanitize_text(text: str) -> str:
    """Sanitize Unicode characters to avoid PDF encoding issues."""
    if not isinstance(text, str):
        return str(text)
    return (text.replace("’", "'")
                .replace("“", '"')
                .replace("”", '"')
                .replace("–", "-")
                .replace("—", "-")
                .replace("\u2028", " ")
                .replace("\u2029", " ")
                .encode("latin-1", errors="replace")
                .decode("latin-1"))

class ReportGenerator:
    def __init__(self, findings: List[Dict[str, Any]], ai_remediation: Dict[str, Any], output_dir: str = "reports"):
        self.findings = self.deduplicate_findings(findings)
        self.ai_remediation = ai_remediation
        self.output_dir = output_dir
        self.metadata = {
            "timestamp": datetime.now().isoformat(),
            "tool_versions": {
                "ffuf": "1.4.0",
                "dastardly": "0.1.0",
                "nuclei": "3.4.7"
            }
        }
        os.makedirs(self.output_dir, exist_ok=True)

    def deduplicate_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in raw_findings:
            key = (f.get("tool"), f.get("endpoint"), f.get("vulnerability"))
            if key not in seen:
                seen.add(key)

                cwe_id = f.get("cwe_id") or ""
                vuln_name = f.get("vulnerability") or ""
                description = f.get("description") or ""

                static_fix = get_static_fix(cwe_id=cwe_id, vuln_name=vuln_name, description=description)

                deduped.append({
                    "tool": f.get("tool"),
                    "endpoint": f.get("endpoint"),
                    "status_code": f.get("status_code"),
                    "vulnerability": vuln_name or "Unspecified",
                    "cwe_id": cwe_id or "Unknown",
                    "severity": f.get("severity", "LOW").upper(),
                    "static_fix": static_fix
                })
        logger.info(f"Deduplicated findings to {len(deduped)} unique entries.")
        return deduped


    def generate_json_report(self) -> str:
        report_data = {
            "metadata": self.metadata,
            "findings": self.findings,
            "ai_remediation": self.ai_remediation
        }
        json_path = os.path.join(self.output_dir, "report.json")
        with open(json_path, 'w', encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        logger.info(f"JSON report written to: {json_path}")
        return json_path

    def generate_html_report(self) -> str:
        try:
            env = Environment(loader=FileSystemLoader('templates'))
            template = env.get_template('dast_report_template.html')
            html_content = template.render(
                report={
                    "timestamp": self.metadata["timestamp"],
                    "tool_versions": self.metadata["tool_versions"],
                    "findings": self.findings,
                    "ai_remediation": self.ai_remediation,
                    "ai_enabled": bool(self.ai_remediation),
                    "fix_verified": "Not Applicable",
                    "source_code": "DAST Scan - Dynamic URLs"
                }
            )
            html_path = os.path.join(self.output_dir, "report.html")
            with open(html_path, 'w', encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report generated at {html_path}")
            return html_path
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            return ""

    def generate_pdf_report(self) -> str:
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, 'DAST Findings Report', ln=True, align='C')
            pdf.set_font("Arial", 'I', 12)
            pdf.cell(0, 10, f"Generated on: {self.metadata['timestamp']}", ln=True)

            for tool, version in self.metadata['tool_versions'].items():
                pdf.cell(0, 10, f"{tool} version: {version}", ln=True)

            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, 'Findings', ln=True)
            pdf.set_font("Arial", '', 12)

            for finding in self.findings:
                try:
                    pdf.cell(0, 10, sanitize_text(f"[{finding['severity']}] {finding['cwe_id']} — {finding['vulnerability']}"), ln=True)
                    pdf.cell(0, 10, sanitize_text(f"Tool: {finding.get('tool')}"), ln=True)
                    pdf.cell(0, 10, sanitize_text(f"Endpoint: {finding.get('endpoint')}"), ln=True)
                    if finding.get("static_fix"):
                        pdf.multi_cell(0, 10, f"Static Fix: {sanitize_text(finding['static_fix'])}")
                    pdf.cell(0, 10, "", ln=True)
                except Exception as e:
                    logger.warning(f"Skipped one finding due to error: {e}")

            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, 'AI Remediation Suggestions', ln=True)
            pdf.set_font("Arial", '', 12)
            for cwe_id, suggestions in self.ai_remediation.items():
                try:
                    pdf.cell(0, 10, sanitize_text(f"CWE ID: {cwe_id}"), ln=True)
                    for suggestion in suggestions:
                        remediation = suggestion.get("remediation") or suggestion.get("risk") or "Not provided"
                        pdf.multi_cell(0, 10, f"Remediation: {sanitize_text(remediation)}")
                    if cwe_id.startswith("CWE-"):
                        cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"
                        pdf.set_text_color(0, 0, 255)
                        pdf.set_font("Arial", 'U', 12)
                        pdf.cell(0, 10, f"More Info: {cwe_url}", ln=True, link=cwe_url)
                        pdf.set_text_color(0, 0, 0)
                        pdf.set_font("Arial", '', 12)
                    pdf.cell(0, 10, "", ln=True)
                except Exception as e:
                    logger.warning(f"Skipped AI remediation block: {e}")

            pdf_path = os.path.join(self.output_dir, "report.pdf")
            pdf.output(pdf_path)
            logger.info(f"PDF report generated at {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return ""

    def generate_reports(self) -> None:
        self.generate_json_report()
        self.generate_html_report()
        self.generate_pdf_report()
        logger.info("All DAST reports generated.")

def generate_dast_report(ffuf_results, nuclei_results, dastardly_results, ai_remediation):
    try:
        findings = []

        # FFUF: no vuln name, no CWE — just feed URL as fallback input
        for result in ffuf_results:
            findings.append({
                "tool": "ffuf",
                "endpoint": result.get("url"),
                "status_code": result.get("status"),
                "vulnerability": "Unspecified",
                "cwe_id": None,
                "severity": "LOW",
                "description": result.get("url"),
            })

        # Nuclei
        for result in nuclei_results:
            cwe_id = result.get("cwe_id") or ""
            vuln_name = result.get("name") or result.get("description", "")
            findings.append({
                "tool": "nuclei",
                "endpoint": result.get("matched_url") or result.get("url"),
                "status_code": None,
                "vulnerability": vuln_name,
                "cwe_id": cwe_id or "Unknown",
                "severity": result.get("severity", "LOW").upper(),
                "description": result.get("description", ""),
            })

        # Dastardly
        for result in dastardly_results or []:
            cwe_id = result.get("cwe_id") or ""
            vuln = result.get("vulnerability") or result.get("description", "")
            findings.append({
                "tool": "dastardly",
                "endpoint": result.get("endpoint"),
                "status_code": None,
                "vulnerability": vuln,
                "cwe_id": cwe_id or "Unknown",
                "severity": result.get("severity", "LOW").upper(),
                "description": result.get("description", ""),
            })

        report_generator = ReportGenerator(findings, ai_remediation)
        report_generator.generate_reports()
        return {
            "metadata": report_generator.metadata,
            "findings": report_generator.findings,
            "ai_remediation": ai_remediation
        }

    except Exception as e:
        logger.error(f"generate_dast_report error: {e}")
        return {
            "metadata": {"timestamp": datetime.now().isoformat()},
            "findings": [],
            "ai_remediation": {}
        }
