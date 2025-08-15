import json
import logging
import os
import html
from datetime import datetime
from typing import List, Dict, Optional
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader
import jsonschema
from jsonschema import validate
from pathlib import Path

from core.static_fix_resolver import get_static_fix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

report_schema = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "tool_versions": {"type": "object"},
        "findings": {"type": "array"},
        "fix_verified": {"type": "string"},
        "source_code": {"type": "string"},
        "ai_enabled": {"type": "boolean"}
    },
    "required": ["timestamp", "tool_versions", "findings", "fix_verified", "source_code"]
}

confidence_explanation_text = (
    "A Confidence Level Score is only established in case the Fix is AI Generated"
    "+2: CWE ID is present\n"
    "+1: Trusted tool (Bandit, Semgrep, SpotBugs, etc.)\n"
    "+1: Fix includes detailed code (>= 4 lines)\n"
    "+1: High severity aligned with CWE\n"
    "+1: Fix has contextual syntax (e.g., {{, }}, ;)\n\n"
    "Scores:\n0 - 2 : Low Confidence\n3 - 4 : Medium Confidence\n5 - 6 : High Confidence"
)

class ReportGenerator:
    def __init__(self, file_path: str, findings: List[Dict], fix_verified: bool,
                 tool_versions: Dict, logo_url: Optional[str] = None, source_code_path: Optional[str] = None):
        self.file_path = file_path
        self.logo_url = logo_url
        self.source_code_path = source_code_path
        self.findings = findings
        self.fix_verified = fix_verified
        self.tool_versions = self._filter_tool_versions(tool_versions)
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.source_code = ""

        if self.source_code_path:
            try:
                self.source_code = Path(self.source_code_path).read_text(encoding="utf-8")
            except Exception as e:
                self.source_code = f"Error reading source file: {e}"

    def _filter_tool_versions(self, versions: Dict) -> Dict:
        tools_used = set(f.get("tool", "").lower() for f in self.findings if f.get("tool"))
        return {k: v for k, v in versions.items() if k.lower() in tools_used}

    def generate_report(self) -> Dict:
        for finding in self.findings:
            cwe_id = finding.get("cwe_id", "")
            vuln_name = finding.get("vulnerability", {}).get("vulnerability_name", "")
            description = finding.get("message") or finding.get("vulnerability", {}).get("description", "")
            static_fix = get_static_fix(cwe_id=cwe_id, vuln_name=vuln_name, description=description)

            if "fixes" not in finding:
                finding["fixes"] = {}

            finding["fixes"]["static_fix"] = static_fix
            if "note" not in finding["fixes"]:
                finding["fixes"]["note"] = "Static fix inserted based on CWE or vulnerability name."

            # Preserve existing AI suggestion if any
            if "ai_suggestion" not in finding["fixes"]:
                finding["fixes"]["ai_suggestion"] = {}

        report = {
            "timestamp": self.timestamp,
            "tool_versions": self.tool_versions,
            "findings": self.findings,
            "fix_verified": self.fix_verified,
            "source_code": self.source_code,
            "ai_enabled": os.environ.get("ALLOW_AI_FIX", "yes").lower() == "yes"
        }
        self.validate_report(report)
        return report


    def validate_report(self, report: Dict):
        try:
            validate(instance=report, schema=report_schema)
            logger.info("Report validation successful.")
        except jsonschema.exceptions.ValidationError as e:
            logger.error(f"Report validation error: {e.message}")
            raise

    def export_to_json(self, report: Dict, output_path: str):
        try:
            with open(output_path, 'w', encoding="utf-8") as json_file:
                json.dump(report, json_file, indent=4)
            logger.info(f"Report exported to JSON at {output_path}.")
        except Exception as e:
            logger.error(f"Error exporting report to JSON: {str(e)}")

    def export_to_pdf(self, report: Dict, output_path: str):
        try:
            pdf = FPDF()
            pdf.add_page()

            logo_path = self.logo_url or "/home/avni/securecheck/ARIBL_LOGO.png"
            if os.path.exists(logo_path):
                pdf.image(logo_path, x=20, y=16, w=50)

            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "SecureCheck - Static Application Security Test Report", ln=True, align='C')
            pdf.set_font("Arial", size=11)
            pdf.cell(0, 10, f"Generated on: {report.get('timestamp', 'N/A')}", ln=True)

            pdf.ln(2)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "AI Suggestions Enabled: " + str(report.get("ai_enabled", False)), ln=True)

            source_code = report.get("source_code")
            if source_code:
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(0, 10, "Source Code Snippet:", ln=True)
                pdf.set_font("Courier", size=8)
                for line in source_code.splitlines()[:100]:
                    pdf.multi_cell(0, 4, line)
                if len(source_code.splitlines()) > 100:
                    pdf.cell(0, 5, "... (truncated)", ln=True)

            tool_versions = report.get("tool_versions")
            if tool_versions:
                pdf.ln(3)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(0, 10, "Tool Versions:", ln=True)
                pdf.set_font("Arial", size=11)
                for tool, version in tool_versions.items():
                    pdf.cell(0, 10, f"{tool}: {version}", ln=True)

            if "fix_verified" in report:
                pdf.ln(2)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(0, 10, f"Fix Verified: {report.get('fix_verified')}", ln=True)

            pdf.ln(2)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "Findings:", ln=True)
            pdf.set_font("Arial", size=9)

            findings = report.get("findings", [])
            for finding in findings:
                fixes = finding.get("fixes", {
                    "static_fix": "No static fix available.",
                    "ai_suggestion": {},
                    "note": "No fixes provided."
                })
                confidence = finding.get("confidence", {})

                line = finding.get("line", 'N/A')
                tool = finding.get("tool", 'N/A')
                severity = finding.get("severity", 'N/A')
                cwe_id = finding.get("cwe_id", 'N/A')

                vuln_data = finding.get("vulnerability", {})
                vuln_name = finding.get("vulnerability_name") or vuln_data.get("vulnerability_name", 'N/A')
                vuln_msg = finding.get("message") or vuln_data.get("description", '')

                fix_note = fixes.get("note", 'N/A')
                static_fix = fixes.get("static_fix") or 'No static fix found.'
                confidence_level = confidence.get("confidence_level", 'N/A')
                confidence_msg = confidence.get("message", '')

                pdf.multi_cell(0, 7,
                    f"Line: {line}\n"
                    f"Tool: {tool}\n"
                    f"Severity: {severity}\n"
                    f"CWE ID: {cwe_id}\n"
                    f"Name: {vuln_name}\n"
                    f"Message: {vuln_msg}\n"
                    f"Fix Note: {fix_note}\n"
                    f"Static Fix:\n{static_fix}\n"
                    f"AI Fix Confidence: {confidence_level} ({confidence_msg})"
                )
                pdf.ln(2)

            pdf.ln(2)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "Confidence Score Explanation:", ln=True)
            pdf.set_font("Courier", size=8)
            pdf.multi_cell(0, 5, confidence_explanation_text)

            pdf.output(output_path)
            logger.info(f"Report exported to PDF at {output_path}.")

        except Exception as e:
            logger.error(f"Error exporting report to PDF: {str(e)}")

    def export_to_html(self, report: Dict, output_path: str):
        try:
            template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('sast_report_template.html')

            html_content = template.render(
                report=report,
                title="SecureCheck - Static Application Security Test Report",
                logo_url=self.logo_url or "home/avni/securecheck/ARIBL_LOGO.png",
                confidence_logic=confidence_explanation_text,
                source_code=html.escape(report['source_code'])
            )

            with open(output_path, 'w', encoding="utf-8") as html_file:
                html_file.write(html_content)
            logger.info(f"Report exported to HTML at {output_path}.")
        except Exception as e:
            logger.error(f"Error exporting report to HTML: {str(e)}")

if __name__ == "__main__":
    findings = [
        {"line": 14, "message": "Possible XSS vulnerability", "cwe_id": "CWE-79", "tool": "semgrep", "severity": "high"},
        {"line": 20, "message": "SQL Injection risk", "cwe_id": "CWE-89", "tool": "semgrep", "severity": "high"}
    ]
    tool_versions = {
        "semgrep": "0.70.0",
        "eslint": "7.32.0",
    }
    fix_verified = "no"

    report_generator = ReportGenerator(
        file_path="example.py",
        findings=findings,
        fix_verified=fix_verified,
        tool_versions=tool_versions,
        source_code_path="example.py"
    )
    report = report_generator.generate_report()
    report_generator.export_to_json(report, "report.json")
    report_generator.export_to_pdf(report, "report.pdf")
    report_generator.export_to_html(report, "report.html")
