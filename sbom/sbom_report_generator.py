import networkx as nx
import json
import logging
from pyvis.network import Network
from graphviz import Digraph
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader, select_autoescape
import pdfkit
import os
import base64
from collections import Counter

# Configure logging 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SBOMReportGenerator:
    def __init__(self, sbom_data: Dict, vulnerabilities: Dict, visuals: Dict):
        """
        Initialize the report generator with SBOM data, vulnerabilities, and visuals.
        
        :param sbom_data: The SBOM data parsed from Syft
        :param vulnerabilities: The vulnerabilities data parsed from Grype
        :param visuals: The visual representation of the Dependency Risk Tree
        """
        self.sbom_data = sbom_data
        self.vulnerabilities = (
            vulnerabilities.get("matches", []) if isinstance(vulnerabilities, dict) else vulnerabilities
        )
        self.visuals = visuals
        self.env = Environment(
            loader=FileSystemLoader(searchpath="templates"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        os.makedirs("reports", exist_ok=True)

    def _calculate_severity_counts(self) -> Dict[str, int]:
        counts = Counter()
        for match in self.vulnerabilities:
            severity = match.get("vulnerability", {}).get("severity", "Unknown")
            counts[severity] += 1
        return dict(counts)

    def _generate_html_report(self, output_file: str) -> str:
        """Generate an HTML report using Jinja2 templates."""
        try:
            template = self.env.get_template("sbom_report.html")
            rendered = template.render(
                metadata=self.sbom_data.get("metadata", {}),
                components=self.sbom_data.get("components", []),
                vulnerabilities=self.vulnerabilities,
                visuals=self.visuals,
                summary=self.sbom_data.get("summary", {}),
                base64_png=self.visuals.get("base64_png", ""),
                tile_html=self.visuals.get("tiles", "")
            )
            with open(output_file, "w") as f:
                f.write(rendered)
            logger.info(f"HTML report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")

    def _generate_pdf_report(self, html_file: str, pdf_file: str):
        """Generate a PDF report from HTML content."""
        try:
            if not os.path.exists(html_file):
                logger.error("Cannot generate PDF: HTML file not found.")
                return
            pdfkit.from_file(html_file, pdf_file)
            logger.info(f"PDF report saved to {pdf_file}")
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")

    def _generate_json_report(self, output_file: str):
        """Generate a JSON report."""
        try:
            report_data = {
                "metadata": self.sbom_data.get("metadata", {}),
                "components": self.sbom_data.get("components", []),
                "vulnerabilities": self.vulnerabilities,
                "visuals": self.visuals,
                "severity_summary": self._calculate_severity_counts()
            }
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"JSON report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")

    def generate_reports(self, output_prefix: str):
        """Generate JSON, HTML, and PDF reports."""
        try:
            json_path = f"{output_prefix}_report.json"
            html_path = f"{output_prefix}_report.html"
            pdf_path = f"{output_prefix}_report.pdf"

            self._generate_json_report(json_path)
            self._generate_html_report(html_path)
            self._generate_pdf_report(html_path, pdf_path)

        except Exception as e:
            logger.error(f"Error generating reports: {e}")

# Example usage
if __name__ == "__main__":
    with open("parsed_sbom.json") as f:
        parsed_data = json.load(f)

    visuals = {
        "html": "<p>Graph placeholder</p>",
        "tiles": "<div>Tile layout here</div>",
        "base64_png": ""
    }

    generator = SBOMReportGenerator(
        sbom_data=parsed_data,
        vulnerabilities=parsed_data.get("vulnerabilities", []),
        visuals=visuals
    )
    generator.generate_reports("reports/sbom")

