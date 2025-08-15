import networkx as nx
import json
import logging
import base64
from pyvis.network import Network
from graphviz import Digraph
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader, select_autoescape


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SBOMVisualizer:
    def __init__(self, parsed_data: Dict):
        """
        Initialize the visualizer with parsed SBOM data.
        
        :param parsed_data: The parsed SBOM data containing components and vulnerabilities.
        """
        self.parsed_data = parsed_data
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        try:
            for component in self.parsed_data.get("components", []):
                cname = component.get("name", "unknown")
                cversion = component.get("version", "unknown")
                if cname == "unknown":
                    continue

                self.graph.add_node(cname, label=cname, type="component", title=f"{cname} ({cversion})")
                for vuln in component.get("vulnerabilities", []):
                    vid = vuln.get("vulnerability_id", "unknown")
                    severity = vuln.get("severity", "unknown")
                    self.graph.add_node(vid, label=vid, type="vulnerability", severity=severity, title=severity)
                    self.graph.add_edge(cname, vid, label=severity)
        except Exception as e:
            logger.error(f"Graph build error: {e}")

    def generate_html_fragment(self) -> str:
        try:
            net = Network(height="700px", width="100%", bgcolor="#fff", font_color="#333", directed=True)
            net.from_nx(self.graph)

            # Enhance layout
            net.force_atlas_2based(gravity=-50, central_gravity=0.005, spring_length=100)
            net.repulsion(node_distance=200, spring_length=150)
            net.set_options("""
            var options = {
              nodes: {
                shape: "dot",
                size: 15,
                font: { size: 14 },
                scaling: { label: true }
              },
              edges: {
                arrows: "to",
                smooth: true,
                color: { inherit: true }
              },
              physics: {
                forceAtlas2Based: {
                  gravitationalConstant: -50,
                  centralGravity: 0.005,
                  springLength: 150
                },
                solver: "forceAtlas2Based"
              }
            }
            """)
            return net.generate_html()
        except Exception as e:
            logger.error(f"HTML graph generation failed: {e}")
            return "<p>Error generating interactive graph.</p>"

    def generate_tile_html(self) -> str:
        """Generate a scrollable tile view of components and their vulnerabilities."""
        try:
            html = '<div style="display: flex; overflow-x: auto; gap: 16px; padding: 10px;">\n'
            for comp in self.parsed_data.get("components", []):
                if not comp.get("name"): continue

                card = f"""
                <div style="min-width: 250px; background: #fff; border: 1px solid #ddd;
                            border-radius: 8px; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); padding: 15px;">
                    <h4 style="margin-bottom: 5px; color: #007bff;">{comp['name']}</h4>
                    <p style="margin: 0 0 10px 0;"><strong>Version:</strong> {comp['version']}</p>
                    <div>
                """

                if comp.get("vulnerabilities"):
                    for vuln in comp["vulnerabilities"]:
                        severity_color = {
                            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                            "MEDIUM": "#ffc107", "LOW": "#28a745"
                        }.get(vuln["severity"].upper(), "#6c757d")

                        card += f"""
                            <div style="margin-bottom: 8px; padding: 6px;
                                        background: {severity_color}; color: white;
                                        border-radius: 4px; font-size: 13px;">
                                <strong>{vuln["vulnerability_id"]}</strong><br>
                                <em>CVSS: {vuln.get("cvss_score", 'N/A')}</em>
                            </div>
                        """
                else:
                    card += "<p>No vulnerabilities</p>"

                card += "</div></div>\n"
                html += card
            html += "</div>"
            return html
        except Exception as e:
            logger.error(f"Tile HTML generation failed: {e}")
            return "<p>Error generating scrollable tile layout.</p>"

    def generate_png(self, output_file: str):
        try:
            dot = Digraph(engine='dot')
            dot.attr(size="10,10", dpi="150")
            for node, data in self.graph.nodes(data=True):
                label = f"{node}\n({data.get('type')})"
                shape = "ellipse" if data.get("type") == "component" else "box"
                color = {
                    "CRITICAL": "red",
                    "HIGH": "orange",
                    "MEDIUM": "gold",
                    "LOW": "green"
                }.get(data.get("severity", "").upper(), "gray")
                dot.node(node, label=label, shape=shape, style="filled", fillcolor=color)
            for src, dst, attrs in self.graph.edges(data=True):
                dot.edge(src, dst, label=attrs.get("label", ""))
            dot.render(output_file, format='png', cleanup=True)
            logger.info(f"PNG graph saved: {output_file}.png")
        except Exception as e:
            logger.error(f"PNG graph generation failed: {e}")

    def generate_pdf(self, output_file: str):
        try:
            dot = Digraph(comment='Dependency Risk Tree')
            for node, attrs in self.graph.nodes(data=True):
                label = f"{node}\n({attrs.get('type', '')})"
                dot.node(node, label=label)
            for src, dst, attrs in self.graph.edges(data=True):
                dot.edge(src, dst, label=attrs.get("label", ""))
            dot.render(output_file, format='pdf', cleanup=True)
            logger.info(f"PDF visualization saved to {output_file}.pdf")
        except Exception as e:
            logger.error(f"PDF graph generation failed: {e}")

    def generate_json(self, output_file: str):
        try:
            tree_data = {
                "nodes": [
                    {
                        "id": node,
                        "version": data.get("version"),
                        "severity": data.get("severity"),
                        "type": data.get("type")
                    } for node, data in self.graph.nodes(data=True)
                ],
                "edges": [
                    {
                        "from": src,
                        "to": dst,
                        "severity": attrs.get("label")
                    } for src, dst, attrs in self.graph.edges(data=True)
                ]
            }
            with open(output_file, 'w') as json_file:
                json.dump(tree_data, json_file, indent=4)
            logger.info(f"JSON visualization saved to {output_file}")
        except Exception as e:
            logger.error(f"Error generating JSON visualization: {str(e)}")

# Example usage
if __name__ == "__main__":
    with open("parsed_sbom.json") as f:
        parsed_data = json.load(f)

    vis = SBOMVisualizer(parsed_data)
    vis.generate_pdf("reports/sbom_tree")
    vis.generate_json("reports/sbom_tree.json")
    vis.generate_png("reports/sbom_risk_tree")

    html_fragment = vis.generate_html_fragment()
    tile_fragment = vis.generate_tile_html()

    with open("reports/sbom_risk_tree.png", "rb") as f:
        base64_png = base64.b64encode(f.read()).decode("utf-8")

    visuals = {
        "html": html_fragment,
        "tiles": tile_fragment,
        "base64_png": f"data:image/png;base64,{base64_png}"
    }

    print("Visuals ready.")
