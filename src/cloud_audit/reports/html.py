"""HTML report generator using Jinja2."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from cloud_audit.models import ScanReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(report: ScanReport) -> str:
    """Render a ScanReport to a self-contained HTML string."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    # Sort findings by severity for display
    from cloud_audit.models import Severity

    severity_order = list(Severity)
    sorted_findings = sorted(report.all_findings, key=lambda f: severity_order.index(f.severity))

    # Group findings by category
    from collections import defaultdict

    by_category: dict[str, list[object]] = defaultdict(list)
    for f in sorted_findings:
        by_category[f.category.value].append(f)

    # Collect unique CIS references across all findings
    cis_controls: list[str] = sorted(
        {ref for f in report.all_findings for ref in f.compliance_refs if ref.startswith("CIS")}
    )

    return template.render(
        report=report,
        sorted_findings=sorted_findings,
        by_category=dict(by_category),
        severity_order=severity_order,
        cis_controls=cis_controls,
    )
