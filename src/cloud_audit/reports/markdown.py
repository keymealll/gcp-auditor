"""Markdown report generator."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_audit.models import ScanReport


def render_markdown(report: ScanReport) -> str:
    """Render scan report as Markdown.

    Args:
        report: The scan report to render

    Returns:
        Markdown formatted string
    """
    lines = [
        "# GCP Security Audit Report",
        "",
        f"**Project:** {report.account_id}",
        f"**Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Duration:** {report.duration_seconds:.2f}s",
        "",
        "## Summary",
        "",
        f"- **Total Findings:** {report.summary.total_findings}",
        f"- **Max CVSS Score:** {report.summary.max_cvss_score}",
        f"- **Risk Rating:** {report.summary.risk_rating}",
        "",
        "## Findings",
        "",
    ]

    # Group findings by severity
    findings = report.all_findings
    if findings:
        for finding in sorted(findings, key=lambda f: f.cvss_score or 0, reverse=True):
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- **Check ID:** {finding.check_id}",
                    f"- **Resource:** `{finding.resource_id}`",
                    f"- **Severity:** {finding.severity.value.upper()}",
                    f"- **CVSS Score:** {finding.cvss_score}",
                    f"- **Region:** {finding.region}",
                    "",
                    f"**Description:** {finding.description}",
                    "",
                    f"**Recommendation:** {finding.recommendation}",
                    "",
                ]
            )
            if finding.compliance_refs:
                lines.append(f"**Compliance:** {', '.join(finding.compliance_refs)}")
                lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("✅ No findings detected!")
        lines.append("")

    return "\n".join(lines)
