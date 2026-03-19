"""SARIF report generator."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_audit.models import ScanReport


def render_sarif(report: ScanReport) -> str:
    """Render scan report as SARIF JSON.

    Args:
        report: The scan report to render

    Returns:
        SARIF JSON string
    """
    # Basic SARIF structure
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gcp-auditor",
                        "informationUri": "https://github.com/abdullahkamil/gcp-auditor",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    # Add findings as results
    for finding in report.all_findings:
        result = {
            "ruleId": finding.check_id,
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.resource_id},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        sarif["runs"][0]["results"].append(result)  # type: ignore[index]

    return json.dumps(sarif, indent=2)
