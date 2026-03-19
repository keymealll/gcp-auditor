"""Tests for CLI remediation and export-fixes flags."""

from __future__ import annotations

from pathlib import Path

from cloud_audit.cli import _export_fixes, _print_remediation
from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)


def _make_finding(
    *,
    check_id: str = "gcp-test-001",
    severity: Severity = Severity.HIGH,
    with_remediation: bool = True,
) -> Finding:
    """Create a test finding with optional remediation."""
    remediation = None
    if with_remediation:
        cli_cmd = (
            "gcloud compute instances delete-access-config test-instance"
            " --zone=us-central1-a"
            ' --access-config-name="External NAT"'
        )
        tf_snippet = 'resource "google_compute_instance" "example" {\n  # remove access_config\n}'
        remediation = Remediation(
            cli=cli_cmd,
            terraform=tf_snippet,
            doc_url="https://cloud.google.com/compute/docs",
            effort=Effort.LOW,
        )
    return Finding(
        check_id=check_id,
        title="Test instance has public IP",
        severity=severity,
        category=Category.SECURITY,
        resource_type="google_compute_instance",
        resource_id="test-instance",
        region="global",
        description="Instance has a public IP address.",
        recommendation="Remove public IP.",
        remediation=remediation,
        compliance_refs=["CIS GCP 4.8"] if with_remediation else [],
    )


def _make_report(findings: list[Finding]) -> ScanReport:
    """Create a minimal ScanReport with given findings."""
    report = ScanReport(
        provider="gcp",
        account_id="my-gcp-project",
        regions=["global"],
    )
    report.results.append(
        CheckResult(
            check_id="gcp-test-001",
            check_name="Test Check",
            findings=findings,
            resources_scanned=len(findings),
        )
    )
    report.compute_summary()
    return report


def test_print_remediation_shows_output(capsys: object) -> None:
    """--remediation flag prints CLI commands and compliance refs."""
    finding = _make_finding(with_remediation=True)
    # _print_remediation uses rich Console, so we just verify it doesn't crash
    _print_remediation([finding])


def test_print_remediation_skips_no_remediation() -> None:
    """No remediation findings - nothing printed."""
    finding = _make_finding(with_remediation=False)
    # Should not raise
    _print_remediation([finding])


def test_print_remediation_empty_list() -> None:
    """Empty findings list - nothing printed."""
    _print_remediation([])


def test_export_fixes_creates_script(tmp_path: Path) -> None:
    """--export-fixes generates a valid bash script with commented commands."""
    finding = _make_finding(with_remediation=True)
    output_path = tmp_path / "fixes.sh"

    _export_fixes([finding], output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    # Bash script structure
    assert content.startswith("#!/bin/bash")
    assert "set -e" in content
    assert "DRY RUN" in content

    # Finding details
    assert "test-instance" in content
    assert "CIS GCP 4.8" in content

    # CLI command is commented out
    assert "# gcloud compute instances delete-access-config test-instance" in content


def test_export_fixes_multiple_findings(tmp_path: Path) -> None:
    """Multiple findings are all included in the script, sorted by CVSS."""
    # Use real check IDs that have CVSS profiles for accurate testing
    # gcp-firewall-001 has CVSS 10.0 (CRITICAL)
    # gcp-firewall-003 has CVSS 1.9 (LOW)
    finding_crit = _make_finding(check_id="gcp-firewall-001", severity=Severity.CRITICAL)
    finding_low = _make_finding(check_id="gcp-firewall-003", severity=Severity.LOW)

    findings = [finding_low, finding_crit]  # Intentionally out of order
    output_path = tmp_path / "fixes.sh"

    _export_fixes(findings, output_path)

    content = output_path.read_text(encoding="utf-8")
    assert "Total actionable findings: 2" in content
    # Higher CVSS should come first (sorted by CVSS score descending)
    # gcp-firewall-001 (10.0) should come before gcp-firewall-003 (1.9)
    # Check for CVSS severity labels in output
    crit_pos = content.index("[CRITICAL]")
    low_pos = content.index("[LOW]")
    assert crit_pos < low_pos, "Findings should be sorted by CVSS score (highest first)"


def test_export_fixes_no_actionable(tmp_path: Path) -> None:
    """No remediation findings - no file created."""
    finding = _make_finding(with_remediation=False)
    output_path = tmp_path / "fixes.sh"

    _export_fixes([finding], output_path)

    assert not output_path.exists()


def test_export_fixes_empty_findings(tmp_path: Path) -> None:
    """Empty findings list - no file created."""
    output_path = tmp_path / "fixes.sh"

    _export_fixes([], output_path)

    assert not output_path.exists()
