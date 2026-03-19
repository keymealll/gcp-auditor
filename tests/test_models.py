"""Tests for core data models."""

from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)


def test_finding_creation():
    f = Finding(
        check_id="test-001",
        title="Test finding",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_type="google_storage_bucket",
        resource_id="my-bucket",
        description="Something is wrong",
        recommendation="Fix it",
    )
    assert f.severity == Severity.HIGH
    assert f.category == Category.SECURITY


def test_check_result_empty():
    r = CheckResult(check_id="test-001", check_name="Test check")
    assert r.findings == []
    assert r.error is None


def test_scan_report_compute_summary():
    report = ScanReport(provider="gcp")
    report.results = [
        CheckResult(
            check_id="test-001",
            check_name="Passing check",
            resources_scanned=5,
        ),
        CheckResult(
            check_id="test-002",
            check_name="Failing check",
            resources_scanned=3,
            findings=[
                Finding(
                    check_id="test-002",
                    title="Critical issue",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    resource_type="google_compute_instance",
                    resource_id="i-123",
                    description="Bad",
                    recommendation="Fix",
                ),
                Finding(
                    check_id="test-002",
                    title="Low issue",
                    severity=Severity.LOW,
                    category=Category.COST,
                    resource_type="google_compute_address",
                    resource_id="eip-456",
                    description="Wasted money",
                    recommendation="Release",
                ),
            ],
        ),
    ]

    report.compute_summary()

    assert report.summary.total_findings == 2
    assert report.summary.resources_scanned == 8
    assert report.summary.checks_passed == 1
    assert report.summary.checks_failed == 1
    assert report.summary.by_severity[Severity.CRITICAL] == 1
    assert report.summary.by_severity[Severity.LOW] == 1
    assert report.summary.by_category[Category.SECURITY] == 1
    assert report.summary.by_category[Category.COST] == 1
    assert report.summary.score == 78  # 100 - 20 (critical) - 2 (low)


def test_scan_report_perfect_score():
    report = ScanReport(provider="gcp")
    report.results = [
        CheckResult(check_id="test-001", check_name="All good", resources_scanned=10),
    ]
    report.compute_summary()
    assert report.summary.score == 100
    assert report.summary.total_findings == 0


def test_finding_with_remediation():
    r = Remediation(
        cli="gcloud compute instances delete-access-config ...",
        terraform='resource "google_compute_instance" "example" { ... }',
        doc_url="https://cloud.google.com/compute/docs",
        effort=Effort.LOW,
    )
    f = Finding(
        check_id="test-001",
        title="Test",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_type="google_compute_instance",
        resource_id="test-instance",
        description="Public IP",
        recommendation="Remove public IP",
        remediation=r,
        compliance_refs=["CIS GCP 4.8"],
    )
    assert f.remediation is not None
    assert f.remediation.effort == Effort.LOW
    assert f.compliance_refs == ["CIS GCP 4.8"]


def test_finding_without_remediation():
    """Ensure remediation is optional (backward compat)."""
    f = Finding(
        check_id="test-001",
        title="Test",
        severity=Severity.LOW,
        category=Category.COST,
        resource_type="google_compute_address",
        resource_id="eip-123",
        description="Unused",
        recommendation="Release",
    )
    assert f.remediation is None
    assert f.compliance_refs == []
