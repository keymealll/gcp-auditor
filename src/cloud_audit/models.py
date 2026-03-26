"""Core data models for gcp-auditor findings and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Category of finding."""

    SECURITY = "security"
    COST = "cost"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"


class Effort(str, Enum):
    """Estimated effort to implement the remediation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Remediation(BaseModel):
    """Remediation details for a finding - CLI command, Terraform HCL, and docs link."""

    cli: str = Field(description="CLI command (copy-paste ready)")
    terraform: str = Field(description="Terraform HCL snippet")
    doc_url: str = Field(description="Link to documentation")
    effort: Effort = Field(description="Estimated remediation effort")


# Legacy severity weights (kept for backward compatibility)
SEVERITY_SCORE = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 5,
    Severity.MEDIUM: 15,
    Severity.LOW: 25,
    Severity.INFO: 35,
}

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


class Finding(BaseModel):
    """A single audit finding - one issue detected in the infrastructure.

    Now includes CVSS scoring for risk-based prioritization.
    """

    check_id: str = Field(description="Unique check identifier, e.g. 'gcp-iam-001'")
    title: str = Field(description="Short human-readable title")
    severity: Severity = Field(description="Legacy severity level")
    category: Category = Field(description="Category of finding")
    resource_type: str = Field(description="Resource type, e.g. 'google_compute_instance'")
    resource_id: str = Field(description="Resource identifier (ARN, ID, or name)")
    region: str = Field(default="global", description="Region where resource is located")
    description: str = Field(description="What is wrong")
    recommendation: str = Field(description="How to fix it")
    remediation: Remediation | None = Field(default=None, description="Structured remediation details")
    compliance_refs: list[str] = Field(default_factory=list, description="Compliance references, e.g. ['CIS 1.5']")

    # CVSS scoring (new)
    cvss_vector: str | None = Field(default=None, description="CVSS v3.1 vector string")
    cvss_score: float | None = Field(default=None, description="CVSS base score (0.0-10.0)")

    def model_post_init(self, __context: object) -> None:
        """Auto-populate CVSS score if not provided."""
        if self.cvss_score is None or self.cvss_vector is None:
            # Import here to avoid circular imports
            from cloud_audit.cvss import get_cvss_profile

            profile = get_cvss_profile(self.check_id)
            if self.cvss_score is None:
                self.cvss_score = profile.calculate_score()
            if self.cvss_vector is None:
                self.cvss_vector = profile.to_vector_string()

    @property
    def cvss_severity(self) -> str:
        """Get CVSS-based severity rating."""
        if self.cvss_score is None:
            from cloud_audit.cvss import get_cvss_profile

            profile = get_cvss_profile(self.check_id)
            return profile.get_severity()

        if self.cvss_score >= 9.0:
            return "CRITICAL"
        elif self.cvss_score >= 7.0:
            return "HIGH"
        elif self.cvss_score >= 4.0:
            return "MEDIUM"
        elif self.cvss_score >= 0.1:
            return "LOW"
        return "NONE"

    @property
    def cvss_emoji(self) -> str:
        """Get emoji representation of CVSS severity."""
        score = self.cvss_score or 0
        if score >= 9.0:
            return "🔴"
        elif score >= 7.0:
            return "🟠"
        elif score >= 4.0:
            return "🟡"
        elif score >= 0.1:
            return "🟢"
        return "⚪"

    def get_risk_priority(self) -> float:
        """Calculate risk priority score for sorting.

        Higher score = higher priority (fix first)
        Uses CVSS score weighted by exploitability factors.
        """
        if self.cvss_score is None:
            return 0.0

        # Square the CVSS score to prioritize critical findings
        # A 9.8 finding should be fixed before ten 3.0 findings
        return round(self.cvss_score**2, 1)


class CheckResult(BaseModel):
    """Result of running a single check - may produce 0..N findings."""

    check_id: str = Field(description="Unique check identifier")
    check_name: str = Field(description="Human-readable check name")
    findings: list[Finding] = Field(default_factory=list, description="List of findings from this check")
    resources_scanned: int = Field(default=0, description="Number of resources scanned")
    error: str | None = Field(default=None, description="Error message if check failed")

    @property
    def max_cvss_score(self) -> float:
        """Get the highest CVSS score from findings."""
        if not self.findings:
            return 0.0
        return max(f.cvss_score or 0 for f in self.findings)

    @property
    def avg_cvss_score(self) -> float:
        """Get average CVSS score from findings."""
        if not self.findings:
            return 0.0
        scores = [f.cvss_score or 0 for f in self.findings]
        return round(sum(scores) / len(scores), 1)


class ScanSummary(BaseModel):
    """Aggregated summary of a full scan with CVSS-based risk metrics."""

    total_findings: int = Field(default=0, description="Total number of findings")
    by_severity: dict[Severity, int] = Field(default_factory=dict, description="Count by legacy severity")
    by_category: dict[Category, int] = Field(default_factory=dict, description="Count by category")
    resources_scanned: int = Field(default=0, description="Total resources scanned")
    checks_passed: int = Field(default=0, description="Number of checks that passed")
    checks_failed: int = Field(default=0, description="Number of checks that found issues")
    checks_errored: int = Field(default=0, description="Number of checks that encountered errors")

    # Legacy health score (kept for backward compatibility)
    score: int = Field(default=100, description="Legacy health score 0-100")

    # NEW: CVSS-based risk metrics
    max_cvss_score: float = Field(default=0.0, description="Highest CVSS score (worst finding)")
    avg_cvss_score: float = Field(default=0.0, description="Average CVSS score across all findings")
    total_risk_score: float = Field(default=0.0, description="Aggregate risk (sum of CVSS²)")

    # CVSS distribution
    by_cvss_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Count by CVSS severity: CRITICAL(9-10), HIGH(7-8.9), MEDIUM(4-6.9), LOW(0.1-3.9)",
    )

    # Attack surface metrics
    network_exposed: int = Field(default=0, description="Number of network-exploitable findings")
    local_only: int = Field(default=0, description="Number of locally-exploitable findings")

    @property
    def risk_rating(self) -> str:
        """Get overall risk rating based on max CVSS score."""
        if self.max_cvss_score >= 9.0:
            return "CRITICAL"
        elif self.max_cvss_score >= 7.0:
            return "HIGH"
        elif self.max_cvss_score >= 4.0:
            return "MEDIUM"
        elif self.max_cvss_score > 0:
            return "LOW"
        return "NONE"

    @property
    def risk_emoji(self) -> str:
        """Get emoji for risk rating."""
        if self.max_cvss_score >= 9.0:
            return "🔴"
        elif self.max_cvss_score >= 7.0:
            return "🟠"
        elif self.max_cvss_score >= 4.0:
            return "🟡"
        elif self.max_cvss_score > 0:
            return "🟢"
        return "⚪"

    @property
    def immediate_action_count(self) -> int:
        """Count findings requiring immediate action (CVSS >= 9.0)."""
        return self.by_cvss_severity.get("CRITICAL", 0)

    def compute_cvss_metrics(self, findings: list[Finding]) -> None:
        """Compute CVSS-based metrics from findings.

        Args:
            findings: List of all findings from the scan
        """
        if not findings:
            self.max_cvss_score = 0.0
            self.avg_cvss_score = 0.0
            self.total_risk_score = 0.0
            self.by_cvss_severity = {}
            self.network_exposed = 0
            self.local_only = 0
            return

        scores = []
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        network_count = 0
        local_count = 0

        for finding in findings:
            score = finding.cvss_score or 0
            scores.append(score)

            # Count by CVSS severity
            sev = finding.cvss_severity
            severities[sev] = severities.get(sev, 0) + 1

            # Count attack vector
            if finding.cvss_vector:
                if "AV:N" in finding.cvss_vector:  # Network
                    network_count += 1
                elif "AV:L" in finding.cvss_vector or "AV:A" in finding.cvss_vector:  # Local/Adjacent
                    local_count += 1

        self.max_cvss_score = max(scores)
        self.avg_cvss_score = round(sum(scores) / len(scores), 1)

        # Calculate total risk using CVSS² (prioritizes critical findings)
        self.total_risk_score = round(sum(s**2 for s in scores), 1)

        # Store distribution (remove zero counts)
        self.by_cvss_severity = {k: v for k, v in severities.items() if v > 0}

        self.network_exposed = network_count
        self.local_only = local_count


class ScanReport(BaseModel):
    """Complete scan report - the top-level output."""

    provider: str = Field(description="Cloud provider (gcp, aws, azure)")
    account_id: str = Field(default="", description="Account/Project ID")
    regions: list[str] = Field(default_factory=list, description="Regions scanned")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Scan timestamp")
    duration_seconds: float = Field(default=0.0, description="Scan duration")
    summary: ScanSummary = Field(default_factory=ScanSummary, description="Scan summary")
    results: list[CheckResult] = Field(default_factory=list, description="Individual check results")

    @property
    def all_findings(self) -> list[Finding]:
        """Get all findings flattened from all check results."""
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    @property
    def critical_findings(self) -> list[Finding]:
        """Get findings sorted by CVSS score (highest first)."""
        findings = self.all_findings
        return sorted(findings, key=lambda f: f.cvss_score or 0, reverse=True)

    @property
    def network_exposed_findings(self) -> list[Finding]:
        """Get network-exploitable findings (highest risk)."""
        findings = self.all_findings
        network_findings = [f for f in findings if f.cvss_vector and "AV:N" in f.cvss_vector]
        return sorted(network_findings, key=lambda f: f.cvss_score or 0, reverse=True)

    def compute_summary(self) -> None:
        """Compute summary statistics from results."""
        findings = self.all_findings
        self.summary.total_findings = len(findings)
        self.summary.resources_scanned = sum(r.resources_scanned for r in self.results)
        self.summary.checks_passed = sum(1 for r in self.results if not r.findings and not r.error)
        self.summary.checks_failed = sum(1 for r in self.results if r.findings)
        self.summary.checks_errored = sum(1 for r in self.results if r.error)

        # Legacy severity counts
        self.summary.by_severity = {}
        for sev in Severity:
            count = sum(1 for f in findings if f.severity == sev)
            if count:
                self.summary.by_severity[sev] = count

        # Category counts
        self.summary.by_category = {}
        for cat in Category:
            count = sum(1 for f in findings if f.category == cat)
            if count:
                self.summary.by_category[cat] = count

        # Legacy score calculation (kept for backward compatibility)
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
        self.summary.score = max(0, 100 - penalty)

        # NEW: Compute CVSS-based metrics
        self.summary.compute_cvss_metrics(findings)
