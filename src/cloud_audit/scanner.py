"""Scanner - orchestrates check execution and produces a report."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cloud_audit.models import Finding, ScanReport, Severity

if TYPE_CHECKING:
    from cloud_audit.config import CloudAuditConfig

if TYPE_CHECKING:
    from cloud_audit.providers.base import BaseProvider

console = Console()


def _should_include_finding(
    finding: Finding,
    config: CloudAuditConfig | None,
    suppressed_ids: set[str],
) -> bool:
    """Determine if a finding should be included based on filters.

    Args:
        finding: The finding to check
        config: Scan configuration with filters
        suppressed_ids: Set of suppressed check/resource combinations

    Returns:
        True if finding should be included, False otherwise
    """
    # Check suppressions
    suppression_key = f"{finding.check_id}:{finding.resource_id}"
    if suppression_key in suppressed_ids:
        return False

    if config is None:
        return True

    # Check excluded checks
    if finding.check_id in config.exclude_checks:
        return False

    # Check minimum severity (legacy filter)
    if config.min_severity is not None:
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        finding_idx = severity_order.index(finding.severity)
        min_idx = severity_order.index(config.min_severity)
        if finding_idx > min_idx:
            return False

    # Check minimum CVSS score (NEW)
    if config.min_cvss is not None:
        cvss = finding.cvss_score or 0
        if cvss < config.min_cvss:
            return False

    return True


def run_scan(
    provider: BaseProvider,
    categories: list[str] | None = None,
    config: CloudAuditConfig | None = None,
    quiet: bool = False,
) -> tuple[ScanReport, int]:
    """Execute all checks for the given provider and return a ScanReport.

    Args:
        provider: Cloud provider instance
        categories: Optional category filter
        config: Optional scan configuration
        quiet: Suppress progress output

    Returns:
        Tuple of (ScanReport, suppressed_count)
    """
    report = ScanReport(provider=provider.get_provider_name())

    # Get account info
    try:
        report.account_id = provider.get_account_id()
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Could not get account ID: {e}[/yellow]")

    if hasattr(provider, "regions"):
        report.regions = provider.regions

    # Build suppressed IDs set from config
    suppressed_ids: set[str] = set()
    if config and config.suppressions:
        for sup in config.suppressions:
            check_id = sup.get("check_id", "")
            resource_id = sup.get("resource_id", "")
            suppressed_ids.add(f"{check_id}:{resource_id}")

    checks = provider.get_checks(categories=categories)

    if not checks:
        if not quiet:
            console.print("[yellow]No checks to run.[/yellow]")
        return report, 0

    if not quiet:
        console.print(f"\n[bold]Running {len(checks)} checks on {report.provider.upper()}...[/bold]\n")

    start = time.monotonic()

    # Use progress bar unless quiet
    if quiet:
        for check_fn in checks:
            try:
                result = check_fn()
                # Filter findings based on config
                if config:
                    result.findings = [f for f in result.findings if _should_include_finding(f, config, suppressed_ids)]
                report.results.append(result)
            except Exception as e:
                from cloud_audit.models import CheckResult

                check_id = getattr(check_fn, "__name__", "unknown")
                report.results.append(
                    CheckResult(
                        check_id=check_id,
                        check_name=check_id,
                        error=str(e),
                    )
                )
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning", total=len(checks))

            for check_fn in checks:
                try:
                    result = check_fn()
                    # Filter findings based on config
                    if config:
                        result.findings = [
                            f for f in result.findings if _should_include_finding(f, config, suppressed_ids)
                        ]
                    report.results.append(result)
                except Exception as e:
                    from cloud_audit.models import CheckResult

                    check_id = getattr(check_fn, "__name__", "unknown")
                    report.results.append(
                        CheckResult(
                            check_id=check_id,
                            check_name=check_id,
                            error=str(e),
                        )
                    )

                progress.advance(task)

    report.duration_seconds = round(time.monotonic() - start, 2)
    report.compute_summary()

    # Calculate suppressed count
    suppressed_count = len(suppressed_ids)

    return report, suppressed_count
