"""CLI interface for gcp-auditor."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloud_audit import __version__
from cloud_audit.models import Finding, ScanReport, Severity

app = typer.Typer(
    name="gcp-auditor",
    help="Scan your cloud infrastructure for security, cost, and reliability issues.",
    no_args_is_help=True,
)
console = Console()

# Legacy severity colors (kept for backward compatibility)
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "✖",
    Severity.HIGH: "✖",
    Severity.MEDIUM: "⚠",
    Severity.LOW: "○",
    Severity.INFO: "ℹ",
}

# CVSS severity colors
CVSS_COLORS = {
    "CRITICAL": "bold bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "NONE": "dim",
}

CVSS_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "NONE": "⚪",
}


def _get_risk_color(score: float) -> str:
    """Get color based on CVSS score."""
    if score >= 9.0:
        return "bold bright_red"
    elif score >= 7.0:
        return "red"
    elif score >= 4.0:
        return "yellow"
    elif score > 0:
        return "cyan"
    return "green"


def _print_summary(report: ScanReport, suppressed_count: int = 0) -> None:
    """Print a rich summary of the scan results to the console with CVSS scoring."""
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # If all checks errored, show error banner instead of fake score
    if all_errored:
        console.print()
        console.print(
            Panel(
                "[bold red]SCAN FAILED[/bold red]\n\nAll checks returned errors. No resources were scanned.",
                title="[bold red]Error[/bold red]",
                border_style="red",
                width=60,
            )
        )

        # Show error details
        errored_results = [r for r in report.results if r.error]
        if errored_results:
            # Deduplicate error messages
            unique_errors: dict[str, list[str]] = {}
            for r in errored_results:
                err = r.error or "Unknown error"
                err_short = err.split("\n")[0][:120]
                unique_errors.setdefault(err_short, []).append(r.check_id)

            console.print("\n[bold]Errors:[/bold]")
            for err_msg, check_ids in unique_errors.items():
                console.print(f"  [red]{err_msg}[/red]")
                console.print(f"  [dim]Affected checks: {', '.join(check_ids)}[/dim]\n")

        # Common fix suggestions
        console.print("[bold]Common fixes:[/bold]")
        console.print("  1. Check credentials: [cyan]gcloud auth application-default print-access-token[/cyan]")
        console.print("  2. Re-authenticate: [cyan]gcloud auth application-default login[/cyan]")
        console.print("  3. Verify project: [cyan]gcp-auditor scan --project my-project[/cyan]")
        console.print("  4. Use service account: [cyan]gcp-auditor scan --service-account-key sa-key.json[/cyan]")
        return

    # NEW: CVSS Risk Assessment Panel (replaces Health Score)
    risk_color = _get_risk_color(s.max_cvss_score)
    risk_emoji = s.risk_emoji

    console.print()

    # Risk summary panel
    if s.total_findings == 0:
        risk_content = "[bold green]✓ NO RISK[/bold green]\n\nNo vulnerabilities detected"
        risk_border = "green"
    else:
        immediate = s.immediate_action_count
        immediate_text = f"\n⚠️  {immediate} finding(s) require immediate action" if immediate > 0 else ""

        risk_content = (
            f"[{risk_color}]{risk_emoji} {s.risk_rating}[/{risk_color}]\n\n"
            f"Max CVSS: [{risk_color}]{s.max_cvss_score}[/{risk_color}]\n"
            f"Avg CVSS: {s.avg_cvss_score}\n"
            f"Total Risk: {s.total_risk_score:.0f}{immediate_text}"
        )
        risk_border = "red" if s.max_cvss_score >= 9.0 else ("yellow" if s.max_cvss_score >= 4.0 else "green")

    console.print(
        Panel(
            risk_content,
            title="[bold]Risk Assessment[/bold]",
            border_style=risk_border,
            width=40,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", report.provider.upper())
    table.add_row("Project", report.account_id or "unknown")
    table.add_row("Duration", f"{report.duration_seconds:.1f}s")
    table.add_row("Resources scanned", str(s.resources_scanned))
    table.add_row("Checks passed", f"[green]{s.checks_passed}[/green]")
    table.add_row("Checks failed", f"[red]{s.checks_failed}[/red]" if s.checks_failed else "0")
    if s.checks_errored:
        table.add_row("Checks errored", f"[yellow]{s.checks_errored}[/yellow]")
    if suppressed_count > 0:
        table.add_row("Suppressed", f"[dim]{suppressed_count}[/dim]")
    console.print(table)

    # Show errors if any (partial failure)
    if s.checks_errored:
        errored_results = [r for r in report.results if r.error]
        console.print(f"\n[yellow]Warning: {s.checks_errored} check(s) failed with errors:[/yellow]")
        for r in errored_results:
            err_short = (r.error or "Unknown")[:100]
            console.print(f"  [dim]{r.check_name}:[/dim] [yellow]{err_short}[/yellow]")

    # NEW: CVSS severity distribution
    if s.by_cvss_severity:
        console.print("\n[bold]Findings by CVSS severity:[/bold]")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
            count = s.by_cvss_severity.get(severity, 0)
            if count > 0:
                color = CVSS_COLORS.get(severity, "white")
                icon = CVSS_ICONS.get(severity, "")
                console.print(f"  [{color}]{icon} {severity}: {count}[/{color}]")

    # Attack surface summary
    if s.network_exposed > 0 or s.local_only > 0:
        console.print("\n[bold]Attack surface:[/bold]")
        if s.network_exposed > 0:
            console.print(f"  🌐 Network-exploitable: {s.network_exposed}")
        if s.local_only > 0:
            console.print(f"  🏢 Local-access only: {s.local_only}")

    # Top findings sorted by CVSS score
    findings = report.critical_findings  # Already sorted by CVSS
    if findings:
        shown = min(len(findings), 10)
        console.print(f"\n[bold]Top findings by CVSS score ({shown} of {len(findings)}):[/bold]\n")

        findings_table = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
        findings_table.add_column("CVSS", width=8, justify="right")
        findings_table.add_column("Sev", width=8)
        findings_table.add_column("Region", width=14)
        findings_table.add_column("Check", width=16)
        findings_table.add_column("Resource")
        findings_table.add_column("Title", max_width=50)

        for f in findings[:10]:
            cvss = f.cvss_score or 0
            cvss_color = _get_risk_color(cvss)
            sev_color = SEVERITY_COLORS.get(f.severity, "white")

            findings_table.add_row(
                f"[{cvss_color}]{cvss}[/{cvss_color}]",
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"[dim]{f.region or 'global'}[/dim]",
                f.check_id,
                f.resource_id[:40],
                f.title[:50],
            )

        console.print(findings_table)

        if len(findings) > 10:
            remaining = len(findings) - 10
            console.print(f"\n  [dim]... and {remaining} more. Use --output for full report.[/dim]")
    elif not s.checks_errored:
        console.print("\n[bold green]✓ No issues found. Your infrastructure looks great![/bold green]")


EFFORT_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}


def _print_remediation(findings: list[Finding]) -> None:
    """Print remediation details for findings that have them, sorted by CVSS score."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        return

    # Sort by CVSS score (highest first) instead of legacy severity
    actionable.sort(key=lambda f: f.cvss_score or 0, reverse=True)

    console.print(f"\n[bold]Remediation details ({len(actionable)} actionable findings):[/bold]\n")

    for f in actionable:
        rem = f.remediation
        assert rem is not None  # noqa: S101

        # Use CVSS for display priority
        cvss_color = _get_risk_color(f.cvss_score or 0)
        effort_color = EFFORT_COLORS[rem.effort.value]

        console.print(f"  [{cvss_color}]{f.cvss_emoji} CVSS {f.cvss_score}[/{cvss_color}] {f.title}")
        console.print(f"  [dim]Resource:[/dim] {f.resource_id}")
        if f.compliance_refs:
            console.print(f"  [dim]Compliance:[/dim] {', '.join(f.compliance_refs)}")
        console.print(f"  [dim]Effort:[/dim] [{effort_color}]{rem.effort.value.upper()}[/{effort_color}]")
        console.print(f"  [dim]CLI:[/dim] [cyan]{rem.cli}[/cyan]")
        if rem.terraform:
            # Show first line of terraform snippet as preview
            tf_preview = rem.terraform.split("\n")[0]
            console.print(f"  [dim]Terraform:[/dim] {tf_preview} ...")
        console.print(f"  [dim]Docs:[/dim] {rem.doc_url}")
        console.print()


def _export_fixes(findings: list[Finding], output_path: Path) -> None:
    """Export CLI remediation commands as a bash script, sorted by CVSS score."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        console.print("[yellow]No actionable findings - nothing to export.[/yellow]")
        return

    # Sort by CVSS score (highest priority first)
    actionable.sort(key=lambda f: f.cvss_score or 0, reverse=True)

    lines = [
        "#!/bin/bash",
        "set -e",
        "",
        "# =============================================================================",
        "# gcp-auditor remediation script",
        "# Generated by gcp-auditor - https://github.com/abdullahkamil/gcp-auditor",
        "# =============================================================================",
        "#",
        "# DRY RUN: All commands are commented out by default.",
        "# Review each command carefully, then uncomment to execute.",
        "#",
        f"# Total actionable findings: {len(actionable)}",
        "# Prioritized by CVSS score (highest risk first)",
        "# =============================================================================",
        "",
    ]

    for f in actionable:
        rem = f.remediation
        assert rem is not None  # noqa: S101
        cvss = f.cvss_score or 0
        lines.append(f"# [{f.cvss_severity}] CVSS: {cvss} - {f.title}")
        lines.append(f"# Resource: {f.resource_id}")
        if f.compliance_refs:
            lines.append(f"# Compliance: {', '.join(f.compliance_refs)}")
        lines.append(f"# {rem.cli}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"\n[green]Remediation script saved to {output_path}[/green]")
    console.print(f"[dim]  {len(actionable)} commands (commented out). Review before uncommenting.[/dim]")


@app.command()
def scan(
    project: Annotated[Optional[str], typer.Option("--project", help="GCP project ID")] = None,
    regions: Annotated[Optional[str], typer.Option("--regions", help="Comma-separated regions to scan")] = None,
    categories: Annotated[
        Optional[str], typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Output file path (.html, .json, .sarif, .md)")
    ] = None,
    fmt: Annotated[
        Optional[str], typer.Option("--format", "-f", help="Output format: json, html, sarif, markdown")
    ] = None,
    remediation: Annotated[
        bool, typer.Option("--remediation", "-R", help="Show remediation details for findings")
    ] = False,
    export_fixes: Annotated[
        Optional[Path], typer.Option("--export-fixes", help="Export CLI fix commands as bash script")
    ] = None,
    min_severity: Annotated[
        Optional[str], typer.Option("--min-severity", help="Minimum severity: critical, high, medium, low")
    ] = None,
    min_cvss: Annotated[Optional[float], typer.Option("--min-cvss", help="Minimum CVSS score (0.0-10.0)")] = None,
    service_account_key: Annotated[
        Optional[Path], typer.Option("--service-account-key", help="Path to service account JSON key")
    ] = None,
    config: Annotated[Optional[Path], typer.Option("--config", help="Path to .gcp-auditor.yml config file")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress console output")] = False,
) -> None:
    """Scan GCP infrastructure and generate a security audit report."""
    import os

    from cloud_audit.config import CloudAuditConfig, load_config
    from cloud_audit.scanner import run_scan

    # Load config file if provided or auto-detect
    cfg = load_config(config)

    # Override with CLI args
    region_list = None
    if regions:
        region_list = [r.strip() for r in regions.split(",")]
    elif cfg.regions:
        region_list = cfg.regions

    # Service account key: CLI > env > config
    effective_sa_key: str | None = (
        str(service_account_key)
        if service_account_key
        else os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or cfg.service_account_key
    )

    # Min severity: CLI > config
    effective_severity: Severity | None = None
    if min_severity:
        try:
            effective_severity = Severity(min_severity.lower())
        except ValueError:
            console.print(
                f"[red]Invalid --min-severity='{min_severity}'. Valid: {', '.join(s.value for s in Severity)}[/red]"
            )
            raise typer.Exit(2) from None
    elif cfg.min_severity:
        effective_severity = cfg.min_severity

    # Exclude checks from config
    all_excludes = cfg.exclude_checks

    # Build effective config for scanner
    effective_config = CloudAuditConfig(
        provider="gcp",
        project=project or cfg.project,
        service_account_key=effective_sa_key,
        regions=region_list,
        min_severity=effective_severity,
        min_cvss=min_cvss,
        exclude_checks=all_excludes,
        suppressions=cfg.suppressions,
    )

    # Validate format early (before scan) to avoid wasting time
    if fmt and fmt not in ("json", "html", "sarif", "markdown"):
        console.print(f"[red]Unknown format '{fmt}'. Available: json, html, sarif, markdown[/red]")
        raise typer.Exit(2)
    if fmt == "html" and not output:
        console.print("[red]HTML format requires --output <file.html>[/red]")
        raise typer.Exit(2)

    category_list = [c.strip().lower() for c in categories.split(",")] if categories else None

    # Initialize GCP provider
    from cloud_audit.providers.gcp import GCPProvider

    try:
        effective_project = project or cfg.project
        if not effective_project:
            console.print("[red]No project specified. Use --project or set in .gcp-auditor.yml[/red]")
            raise typer.Exit(2)

        cloud_provider = GCPProvider(
            project=effective_project,
            regions=region_list,
            service_account_key=effective_sa_key,
        )
    except Exception as e:
        console.print(f"[red]GCP authentication failed: {e}[/red]")
        console.print("\n[bold]Common fixes:[/bold]")
        console.print("  1. Authenticate: [cyan]gcloud auth application-default login[/cyan]")
        console.print("  2. Set project: [cyan]gcp-auditor scan --project my-project-id[/cyan]")
        console.print("  3. Use service account: [cyan]gcp-auditor scan --service-account-key sa.json[/cyan]")
        raise typer.Exit(2) from None

    # Run scan
    report, suppressed_count = run_scan(
        cloud_provider,
        categories=category_list,
        config=effective_config,
        quiet=quiet,
    )

    # Determine exit code: 0=clean, 1=findings, 2=errors
    has_findings = report.summary.total_findings > 0
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # Format output
    if fmt:
        _handle_format(fmt, report, output, quiet)
    elif output:
        # Backward compat: detect format from suffix
        suffix = output.suffix.lower()
        suffix_to_fmt = {".json": "json", ".html": "html", ".sarif": "sarif", ".md": "markdown"}
        detected_fmt = suffix_to_fmt.get(suffix)
        if detected_fmt:
            _handle_format(detected_fmt, report, output, quiet)
        else:
            console.print(f"[red]Cannot detect format from suffix '{suffix}'. Use --format explicitly.[/red]")
            raise typer.Exit(2)
    else:
        # Default: Rich console output
        if not quiet:
            _print_summary(report, suppressed_count)

            if remediation:
                _print_remediation(report.all_findings)

            if export_fixes:
                _export_fixes(report.all_findings, export_fixes)

    # Exit code
    if all_errored:
        raise typer.Exit(2)
    if has_findings:
        raise typer.Exit(1)


def _handle_format(fmt: str, report: ScanReport, output: Optional[Path], quiet: bool) -> None:
    """Handle different output formats."""
    if fmt == "json":
        json_output = report.model_dump_json(indent=2)
        if output:
            output.write_text(json_output, encoding="utf-8")
            if not quiet:
                console.print(f"\n[green]JSON report saved to {output}[/green]")
        else:
            console.print(json_output)

    elif fmt == "html":
        from cloud_audit.reports.html import render_html

        html = render_html(report)
        if output:
            output.write_text(html, encoding="utf-8")
            if not quiet:
                console.print(f"\n[green]HTML report saved to {output}[/green]")
        else:
            console.print(html)

    elif fmt == "sarif":
        from cloud_audit.reports.sarif import render_sarif

        sarif = render_sarif(report)
        if output:
            output.write_text(sarif, encoding="utf-8")
            if not quiet:
                console.print(f"\n[green]SARIF report saved to {output}[/green]")
        else:
            console.print(sarif)

    elif fmt == "markdown":
        from cloud_audit.reports.markdown import render_markdown

        md = render_markdown(report)
        if output:
            output.write_text(md, encoding="utf-8")
            if not quiet:
                console.print(f"\n[green]Markdown report saved to {output}[/green]")
        else:
            console.print(md)


@app.command()
def demo() -> None:
    """Show a demo scan with sample output (no GCP credentials needed)."""
    import time

    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

    console.print()

    # Simulate progress bar
    with Progress(
        TextColumn("[bold]Running 30 checks on GCP..."),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=30)
        for _ in range(30):
            time.sleep(0.05)
            progress.advance(task)

    # Risk Assessment Panel (CVSS-based)
    console.print()
    console.print(
        Panel(
            "[bold red]🔴 CRITICAL[/bold red]\n\n"
            "Max CVSS: [bold red]9.8[/bold red]\n"
            "Avg CVSS: 4.2\n"
            "Total Risk: 892\n\n"
            "⚠️  2 finding(s) require immediate action",
            title="[bold]Risk Assessment[/bold]",
            border_style="red",
            width=40,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "GCP")
    table.add_row("Project", "demo-project-123")
    table.add_row("Duration", "12.5s")
    table.add_row("Resources scanned", "52")
    table.add_row("Checks passed", "[green]14[/green]")
    table.add_row("Checks failed", "[red]6[/red]")
    table.add_row("Checks errored", "[yellow]10[/yellow]")
    console.print(table)

    # Findings by CVSS severity
    console.print("\n[bold]Findings by CVSS severity:[/bold]")
    console.print("  [bold bright_red]🔴 CRITICAL: 2[/bold bright_red]")
    console.print("  [red]🟠 HIGH: 0[/red]")
    console.print("  [yellow]🟡 MEDIUM: 46[/yellow]")
    console.print("  [cyan]🟢 LOW: 0[/cyan]")

    # Attack surface
    console.print("\n[bold]Attack surface:[/bold]")
    console.print("  🌐 Network-exploitable: 2")
    console.print("  🏢 Local-access only: 46")

    # Top findings by CVSS
    console.print("\n[bold]Top findings by CVSS score (5 of 48):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("CVSS", width=8, justify="right")
    ft.add_column("Sev", width=8)
    ft.add_column("Region", width=14)
    ft.add_column("Check", width=16)
    ft.add_column("Resource")
    ft.add_column("Title", max_width=45)

    ft.add_row(
        "[bold bright_red]9.8[/bold bright_red]",
        "[bold red]CRIT[/bold red]",
        "[dim]global[/dim]",
        "gcp-firewall-001",
        "projects/demo/firewalls/default-allow-ssh",
        "SSH exposed to 0.0.0.0/0",
    )
    ft.add_row(
        "[bold bright_red]9.8[/bold bright_red]",
        "[bold red]CRIT[/bold red]",
        "[dim]global[/dim]",
        "gcp-firewall-001",
        "projects/demo/firewalls/default-allow-rdp",
        "RDP exposed to 0.0.0.0/0",
    )
    ft.add_row(
        "[yellow]4.1[/yellow]",
        "[yellow]MED[/yellow]",
        "[dim]global[/dim]",
        "gcp-compute-004",
        "projects/demo",
        "OS Login not enabled at project level",
    )
    ft.add_row(
        "[yellow]3.8[/yellow]",
        "[yellow]MED[/yellow]",
        "[dim]global[/dim]",
        "gcp-firewall-002",
        "projects/demo/networks/default",
        "Default VPC network exists",
    )
    ft.add_row(
        "[cyan]2.0[/cyan]",
        "[yellow]MED[/yellow]",
        "[dim]us-central1[/dim]",
        "gcp-firewall-003",
        "projects/demo/subnetworks/default",
        "VPC Flow Logs disabled on subnet",
    )
    console.print(ft)

    console.print("\n  [dim]... and 43 more. Run with --output for full report.[/dim]")

    # Remediation preview
    console.print("\n[bold]Remediation details (1 of 6 actionable findings):[/bold]\n")

    console.print("  [bold bright_red]🔴 CVSS 9.8[/bold bright_red]  SSH exposed to 0.0.0.0/0")
    console.print("  [dim]Resource:[/dim]   projects/demo/firewalls/default-allow-ssh")
    console.print("  [dim]Compliance:[/dim] CIS GCP 3.6, ISO 27001 A.13.1")
    console.print("  [dim]Effort:[/dim]     [green]LOW[/green]")
    sg_cli = "gcloud compute firewall-rules update default-allow-ssh --source-ranges=10.0.0.0/8"
    console.print(f"  [dim]CLI:[/dim]        [cyan]{sg_cli}[/cyan]")
    console.print('  [dim]Terraform:[/dim]  source_ranges = ["10.0.0.0/8"]  # Restrict to internal')
    sg_docs = "https://cloud.google.com/vpc/docs/using-firewalls"
    console.print(f"  [dim]Docs:[/dim]       {sg_docs}")
    console.print()

    console.print(
        "[dim]This is sample output. Run [bold]gcp-auditor scan --project my-project[/bold] for a real scan.[/dim]"
    )


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"gcp-auditor {__version__}")


@app.command()
def list_checks() -> None:
    """List all available security checks with their CVSS scores."""
    from cloud_audit.cvss import CHECK_CVSS_PROFILES

    console.print("\n[bold]Available Security Checks:[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Check ID", width=18)
    table.add_column("CVSS", width=8, justify="right")
    table.add_column("Severity", width=12)
    table.add_column("Category", width=12)
    table.add_column("Description")

    # Sort by CVSS score (highest first)
    sorted_checks = sorted(CHECK_CVSS_PROFILES.items(), key=lambda x: x[1].calculate_score(), reverse=True)

    for check_id, profile in sorted_checks:
        score = profile.calculate_score()
        severity = profile.get_severity()
        color = CVSS_COLORS.get(severity, "white")

        # Get category from check_id
        category = check_id.split("-")[1].upper() if "-" in check_id else "OTHER"

        table.add_row(
            check_id,
            f"[{color}]{score}[/{color}]",
            f"[{color}]{severity}[/{color}]",
            category,
            profile.to_vector_string()[:50] + "...",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(CHECK_CVSS_PROFILES)} checks[/dim]")


if __name__ == "__main__":
    app()
