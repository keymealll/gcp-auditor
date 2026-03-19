"""Generate animated demo GIF for README using Rich console export + Pillow."""

import io
import textwrap

from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# We'll render multiple frames as SVG, convert to PNG via cairosvg, then combine into GIF
import cairosvg


TARGET_LINES = 52  # Fixed terminal height in lines


def pad_to_height(console, current_lines: int):
    """Add blank lines so every frame has the same terminal height."""
    for _ in range(max(0, TARGET_LINES - current_lines)):
        console.print()


def render_frame(lines_to_show: int, progress: int = 0) -> bytes:
    """Render a frame as PNG bytes."""
    buf = io.StringIO()
    console = Console(record=True, width=90, force_terminal=True, file=buf)

    # Frame 1: just the command
    console.print()
    console.print("[bold]$[/bold] gcp-auditor scan --project my-project")

    if lines_to_show < 1:
        pad_to_height(console, 3)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 2+: progress bar
    console.print()
    console.print("[bold]Running 30 checks on GCP...[/bold]")
    bar_len = min(progress, 40)
    bar = "\u2501" * bar_len + " " * (40 - bar_len)
    done = int(progress * 30 / 40)
    console.print(f"[green]{bar}[/green] {done}/30")

    if lines_to_show < 2:
        pad_to_height(console, 6)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 3+: risk assessment + summary
    console.print()
    console.print(
        Panel(
            "[bold red]🔴 CRITICAL[/bold red]\n\nMax CVSS: [bold red]9.8[/bold red]\nAvg CVSS: 4.2",
            title="[bold]Risk Assessment[/bold]",
            border_style="red",
            width=40,
        )
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "GCP")
    table.add_row("Project", "my-gcp-project")
    table.add_row("Duration", "12.5s")
    table.add_row("Resources scanned", "52")
    table.add_row("Checks passed", "[green]14[/green]")
    table.add_row("Checks failed", "[red]6[/red]")
    console.print(table)

    if lines_to_show < 3:
        pad_to_height(console, 16)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 4+: severity
    console.print("\n[bold]Findings by CVSS severity:[/bold]")
    console.print("  [bold red]🔴 CRITICAL: 2[/bold red]")
    console.print("  [red]🟠 HIGH: 0[/red]")
    console.print("  [yellow]🟡 MEDIUM: 46[/yellow]")
    console.print("  [cyan]🟢 LOW: 0[/cyan]")

    if lines_to_show < 4:
        pad_to_height(console, 22)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 5+: findings table
    console.print("\n[bold]Top findings (5 of 48):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("CVSS", width=8)
    ft.add_column("Sev", width=8)
    ft.add_column("Check", width=16)
    ft.add_column("Resource", width=28)
    ft.add_column("Title", max_width=25)
    ft.add_row(
        "[bold red]9.8[/bold red]", "[bold red]CRIT[/bold red]", "gcp-firewall-001",
        "projects/demo/...", "SSH exposed to 0.0.0.0/0",
    )
    ft.add_row(
        "[bold red]9.8[/bold red]", "[bold red]CRIT[/bold red]", "gcp-firewall-001",
        "projects/demo/...", "RDP exposed to 0.0.0.0/0",
    )
    ft.add_row(
        "[yellow]4.1[/yellow]", "[yellow]MED[/yellow]", "gcp-compute-004",
        "projects/demo", "OS Login not enabled",
    )
    ft.add_row(
        "[yellow]3.8[/yellow]", "[yellow]MED[/yellow]", "gcp-firewall-002",
        "projects/demo/...", "Default VPC exists",
    )
    ft.add_row(
        "[cyan]2.0[/cyan]", "[yellow]MED[/yellow]", "gcp-firewall-003",
        "projects/demo/...", "VPC Flow Logs disabled",
    )
    console.print(ft)

    if lines_to_show < 5:
        pad_to_height(console, 30)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 6+: remediation
    console.print("\n[bold]Remediation (1 of 6 actionable):[/bold]\n")

    console.print("  [bold red]🔴 CVSS 9.8[/bold red]  SSH exposed to 0.0.0.0/0")
    console.print("  [dim]Resource:[/dim] projects/demo/firewalls/default-allow-ssh")
    console.print("  [dim]Compliance:[/dim] CIS GCP 3.6  [dim]Effort:[/dim] [green]LOW[/green]")
    console.print(
        "  [dim]CLI:[/dim]  [cyan]gcloud compute firewall-rules update default-allow-ssh \\"
        " --source-ranges=10.0.0.0/8[/cyan]"
    )
    console.print(
        '  [dim]Terraform:[/dim]  source_ranges = ["10.0.0.0/8"]'
    )
    console.print()
    console.print("[green]HTML report saved to report.html[/green]")

    pad_to_height(console, 48)
    svg = console.export_svg(title="gcp-auditor")
    return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)


def main():
    frames = []

    # Frame 0: command typed (hold 1s = 2 frames at 500ms)
    png_data = render_frame(0)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frames 1-8: progress bar animation (fast)
    for p in range(0, 41, 5):
        png_data = render_frame(1, progress=p)
        img = Image.open(io.BytesIO(png_data))
        frames.append(img.copy())

    # Frame: health score + summary (hold 1.5s)
    png_data = render_frame(2)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: severity (hold 1s)
    png_data = render_frame(3)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table (hold 2s)
    png_data = render_frame(4)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table done (hold 1s)
    png_data = render_frame(5)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Final frame: full output with remediation (hold 4s)
    png_data = render_frame(6)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Durations in ms per frame
    durations = (
        [800]           # command
        + [120] * 9     # progress bar (9 steps)
        + [1500]        # health score
        + [1000]        # severity
        + [1500]        # findings table appearing
        + [1000]        # findings done
        + [5000]        # final with remediation (long hold)
    )

    # Ensure all frames same size (pad to largest)
    max_w = max(f.width for f in frames)
    max_h = max(f.height for f in frames)

    padded_frames = []
    for f in frames:
        if f.width < max_w or f.height < max_h:
            # Create dark background and paste frame
            bg = Image.new("RGBA", (max_w, max_h), (40, 42, 54, 255))
            bg.paste(f, (0, 0))
            padded_frames.append(bg.convert("RGB"))
        else:
            padded_frames.append(f.convert("RGB"))

    # Save as animated GIF
    padded_frames[0].save(
        "assets/demo.gif",
        save_all=True,
        append_images=padded_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    import os
    size = os.path.getsize("assets/demo.gif")
    print(f"GIF saved to assets/demo.gif ({size / 1024:.0f} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
