"""
Rich Console Reporter for AegisScan.
Produces beautiful terminal dashboards, colored findings tables, and remediation summaries.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from aegisscan.core.models import ScanResult, Severity

BANNER = r"""[bold cyan]
     _    _____ ____ ___ ____  ____   ____    _    _   _ 
    / \  | ____/ ___|_ _/ ___|/ ___| / ___|  / \  | \ | |
   / _ \ |  _|| |  _ | |\___ \\___ \| |     / _ \ |  \| |
  / ___ \| |__| |_| || | ___) |___) | |___ / ___ \| |\  |
 /_/   \_\_____\____|___|____/|____/ \____//_/   \_\_| \_|
[/bold cyan][dim cyan]  Modern Web Security Posture & Exposure Audit Tool v1.0.0
  Author: RobsHs | Community Open-Source Edition[/dim cyan]
"""

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "bold cyan",
}

GRADE_COLORS = {
    "A+": "bold green",
    "A": "bold green",
    "B": "bold cyan",
    "C": "bold yellow",
    "D": "bold red",
    "F": "bold white on red",
}


def render_console_report(result: ScanResult, console: Console | None = None) -> None:
    """Renders the comprehensive scan findings to terminal."""
    if console is None:
        console = Console()

    console.print(BANNER)

    # 1. Target Summary & Grade Panel
    summary = result.summary
    grade_color = GRADE_COLORS.get(summary.grade, "white")

    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column("Key", style="bold white")
    summary_table.add_column("Val", style="cyan")
    summary_table.add_column("Key2", style="bold white")
    summary_table.add_column("Val2", style="cyan")

    summary_table.add_row("Target Host:", summary.target_host, "Scan Date:", summary.scan_date)
    summary_table.add_row("Target URL:", summary.target_url, "Duration:", f"{summary.scan_duration_sec}s")
    summary_table.add_row(
        "Posture Grade:",
        f"[{grade_color}]{summary.grade}[/{grade_color}] (Score: {summary.score}/100)",
        "Total Issues:",
        f"[bold red]{summary.critical_count} Crit[/], [red]{summary.high_count} High[/], [yellow]{summary.medium_count} Med[/], [blue]{summary.low_count} Low[/]",
    )

    console.print(
        Panel(
            summary_table,
            title="[bold green][+] AUDIT SUMMARY[/bold green]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # 2. HTTP Security Headers Table
    headers_table = Table(
        title="HTTP Security Headers Status",
        box=box.ROUNDED,
        header_style="bold magenta",
        title_style="bold white",
        show_lines=True,
    )
    headers_table.add_column("Security Header", style="cyan", width=28)
    headers_table.add_column("Status", width=10, justify="center")
    headers_table.add_column("Current Value / Recommendation", style="white")

    for h in result.headers:
        if h.status == "PASS":
            status_badge = "[bold green]PASS[/bold green]"
            val = f"[dim]{h.value}[/dim]" if h.value else "[green]Configured[/green]"
        elif h.status == "WARN":
            status_badge = "[bold yellow]WARN[/bold yellow]"
            val = f"[yellow]{h.recommendation}[/yellow]"
        else:
            status_badge = "[bold red]FAIL[/bold red]"
            val = f"[red]{h.recommendation}[/red]"

        headers_table.add_row(h.header, status_badge, val)

    console.print(headers_table)

    # 3. Sensitive Exposure Table (if exposed or sample)
    exposed_items = [e for e in result.exposures if e.exposed]
    if exposed_items:
        exp_table = Table(
            title="[!] EXPOSED SENSITIVE FILES & PATHS (LEAKS DETECTED)",
            box=box.HEAVY_EDGE,
            header_style="bold white on red",
            title_style="bold red",
            show_lines=True,
        )
        exp_table.add_column("Path", style="bold red", width=24)
        exp_table.add_column("Risk", justify="center", width=12)
        exp_table.add_column("Category", style="yellow", width=22)
        exp_table.add_column("Evidence Snippet", style="white")

        for exp in exposed_items:
            risk_badge = f"[{SEVERITY_COLORS.get(exp.risk_level, 'white')}]{exp.risk_level.value}[/]"
            snippet = (exp.evidence_snippet or "HTTP 200 OK").replace("\n", " ")[:60]
            exp_table.add_row(exp.path, risk_badge, exp.category, f"[dim]{snippet}...[/dim]")

        console.print(exp_table)
    else:
        console.print(
            Panel(
                "[green][OK] No high-risk sensitive paths or repository files were detected publicly exposed.[/green]",
                title="[bold green]Sensitive Exposure Check[/bold green]",
                box=box.ROUNDED,
            )
        )

    # 4. SSL/TLS & DNS Posture Cards
    tls = result.tls
    dns = result.dns_mail

    tls_summary = "Not Scanned"
    if tls:
        if tls.supported:
            status_str = "[bold red]EXPIRED[/bold red]" if tls.is_expired else f"[green]{tls.days_left} days left[/green]"
            tls_summary = f"[bold cyan]Issuer:[/] {tls.issuer}\n[bold cyan]Protocol:[/] {tls.protocol_version}\n[bold cyan]Expiry:[/] {status_str}"
        else:
            tls_summary = f"[red]{tls.issues[0] if tls.issues else 'No TLS Support'}[/red]"

    dns_summary = "Not Scanned"
    if dns:
        spf_c = "green" if "ENFORCED" in dns.spf_status else ("yellow" if "SOFTFAIL" in dns.spf_status else "red")
        dmarc_c = "green" if "ENFORCED" in dns.dmarc_status else ("yellow" if "WEAK" in dns.dmarc_status else "red")
        dns_summary = (
            f"[bold cyan]SPF:[/] [{spf_c}]{dns.spf_status}[/{spf_c}]\n"
            f"[bold cyan]DMARC:[/] [{dmarc_c}]{dns.dmarc_status}[/{dmarc_c}]\n"
            f"[bold cyan]MX Backup:[/] {'Found' if dns.has_mx else 'None'}"
        )

    infra_table = Table.grid(expand=True)
    infra_table.add_column(ratio=1)
    infra_table.add_column(ratio=1)
    infra_table.add_row(
        Panel(tls_summary, title="[bold cyan][*] SSL / TLS Health[/bold cyan]", box=box.ROUNDED),
        Panel(dns_summary, title="[bold cyan][*] DNS & Email Defense[/bold cyan]", box=box.ROUNDED),
    )
    console.print(infra_table)

    # 5. Detailed Findings & Remediation Guide
    if result.findings:
        console.print("\n[bold yellow][!] IDENTIFIED SECURITY FINDINGS & MITIGATION[/bold yellow]")
        for idx, f in enumerate(result.findings, 1):
            badge = f"[{SEVERITY_COLORS.get(f.severity, 'white')}][{f.severity.value}][/]"
            category_tag = f"[dim cyan]({f.category.value})[/dim cyan]"

            finding_text = Text()
            finding_text.append(f"\nDescription:\n", style="bold white")
            finding_text.append(f"{f.description}\n", style="white")

            finding_text.append(f"Impact:\n", style="bold red")
            finding_text.append(f"{f.impact}\n", style="dim white")

            finding_text.append(f"Remediation:\n", style="bold green")
            finding_text.append(f"{f.remediation}\n", style="green")

            if f.evidence:
                finding_text.append(f"Evidence:\n", style="bold magenta")
                finding_text.append(f"{f.evidence}\n", style="dim magenta")

            console.print(
                Panel(
                    finding_text,
                    title=f"{badge} {f.title} {category_tag}",
                    border_style="red" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow",
                    box=box.ROUNDED,
                )
            )
    else:
        console.print(
            Panel(
                "[bold green][OK] Excellent security posture! No security findings detected.[/bold green]",
                box=box.ROUNDED,
            )
        )

    console.print("\n[dim]AegisScan audit complete. Use '--output-html report.html' for executive dashboard.[/dim]\n")
