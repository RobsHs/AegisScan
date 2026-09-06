"""
Command Line Interface for AegisScan.
Author: RobsHs
"""

import argparse
import asyncio
import sys
from rich.console import Console

from aegisscan import __version__
from aegisscan.core.scanner import AegisScanner
from aegisscan.core.models import Severity
from aegisscan.reporters.console import render_console_report
from aegisscan.reporters.html_report import generate_html_report
from aegisscan.reporters.json_report import generate_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisscan",
        description="AegisScan - Modern Web Security Posture & Sensitive Exposure Audit Tool",
        epilog="Example: aegisscan https://example.com --output-html report.html --fail-on high",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL or domain to audit (e.g. https://example.com or example.com)",
    )
    parser.add_argument(
        "-u", "--url",
        dest="target_flag",
        help="Target URL (alternative to positional target)",
    )
    parser.add_argument(
        "-o", "--output-html",
        metavar="FILE",
        help="Path to save modern interactive HTML security report",
    )
    parser.add_argument(
        "-j", "--output-json",
        metavar="FILE",
        help="Path to export raw structured JSON findings for CI/CD",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Fail (exit with code 1) if findings match or exceed specified severity (for DevSecOps CI/CD)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Request timeout in seconds (default: 8.0)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Max concurrent asynchronous exposure checks (default: 10)",
    )
    parser.add_argument(
        "--skip-exposure",
        action="store_true",
        help="Skip sensitive file and directory exposure scanning",
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip DNS, SPF, and DMARC inspection",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress terminal UI dashboard output",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"AegisScan v{__version__} by RobsHs",
    )
    return parser


def main() -> None:
    # Ensure UTF-8 output on Windows consoles
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    target = args.target or args.target_flag
    if not target:
        parser.print_help()
        sys.exit(1)

    console = Console()
    scanner = AegisScanner(
        target_url=target,
        timeout=args.timeout,
        max_concurrency=args.concurrency,
        skip_exposure=args.skip_exposure,
        skip_dns=args.skip_dns,
    )

    if not args.quiet:
        with console.status("[bold cyan][*] Initializing AegisScan engine...", spinner="dots") as status:
            def update_progress(msg: str) -> None:
                status.update(f"[bold cyan][*] {msg}")

            result = asyncio.run(scanner.run_scan(progress_callback=update_progress))
    else:
        result = asyncio.run(scanner.run_scan())

    # Render console report
    if not args.quiet:
        render_console_report(result, console=console)

    # Save HTML report
    if args.output_html:
        generate_html_report(result, args.output_html)
        if not args.quiet:
            console.print(f"[bold green]✔ HTML report generated successfully:[/] [cyan]{args.output_html}[/]")

    # Save JSON report
    if args.output_json:
        generate_json_report(result, args.output_json)
        if not args.quiet:
            console.print(f"[bold green]✔ JSON report saved successfully:[/] [cyan]{args.output_json}[/]")

    # CI/CD fail-on threshold check
    if args.fail_on:
        threshold = args.fail_on.upper()
        severity_rank = {
            Severity.CRITICAL.value: 4,
            Severity.HIGH.value: 3,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 1,
            Severity.INFO.value: 0,
        }
        threshold_rank = severity_rank.get(threshold, 3)

        violating = [
            f for f in result.findings
            if severity_rank.get(f.severity.value, 0) >= threshold_rank
        ]

        if violating:
            if not args.quiet:
                console.print(
                    f"\n[bold red]❌ CI/CD Pipeline Failed: {len(violating)} finding(s) met or exceeded '--fail-on {args.fail_on}' threshold![/bold red]"
                )
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
