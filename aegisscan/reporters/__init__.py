"""
Reporting modules for AegisScan (Console, HTML, JSON).
"""

from aegisscan.reporters.console import render_console_report
from aegisscan.reporters.html_report import generate_html_report
from aegisscan.reporters.json_report import generate_json_report

__all__ = [
    "render_console_report",
    "generate_html_report",
    "generate_json_report",
]
