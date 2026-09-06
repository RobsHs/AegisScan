import unittest
import tempfile
import os
import json
from io import StringIO
from rich.console import Console

from aegisscan.core.models import (
    ScanResult,
    ScanSummary,
    Finding,
    FindingCategory,
    Severity,
    HeaderAuditItem,
    ExposureAuditItem,
)
from aegisscan.reporters.html_report import generate_html_report
from aegisscan.reporters.json_report import generate_json_report
from aegisscan.reporters.console import render_console_report


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.summary = ScanSummary(
            target_url="https://sec-target.local",
            target_host="sec-target.local",
            scan_date="2026-09-06 10:00:00 UTC",
            scan_duration_sec=2.1,
            score=72,
            grade="C",
            critical_count=0,
            high_count=1,
            medium_count=1,
            low_count=1,
            info_count=0,
            total_findings=3,
        )
        self.findings = [
            Finding(
                id="SEC-001",
                category=FindingCategory.HEADERS,
                severity=Severity.HIGH,
                title="Missing CSP",
                description="No CSP",
                impact="XSS",
                remediation="Add CSP",
            )
        ]
        self.headers = [
            HeaderAuditItem(
                header="Content-Security-Policy",
                present=False,
                value=None,
                status="FAIL",
                recommendation="Add CSP",
                severity_if_missing=Severity.HIGH,
            )
        ]
        self.exposures = [
            ExposureAuditItem(
                path="/.env",
                url="https://sec-target.local/.env",
                status_code=404,
                exposed=False,
                category="Secrets",
                risk_level=Severity.CRITICAL,
            )
        ]
        self.result = ScanResult(
            summary=self.summary,
            findings=self.findings,
            headers=self.headers,
            exposures=self.exposures,
        )

    def test_json_report_generation(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            path = tf.name

        try:
            generate_json_report(self.result, path)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["score"], 72)
            self.assertEqual(len(data["findings"]), 1)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_html_report_generation(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            path = tf.name

        try:
            generate_html_report(self.result, path)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("AegisScan", content)
            self.assertIn("sec-target.local", content)
            self.assertIn("Missing CSP", content)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_console_render(self):
        buf = StringIO()
        test_console = Console(file=buf, force_terminal=False, color_system=None)
        render_console_report(self.result, console=test_console)
        output = buf.getvalue()
        self.assertIn("AegisScan", output)
        self.assertIn("sec-target.local", output)


if __name__ == "__main__":
    unittest.main()
