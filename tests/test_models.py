import unittest
from aegisscan.core.models import (
    Finding,
    FindingCategory,
    Severity,
    HeaderAuditItem,
    ScanSummary,
    ScanResult,
)


class TestModels(unittest.TestCase):
    def test_finding_to_dict(self):
        finding = Finding(
            id="SEC-001",
            category=FindingCategory.HEADERS,
            severity=Severity.HIGH,
            title="Missing CSP",
            description="No CSP found",
            impact="XSS vulnerability",
            remediation="Add CSP header",
            evidence="Header null",
            references=["https://owasp.org"],
        )
        d = finding.to_dict()
        self.assertEqual(d["id"], "SEC-001")
        self.assertEqual(d["category"], "Security Headers")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["title"], "Missing CSP")

    def test_scan_result_serialization(self):
        summary = ScanSummary(
            target_url="https://test.local",
            target_host="test.local",
            scan_date="2026-09-06 12:00:00 UTC",
            scan_duration_sec=1.5,
            score=85,
            grade="B",
            critical_count=0,
            high_count=1,
            medium_count=0,
            low_count=0,
            info_count=0,
            total_findings=1,
        )
        res = ScanResult(summary=summary)
        data = res.to_dict()
        self.assertEqual(data["summary"]["score"], 85)
        self.assertEqual(data["summary"]["grade"], "B")


if __name__ == "__main__":
    unittest.main()

