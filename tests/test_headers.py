import unittest
from aegisscan.modules.headers import audit_headers


class TestHeadersAudit(unittest.TestCase):
    def test_missing_all_security_headers(self):
        headers = {}
        items, findings = audit_headers(headers, "https://example.com")

        # Expect fails for CSP, HSTS, X-Frame-Options, X-Content-Type-Options
        fail_headers = [i.header for i in items if i.status == "FAIL"]
        self.assertIn("Content-Security-Policy", fail_headers)
        self.assertIn("Strict-Transport-Security", fail_headers)
        self.assertIn("X-Frame-Options", fail_headers)
        self.assertIn("X-Content-Type-Options", fail_headers)

        finding_titles = [f.title for f in findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in finding_titles))
        self.assertTrue(any("Strict Transport Security" in t for t in finding_titles))

    def test_configured_secure_headers(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        items, findings = audit_headers(headers, "https://example.com")

        # None should be FAIL
        fails = [i for i in items if i.status == "FAIL"]
        self.assertEqual(len(fails), 0)
        self.assertEqual(len(findings), 0)

    def test_weak_csp_detection(self):
        headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
        }
        items, findings = audit_headers(headers, "https://example.com")
        csp_item = next(i for i in items if i.header == "Content-Security-Policy")
        self.assertEqual(csp_item.status, "WARN")
        self.assertTrue(any("Weak Directives" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
