import unittest
from aegisscan.modules.cookies import audit_cookies


class TestCookiesAudit(unittest.TestCase):
    def test_insecure_cookie(self):
        cookies = ["session_id=abcdef123456; Path=/"]
        items, findings = audit_cookies(cookies, "https://example.com")
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertFalse(item.secure)
        self.assertFalse(item.httponly)
        self.assertIsNone(item.samesite)

        # Findings should include missing Secure, HttpOnly, and SameSite
        titles = [f.title for f in findings]
        self.assertTrue(any("Missing 'Secure'" in t for t in titles))
        self.assertTrue(any("Missing 'HttpOnly'" in t for t in titles))
        self.assertTrue(any("SameSite" in t for t in titles))

    def test_hardened_cookie(self):
        cookies = ["__Host-auth=secret_token; Secure; HttpOnly; SameSite=Strict; Path=/"]
        items, findings = audit_cookies(cookies, "https://example.com")
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertTrue(item.secure)
        self.assertTrue(item.httponly)
        self.assertEqual(item.samesite.lower(), "strict")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
