import unittest
from aegisscan.modules.exposure import EXPOSURE_TARGETS


class TestExposureSignatures(unittest.TestCase):
    def test_git_head_signature(self):
        git_target = next(t for t in EXPOSURE_TARGETS if t["path"] == "/.git/HEAD")
        sig = git_target["signature"]

        # Valid git HEAD
        self.assertTrue(sig.search("ref: refs/heads/main\n"))
        self.assertTrue(sig.search("4a3c2b1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b"))

        # HTML 404 page (must NOT match)
        self.assertIsNone(sig.search("<!DOCTYPE html><html><body>404 Not Found</body></html>"))

    def test_env_signature(self):
        env_target = next(t for t in EXPOSURE_TARGETS if t["path"] == "/.env")
        sig = env_target["signature"]

        # Valid .env
        self.assertTrue(sig.search("DB_HOST=localhost\nDB_PASSWORD=secret\n"))

        # Generic HTML error
        self.assertIsNone(sig.search("<html>Error Page</html>"))

    def test_sql_dump_signature(self):
        sql_target = next(t for t in EXPOSURE_TARGETS if t["path"] == "/dump.sql")
        sig = sql_target["signature"]

        # Valid SQL dump
        self.assertTrue(sig.search("CREATE TABLE users (id INT PRIMARY KEY);"))
        self.assertTrue(sig.search("-- MySQL dump 10.13"))


if __name__ == "__main__":
    unittest.main()
