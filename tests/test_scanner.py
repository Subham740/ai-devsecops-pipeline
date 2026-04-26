from __future__ import annotations

import unittest

from app.scanner import get_rule_catalog, scan_code


class ScannerTests(unittest.TestCase):
    def test_scanner_detects_multiple_findings(self):
        code = """
import subprocess

cursor.execute(f"SELECT * FROM users WHERE username = {username}")
subprocess.run(user_cmd, shell=True)
"""
        result = scan_code(code, "danger.py")

        self.assertEqual(result["status"], "needs_attention")
        self.assertEqual(result["finding_count"], 2)
        self.assertSetEqual(
            {finding["id"] for finding in result["findings"]},
            {"SQLI001", "CMDI001"},
        )

    def test_scanner_passes_clean_code(self):
        code = """
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
"""
        result = scan_code(code, "safe.py")

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["findings"], [])

    def test_rule_catalog_is_exposed(self):
        catalog = get_rule_catalog()

        self.assertTrue(any(rule["id"] == "SQLI001" for rule in catalog))


if __name__ == "__main__":
    unittest.main()
