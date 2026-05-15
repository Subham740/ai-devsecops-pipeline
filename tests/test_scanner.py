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
        self.assertTrue(all("cvss" in finding for finding in result["findings"]))
        self.assertTrue(all("risk_weight" in finding for finding in result["findings"]))

    def test_scanner_detects_eval_and_hardcoded_secret(self):
        code = """
api_key = "secret-key-123456"
eval(user_supplied_expression)
"""
        result = scan_code(code, "dangerous.py")

        self.assertEqual(result["status"], "needs_attention")
        self.assertSetEqual(
            {finding["id"] for finding in result["findings"]},
            {"EXEC001", "SECRET001"},
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

    def test_scanner_detects_python_syntax_errors(self):
        code = """
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class ScanForm(FlaskForm):
    validators=[DataRequired(), Length(min=1, max=100)],
    render_kw={"placeholder": "e.g., my_script.py"})
    code = TextAreaField('Code to Scan',
                         validators=["subham"]
                         render_kw={"placeholder": "Paste your Python code here for security analysis...",
                                    "rows": 8})
    submit = SubmitField('Run Security Scan')
"""
        result = scan_code(code, "forms.py")

        self.assertEqual(result["status"], "needs_attention")
        self.assertTrue(any(finding["id"] == "SYNTAX001" for finding in result["findings"]))

    def test_rule_catalog_is_exposed(self):
        catalog = get_rule_catalog()

        self.assertTrue(any(rule["id"] == "SQLI001" for rule in catalog))
        self.assertTrue(any(rule["id"] == "SYNTAX001" for rule in catalog))
        self.assertTrue(all("cvss" in rule for rule in catalog))


if __name__ == "__main__":
    unittest.main()
