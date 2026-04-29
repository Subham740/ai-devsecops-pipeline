from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.demo_password = "TestPass123!"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(root / "test.db"),
                "SCAN_ROOT": str(root),
                "DATA_BACKEND": "sql",
                "MONGODB_URI": "",
                "MONGODB_DB_NAME": "",
                "DEMO_USERNAME": "tester",
                "DEMO_PASSWORD_HASH": generate_password_hash(self.demo_password),
                "AI_PROVIDER": "auto",
                "GEMINI_API_KEY": "",
                "OPENAI_API_KEY": "",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def login(self):
        response = self.client.post(
            "/login",
            json={"username": "tester", "password": self.demo_password},
        )
        self.assertEqual(response.status_code, 200)
        return response

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["gemini_enabled"], False)
        self.assertIn("data_backend", data)

    def test_login_success(self):
        response = self.login()

        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("session_token", data)

    def test_dashboard_starts_without_mock_scan_data(self):
        self.login()

        response = self.client.get("/dashboard")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("No scans recorded yet.", page)
        self.assertIn("Interactive Scanner", page)
        self.assertNotIn("SCAN-001", page)

    def test_scan_persists_and_returns_history(self):
        self.login()
        code = "import subprocess\\nsubprocess.run(cmd, shell=True)"
        scan_response = self.client.post("/scan", json={"code": code, "filename": "job.py"})

        self.assertEqual(scan_response.status_code, 200)
        scan_data = scan_response.get_json()
        self.assertEqual(scan_data["finding_count"], 1)
        self.assertEqual(scan_data["target_name"], "job.py")

        history_response = self.client.get("/scans")
        history_data = history_response.get_json()
        self.assertEqual(history_response.status_code, 200)
        self.assertEqual(history_data["status"], "ok")
        self.assertEqual(len(history_data["scans"]), 1)
        self.assertEqual(history_data["scans"][0]["target_name"], "job.py")
        self.assertEqual(history_data["scans"][0]["findings"][0]["id"], "CMDI001")

        scan_id = history_data["scans"][0]["id"]
        detail_response = self.client.get(f"/scans/{scan_id}")
        detail_data = detail_response.get_json()
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_data["status"], "ok")
        self.assertEqual(detail_data["scan"]["target_name"], "job.py")

        stats_response = self.client.get("/api/stats")
        stats_data = stats_response.get_json()
        self.assertEqual(stats_response.status_code, 200)
        self.assertEqual(stats_data["total_scans"], 1)
        self.assertEqual(stats_data["total_findings"], 1)
        self.assertEqual(stats_data["passed_scans"], 0)

        metrics_response = self.client.get("/metrics")
        metrics_data = metrics_response.get_json()
        self.assertEqual(metrics_response.status_code, 200)
        self.assertEqual(metrics_data["status"], "ok")
        self.assertEqual(metrics_data["metrics"]["rule_breakdown"]["CMDI001"], 1)

    def test_scan_rejects_path_traversal(self):
        self.login()
        response = self.client.post(
            "/scan",
            json={"file_path": "../outside.py", "code": "print('x')"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_rules_endpoint_returns_catalog(self):
        self.login()
        response = self.client.get("/rules")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(any(rule["id"] == "SQLI001" for rule in data["rules"]))

    def test_fix_endpoint_uses_fallback_without_ai_key(self):
        self.login()
        response = self.client.post(
            "/fix",
            json={
                "finding_id": "CMDI001",
                "title": "Command Injection",
                "description": "Unsafe shell execution detected.",
                "code": "subprocess.run(user_cmd, shell=True)",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["provider"], "fallback")
        self.assertIn("secure_example", data)

    @patch("app.dashboard.routes.generate_remediation")
    def test_fix_endpoint_uses_ai_helper_when_available(self, mock_generate_remediation):
        self.login()
        mock_generate_remediation.return_value = {
            "status": "ok",
            "provider": "gemini",
            "title": "Command Injection",
            "explanation": "Unsafe shell execution detected.",
            "recommendation": "Pass arguments as a list.",
            "secure_example": "subprocess.run(['python', 'app.py'], check=True)",
            "best_practices": ["Avoid shell=True."],
        }

        response = self.client.post(
            "/fix",
            json={
                "finding_id": "CMDI001",
                "title": "Command Injection",
                "description": "Unsafe shell execution detected.",
                "code": "subprocess.run(user_cmd, shell=True)",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["provider"], "gemini")
        mock_generate_remediation.assert_called_once()


if __name__ == "__main__":
    unittest.main()
