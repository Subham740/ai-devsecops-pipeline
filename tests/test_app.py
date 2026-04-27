from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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
                "LOG_PATH": str(root / "test.log"),
                "SCAN_ROOT": str(root),
                "DEMO_USERNAME": "tester",
                "DEMO_PASSWORD_HASH": generate_password_hash(self.demo_password),
                "LOGIN_ATTEMPT_LIMIT": 3,
                "LOGIN_WINDOW_SECONDS": 60,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("openai_enabled", data)

    def test_login_success(self):
        response = self.client.post(
            "/login",
            json={"username": "tester", "password": self.demo_password},
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("session_token", data)

    def test_scan_persists_and_returns_history(self):
        code = "import subprocess\\nsubprocess.run(cmd, shell=True)"
        scan_response = self.client.post("/scan", json={"code": code, "filename": "job.py"})

        self.assertEqual(scan_response.status_code, 200)
        scan_data = scan_response.get_json()
        self.assertEqual(scan_data["finding_count"], 1)

        history_response = self.client.get("/scans")
        history_data = history_response.get_json()
        self.assertEqual(history_response.status_code, 200)
        self.assertEqual(len(history_data["scans"]), 1)
        self.assertEqual(history_data["scans"][0]["target_name"], "job.py")

    def test_scan_rejects_path_traversal(self):
        response = self.client.post("/scan", json={"file_path": "../outside.py"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_fix_endpoint_uses_fallback_without_openai(self):
        response = self.client.post(
            "/fix",
            json={
                "finding_id": "EXEC001",
                "title": "Dangerous dynamic execution",
                "description": "eval is used on user input.",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["provider"], "fallback")
        self.assertIn("secure_example", data)


if __name__ == "__main__":
    unittest.main()
