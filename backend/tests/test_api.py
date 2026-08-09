from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app import config, nxc_db, security
from app.job_manager import Job, job_manager
from app.main import app


class ApiIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.patchers = [
            patch.object(config, "AUTH_STORE_PATH", root / "auth.json"),
            patch.object(config, "NXC_WORKSPACES_DIR", root / "workspaces"),
            patch.object(config, "NXC_BIN", "/usr/bin/true"),
            patch.object(config, "COOKIE_SECURE", False),
        ]
        for patcher in self.patchers:
            patcher.start()
        security.change_password("admin", "StrongPassword1!")
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp_dir.cleanup()

    def login(self) -> None:
        response = self.client.post("/api/auth/login", json={"username": "admin", "password": "StrongPassword1!"})
        self.assertEqual(response.status_code, 200)

    def test_authentication_and_security_headers(self) -> None:
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.login()

        response = self.client.get("/api/auth/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"username": "admin", "role": "admin"})
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["cache-control"], "no-store")

        self.assertEqual(self.client.get("/").headers["cache-control"], "no-cache")
        self.assertEqual(self.client.get("/static/js/app.js").headers["cache-control"], "no-cache")

    def test_self_password_change_rotates_session(self) -> None:
        self.login()

        changed = self.client.post(
            "/api/auth/change-password",
            json={"current_password": "StrongPassword1!", "new_password": "NewStrongPassword2!"},
        )

        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        self.client.post("/api/auth/logout")
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "StrongPassword1!"},
            ).status_code,
            401,
        )

    def test_admin_can_manage_operator_accounts(self) -> None:
        self.login()

        created = self.client.post(
            "/api/users",
            json={"username": "analyst.one", "password": "AnalystPassword1!", "role": "operator"},
        )
        duplicate = self.client.post(
            "/api/users",
            json={"username": "ANALYST.ONE", "password": "AnotherPassword1!", "role": "operator"},
        )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["role"], "operator")
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(len(self.client.get("/api/users").json()), 2)

        self.client.post("/api/auth/logout")
        operator_login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst.one", "password": "AnalystPassword1!"},
        )
        self.assertEqual(operator_login.status_code, 200)
        self.assertEqual(operator_login.json()["role"], "operator")
        self.assertEqual(self.client.get("/api/users").status_code, 403)

        self.client.post("/api/auth/logout")
        self.login()
        disabled = self.client.patch("/api/users/analyst.one", json={"enabled": False})
        self.assertFalse(disabled.json()["enabled"])
        self.client.post("/api/auth/logout")
        self.assertEqual(
            self.client.post(
                "/api/auth/login",
                json={"username": "analyst.one", "password": "AnalystPassword1!"},
            ).status_code,
            401,
        )

        self.login()
        self.client.patch("/api/users/analyst.one", json={"enabled": True})
        reset = self.client.post(
            "/api/users/analyst.one/reset-password",
            json={"new_password": "NewAnalystPassword2!"},
        )
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(self.client.delete("/api/users/analyst.one").status_code, 204)
        self.assertEqual(len(self.client.get("/api/users").json()), 1)

    def test_job_response_redacts_credentials_and_command(self) -> None:
        self.login()

        with patch(
            "app.main._get_module_listing",
            AsyncMock(return_value={
                "available": True,
                "detail": None,
                "modules": [{"name": "one"}, {"name": "two"}],
            }),
        ):
            response = self.client.post(
                "/api/jobs",
                json={
                    "protocol": "smb",
                    "targets": ["127.0.0.1"],
                    "username": ["alice"],
                    "password": ["secret-password"],
                    "execute_powershell": "approved-command",
                    "modules": ["one", "two"],
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertNotIn("secret-password", body["command_preview"])
        self.assertNotIn("approved-command", body["command_preview"])
        detail = self.client.get(f"/api/jobs/{body['id']}").json()
        self.assertNotIn("secret-password", detail["argv"])
        self.assertNotIn("approved-command", detail["argv"])
        self.assertEqual(detail["argv"].count("-M"), 2)

    def test_ssh_rejects_local_auth_and_module_from_another_protocol(self) -> None:
        self.login()

        local_auth_response = self.client.post(
            "/api/jobs",
            json={"protocol": "ssh", "targets": ["192.0.2.10"], "local_auth": True},
        )
        with patch(
            "app.main._get_module_listing",
            AsyncMock(return_value={
                "available": True,
                "detail": None,
                "modules": [{"name": "aws-credentials"}],
            }),
        ):
            stale_module_response = self.client.post(
                "/api/jobs",
                json={"protocol": "ssh", "targets": ["192.0.2.10"], "modules": ["test_connection"]},
            )

        self.assertEqual(local_auth_response.status_code, 400)
        self.assertIn("--local-auth", local_auth_response.json()["detail"])
        self.assertEqual(stale_module_response.status_code, 400)
        self.assertIn("test_connection", stale_module_response.json()["detail"])
        self.assertIn("SSH", stale_module_response.json()["detail"])

    def test_invalid_protocol_and_workspace_are_rejected(self) -> None:
        self.login()

        job = self.client.post("/api/jobs", json={"protocol": "unknown", "targets": ["127.0.0.1"]})
        hosts = self.client.get("/api/hosts", params={"protocol": "smb", "workspace": "../outside"})

        self.assertEqual(job.status_code, 400)
        self.assertEqual(hosts.status_code, 400)

    def test_scan_request_size_limits_return_validation_errors(self) -> None:
        self.login()

        too_many_targets = self.client.post(
            "/api/jobs",
            json={"protocol": "smb", "targets": ["192.0.2.1"] * 2049},
        )
        oversized_extra_args = self.client.post(
            "/api/jobs",
            json={"protocol": "smb", "targets": ["192.0.2.1"], "extra_args": "x" * 8193},
        )
        oversized_combination = self.client.post(
            "/api/jobs",
            json={"protocol": "smb", "targets": ["x" * 512] * 129},
        )

        self.assertEqual(too_many_targets.status_code, 422)
        self.assertEqual(oversized_extra_args.status_code, 422)
        self.assertEqual(oversized_combination.status_code, 422)

    def test_modules_degrade_cleanly_without_nxc(self) -> None:
        self.login()

        with patch.object(config, "NXC_BIN", "/path/that/does/not/exist"):
            response = self.client.get("/api/modules", params={"protocol": "smb"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["modules"], [])
        self.assertFalse(response.json()["available"])

    def test_ai_assistant_requires_authentication_and_returns_local_suggestions(self) -> None:
        payload = {"field": "execute_command", "protocol": "ssh", "goal": "inspect system identity"}
        self.assertEqual(self.client.post("/api/ai/suggestions", json=payload).status_code, 401)
        self.login()

        response = self.client.post("/api/ai/suggestions", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provider"], "local")
        self.assertGreaterEqual(len(response.json()["suggestions"]), 2)
        self.assertEqual(response.json()["suggestions"][0]["command"], "id")

    def test_ai_assistant_rejects_sensitive_context(self) -> None:
        self.login()

        response = self.client.post(
            "/api/ai/suggestions",
            json={"field": "execute_command", "protocol": "smb", "goal": "password=SuperSecret123!"},
        )

        self.assertEqual(response.status_code, 422)

    def test_ai_assistant_reports_incomplete_remote_configuration(self) -> None:
        self.login()

        with (
            patch.object(config, "AI_PROVIDER", "openai"),
            patch.object(config, "AI_MODEL", ""),
            patch.object(config, "AI_API_KEY", ""),
        ):
            status_response = self.client.get("/api/ai/status")
            suggestion_response = self.client.post(
                "/api/ai/suggestions",
                json={"field": "execute_powershell", "protocol": "smb"},
            )

        self.assertEqual(status_response.status_code, 200)
        self.assertFalse(status_response.json()["available"])
        self.assertEqual(suggestion_response.status_code, 503)

    def test_backconnect_requires_authorization_confirmation(self) -> None:
        self.login()

        response = self.client.post(
            "/api/backconnect/trigger",
            json={
                "protocol": "smb",
                "target": "127.0.0.1",
                "username": ["alice"],
                "password": ["secret-password"],
                "command": "approved-command",
                "shell_type": "powershell",
                "confirm_authorized": False,
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_ssh_shell_access_can_trigger_backconnect(self) -> None:
        self.login()
        started_job = Job(id="ssh-callback", protocol="ssh", argv=["ssh", "10.0.0.8"])

        with (
            patch.object(
                nxc_db,
                "get_backconnect_hosts",
                return_value=[{"host": "10.0.0.8", "hostname": None}],
            ),
            patch.object(job_manager, "start_job", AsyncMock(return_value=started_job)) as start_job,
        ):
            response = self.client.post(
                "/api/backconnect/trigger",
                json={
                    "protocol": "ssh",
                    "target": "10.0.0.8",
                    "username": ["alice"],
                    "password": ["secret-password"],
                    "command": "approved-callback-command",
                    "shell_type": "cmd",
                    "kerberos": True,
                    "local_auth": True,
                    "confirm_authorized": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        scan = start_job.await_args.args[0]
        self.assertEqual(scan.execute_command, "approved-callback-command")
        self.assertIsNone(scan.execute_powershell)
        self.assertFalse(scan.kerberos)
        self.assertFalse(scan.local_auth)
        self.assertTrue(scan.no_output)

    def test_ssh_backconnect_rejects_powershell_mode(self) -> None:
        self.login()

        response = self.client.post(
            "/api/backconnect/trigger",
            json={
                "protocol": "ssh",
                "target": "10.0.0.8",
                "username": ["alice"],
                "password": ["secret-password"],
                "command": "approved-callback-command",
                "shell_type": "powershell",
                "confirm_authorized": True,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("SSH", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()