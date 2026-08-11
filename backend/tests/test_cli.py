from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from app import cli, config, security


class CliPasswordResetTests(unittest.TestCase):
    def test_reset_password_requires_change_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            security.change_password("admin", "StrongPassword1!")
            output = io.StringIO()
            with patch("app.cli.getpass.getpass", side_effect=["ResetPassword2!", "ResetPassword2!"]), redirect_stdout(output):
                result = cli.main(["reset-password"])

            self.assertEqual(result, 0)
            self.assertTrue(security.verify_credentials("admin", "ResetPassword2!"))
            self.assertTrue(security.get_user("admin")["must_change_password"])
            self.assertIn("must change", output.getvalue())

    def test_reset_password_rejects_unknown_account(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            security.change_password("admin", "StrongPassword1!")

            result = cli.main(["reset-password", "--username", "missing"])

            self.assertEqual(result, 2)