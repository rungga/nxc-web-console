from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import config, nxc_db, security
from app.ai_assistant import AiProviderError, _parse_suggestions, detect_language, generate_suggestions
from app.backconnect import BackConnectManager, discover_callback_route
from app.job_manager import Job, JobManager, build_argv, redact_argv, sensitive_values
from app.main import _WS_CONNECTION_COUNTS, _acquire_ws_slot, _parse_module_listing, _release_ws_slot, _startup_warnings
from app.schemas import AiSuggestionRequest, ModuleOption, ScanRequest


class JobArgumentTests(unittest.TestCase):
    def test_ssh_rejects_unsupported_auth_and_powershell_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "--local-auth is not supported for SSH"):
            build_argv(ScanRequest(protocol="ssh", targets=["192.0.2.10"], local_auth=True))

        with self.assertRaisesRegex(ValueError, "PowerShell execution .* is not supported for SSH"):
            build_argv(ScanRequest(protocol="ssh", targets=["192.0.2.10"], execute_powershell="Get-Process"))

    def test_build_argv_repeats_module_flag(self) -> None:
        scan = ScanRequest(
            protocol="smb",
            targets=["10.0.0.5"],
            username=["alice", "bob"],
            password=["secret", "second"],
            hashes=["hash-one", "hash-two"],
            modules=["one", "two"],
            module_options=[ModuleOption(key="TOKEN", value="value"), ModuleOption(key="MODE", value="safe")],
        )

        argv = build_argv(scan)

        self.assertEqual(argv.count("-M"), 2)
        self.assertEqual(argv.count("-u"), 1)
        self.assertEqual(argv.count("-p"), 1)
        self.assertEqual(argv.count("-H"), 1)
        self.assertEqual(argv.count("-o"), 1)
        self.assertNotIn("--workspace", argv)
        self.assertIn(["-u", "alice", "bob"], [argv[index:index + 3] for index in range(len(argv) - 2)])
        self.assertIn(["-p", "secret", "second"], [argv[index:index + 3] for index in range(len(argv) - 2)])
        self.assertIn(["-H", "hash-one", "hash-two"], [argv[index:index + 3] for index in range(len(argv) - 2)])
        self.assertIn(["-o", "TOKEN=value", "MODE=safe"], [argv[index:index + 3] for index in range(len(argv) - 2)])
        self.assertIn(["-M", "one", "-M", "two"], [argv[index:index + 4] for index in range(len(argv) - 3)])

    def test_sensitive_values_are_redacted(self) -> None:
        argv = ["smb", "10.0.0.5", "-p", "secret", "second", "-H", "deadbeef", "another", "-X", "command", "-o", "TOKEN=value", "MODE=safe"]

        redacted = redact_argv(argv)
        preview = Job(id="1", protocol="smb", argv=argv).command_preview

        for value in ["secret", "second", "deadbeef", "another", "command", "TOKEN=value", "MODE=safe"]:
            self.assertNotIn(value, redacted)
            self.assertNotIn(value, preview)
            self.assertIn(value, sensitive_values(argv))


class _FakeProcess:
    def __init__(self) -> None:
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_eof()
        self.returncode: int | None = None
        self._finished = asyncio.Event()

    async def wait(self) -> int:
        await self._finished.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15
        self._finished.set()

    def kill(self) -> None:
        self.returncode = -9
        self._finished.set()


class JobLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_unexpected_background_failure_finalizes_job(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                patch.object(config, "JOBS_DB_PATH", root / "jobs.sqlite3"),
                patch.object(config, "LOGS_DIR", root / "logs"),
                patch.object(config, "NXC_BIN", "/usr/bin/true"),
            ):
                config.LOGS_DIR.mkdir()
                manager = JobManager()

                async def fail_run(_job: Job) -> None:
                    raise RuntimeError("test failure")

                with patch.object(manager, "_run", side_effect=fail_run):
                    job = await manager.start_job(ScanRequest(protocol="ftp", targets=["127.0.0.1"]))
                    assert job.task is not None
                    with self.assertRaises(RuntimeError):
                        await job.task
                    await asyncio.sleep(0)

                self.assertEqual(job.status, "failed")
                self.assertIsNotNone(job.finished_at)
                self.assertIn("RuntimeError", job.log_lines[-1])

    async def test_stop_before_process_spawn_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release_spawn = asyncio.Event()
            process = _FakeProcess()

            async def delayed_spawn(*_args, **_kwargs):
                await release_spawn.wait()
                return process

            with (
                patch.object(config, "JOBS_DB_PATH", root / "jobs.sqlite3"),
                patch.object(config, "LOGS_DIR", root / "logs"),
                patch.object(config, "NXC_BIN", "/usr/bin/true"),
                patch("app.job_manager.asyncio.create_subprocess_exec", side_effect=delayed_spawn),
            ):
                config.LOGS_DIR.mkdir()
                manager = JobManager()
                job = await manager.start_job(ScanRequest(protocol="ftp", targets=["127.0.0.1"]))
                stop_task = asyncio.create_task(manager.stop_job(job))
                await asyncio.sleep(0)

                self.assertTrue(job.stop_requested)
                self.assertEqual(job.status, "stopping")

                release_spawn.set()
                await stop_task
                assert job.task is not None
                await job.task

                self.assertEqual(job.status, "stopped")
                self.assertEqual(job.return_code, -15)

    async def test_job_close_sentinel_replaces_oldest_item_when_queue_is_full(self) -> None:
        manager = object.__new__(JobManager)
        job = Job(id="queue-test", protocol="smb", argv=["smb", "127.0.0.1"])
        queue = asyncio.Queue(maxsize=2)
        queue.put_nowait("first")
        queue.put_nowait("second")
        job.subscribers.append(queue)

        manager._broadcast(job, None)

        self.assertEqual(queue.get_nowait(), "second")
        self.assertIsNone(queue.get_nowait())

    async def test_slow_job_subscriber_receives_overflow_marker(self) -> None:
        manager = object.__new__(JobManager)
        job = Job(id="queue-test", protocol="smb", argv=["smb", "127.0.0.1"])
        queue = asyncio.Queue(maxsize=2)
        queue.put_nowait("first")
        queue.put_nowait("second")
        job.subscribers.append(queue)

        manager._broadcast(job, "third")

        self.assertEqual(queue.get_nowait(), "second")
        overflow = queue.get_nowait()
        self.assertIn("truncated", overflow)
        self.assertTrue(overflow.endswith("third"))


class ModuleListingTests(unittest.TestCase):
    def test_current_netexec_module_prefix_is_parsed(self) -> None:
        output = """
LOW PRIVILEGE MODULES
ENUMERATION
[*] enum_av                   Gathers endpoint protection information
HIGH PRIVILEGE MODULES (requires admin privs)
CREDENTIAL_DUMPING
[*] lsassy                    Dump lsass remotely
"""

        modules = _parse_module_listing(output)

        self.assertEqual([module["name"] for module in modules], ["enum_av", "lsassy"])
        self.assertFalse(modules[0]["requires_admin"])
        self.assertTrue(modules[1]["requires_admin"])


class WorkspaceDatabaseTests(unittest.TestCase):
    def test_workspace_path_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "NXC_WORKSPACES_DIR", Path(temp_dir)):
            with self.assertRaises(ValueError):
                nxc_db._db_path("../outside", "smb")

    def test_nfs_relation_column_names_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "NXC_WORKSPACES_DIR", Path(temp_dir)):
            workspace = Path(temp_dir) / "default"
            workspace.mkdir()
            database = workspace / "nfs.db"
            conn = sqlite3.connect(database)
            conn.executescript(
                """
                CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT, port INTEGER, nfs_version TEXT);
                CREATE TABLE credentials (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
                CREATE TABLE loggedin_relations (id INTEGER PRIMARY KEY, cred_id INTEGER, host_id INTEGER);
                INSERT INTO hosts VALUES (1, '10.0.0.7', 'files', 2049, '4');
                INSERT INTO credentials VALUES (2, 'alice', 'secret');
                INSERT INTO loggedin_relations VALUES (3, 2, 1);
                """
            )
            conn.close()

            hosts = nxc_db.get_hosts("default", "nfs")

            self.assertEqual(hosts[0]["host"], "10.0.0.7")
            self.assertEqual(hosts[0]["credentials"][0]["username"], "alice")

    def test_ssh_shell_access_is_backconnect_capable_without_admin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "NXC_WORKSPACES_DIR", Path(temp_dir)):
            workspace = Path(temp_dir) / "default"
            workspace.mkdir()
            database = workspace / "ssh.db"
            conn = sqlite3.connect(database)
            conn.executescript(
                """
                CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT, port INTEGER, banner TEXT);
                CREATE TABLE credentials (id INTEGER PRIMARY KEY, username TEXT, password TEXT, credtype TEXT);
                CREATE TABLE loggedin_relations (id INTEGER PRIMARY KEY, credid INTEGER, hostid INTEGER, shell BOOLEAN);
                CREATE TABLE admin_relations (id INTEGER PRIMARY KEY, credid INTEGER, hostid INTEGER);
                INSERT INTO hosts VALUES (1, '10.0.0.8', 22, 'OpenSSH');
                INSERT INTO credentials VALUES (2, 'alice', 'secret', 'plaintext');
                INSERT INTO loggedin_relations VALUES (3, 2, 1, 1);
                """
            )
            conn.close()

            host = nxc_db.get_hosts("default", "ssh")[0]
            capable_hosts = nxc_db.get_backconnect_hosts("default", "ssh")

            self.assertTrue(host["shell_access"])
            self.assertFalse(host["pwned"])
            self.assertEqual([item["host"] for item in capable_hosts], ["10.0.0.8"])


class SecurityTests(unittest.TestCase):
    def test_websocket_connections_are_bounded_per_user(self) -> None:
        _WS_CONNECTION_COUNTS.clear()
        with patch.object(config, "MAX_WS_CONNECTIONS_PER_USER", 2):
            self.assertTrue(_acquire_ws_slot("alice"))
            self.assertTrue(_acquire_ws_slot("alice"))
            self.assertFalse(_acquire_ws_slot("alice"))
            _release_ws_slot("alice")
            self.assertTrue(_acquire_ws_slot("alice"))
        _WS_CONNECTION_COUNTS.clear()

    def test_non_loopback_deployment_emits_security_warnings(self) -> None:
        with (
            patch.object(config, "WEB_HOST", "0.0.0.0"),
            patch.object(config, "COOKIE_SECURE", False),
            patch.object(config, "LISTENER_BIND_HOST", "0.0.0.0"),
        ):
            warnings = _startup_warnings()

        self.assertEqual(len(warnings), 2)
        self.assertIn("secure cookies", warnings[0])
        self.assertIn("firewall", warnings[1])

    def test_malformed_session_token_is_rejected(self) -> None:
        self.assertIsNone(security.verify_session_token("not-a-token"))

    def test_bootstrap_admin_must_change_generated_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            with patch("app.security.secrets.token_urlsafe", return_value="GeneratedPassword1!"):
                password = security.bootstrap_admin_account()

            self.assertEqual(password, "GeneratedPassword1!")
            self.assertTrue(security.verify_credentials("admin", password))
            self.assertTrue(security.get_user("admin")["must_change_password"])

    def test_valid_session_token_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            security.change_password("admin", "StrongPassword1!")
            token = security.create_session_token("admin")

            self.assertEqual(security.verify_session_token(token), "admin")

    def test_password_change_revokes_existing_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            security.change_password("admin", "StrongPassword1!")
            token = security.create_session_token("admin")

            security.change_password("admin", "NewStrongPassword2!")

            self.assertIsNone(security.verify_session_token(token))

    def test_legacy_single_user_store_migrates_to_admin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(config, "AUTH_STORE_PATH", Path(temp_dir) / "auth.json"):
            salt = b"0123456789abcdef"
            legacy = {
                "username": "LegacyAdmin",
                "salt": base64.b64encode(salt).decode("ascii"),
                "hash": security._hash_password("StrongPassword1!", salt),
            }
            config.AUTH_STORE_PATH.write_text(json.dumps(legacy))

            self.assertTrue(security.verify_credentials("legacyadmin", "StrongPassword1!"))
            account = security.get_user("LegacyAdmin")
            migrated = json.loads(config.AUTH_STORE_PATH.read_text())

            self.assertEqual(account["role"], "admin")
            self.assertIn("users", migrated)
            self.assertNotIn("hash", migrated)


class AiAssistantTests(unittest.TestCase):
    def test_language_detection_handles_short_mixed_indonesian_prompt(self) -> None:
        self.assertEqual(detect_language("cek user linux"), "id")
        self.assertEqual(detect_language("check Linux users"), "en")

    def test_local_assistant_detects_indonesian_linux_user_intent(self) -> None:
        request = AiSuggestionRequest(
            field="execute_command",
            protocol="smb",
            goal="untuk mengecek daftar user di linux?",
        )

        response = asyncio.run(generate_suggestions(request))

        self.assertEqual(response.language, "id")
        self.assertIn("getent passwd", [item.command for item in response.suggestions])
        self.assertTrue(any("pengguna" in item.explanation.casefold() for item in response.suggestions))

    def test_provider_json_is_bounded_and_dangerous_commands_are_removed(self) -> None:
        response = json.dumps({
            "suggestions": [
                {
                    "title": "Identity",
                    "command": "whoami /all",
                    "explanation": "Inspect the current identity.",
                    "risk": "low",
                },
                {
                    "title": "Unsafe",
                    "command": "Invoke-Mimikatz sekurlsa::logonpasswords",
                    "explanation": "Credential access.",
                    "risk": "high",
                },
            ]
        })

        suggestions = _parse_suggestions(f"```json\n{response}\n```")

        self.assertEqual([item.command for item in suggestions], ["whoami /all"])

    def test_provider_response_with_only_unsafe_commands_is_rejected(self) -> None:
        response = json.dumps({
            "suggestions": [{
                "title": "Unsafe",
                "command": "rm -rf /",
                "explanation": "Destructive.",
                "risk": "high",
            }]
        })

        with self.assertRaises(AiProviderError):
            _parse_suggestions(response)


class CallbackListenerTests(unittest.IsolatedAsyncioTestCase):
    async def test_listener_buffers_allowed_peer_output(self) -> None:
        manager = BackConnectManager()
        listener = await manager.start_listener(0, "127.0.0.1/32", "test")
        port = listener.server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello")
        await writer.drain()

        async def get_transcript() -> bytes:
            while not listener.sessions or not next(iter(listener.sessions.values())).transcript:
                await asyncio.sleep(0)
            return bytes(next(iter(listener.sessions.values())).transcript)

        transcript = await asyncio.wait_for(get_transcript(), timeout=1)
        self.assertEqual(transcript, b"hello")

        writer.close()
        await writer.wait_closed()
        await manager.stop_listener(listener.id)
        del reader

    async def test_listener_rejects_unapproved_peer(self) -> None:
        manager = BackConnectManager()
        listener = await manager.start_listener(0, "192.0.2.1/32", "test")
        port = listener.server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        self.assertEqual(await asyncio.wait_for(reader.read(), timeout=1), b"")
        self.assertFalse(listener.sessions)
        self.assertEqual(len(listener.rejected_connections), 1)
        self.assertTrue(listener.rejected_connections[0].peer.startswith("127.0.0.1:"))
        self.assertEqual(listener.rejected_connections[0].reason, "source_not_allowed")

        writer.close()
        await writer.wait_closed()
        await manager.stop_listener(listener.id)

    async def test_closed_session_delivers_sentinel_when_subscriber_queue_is_full(self) -> None:
        manager = BackConnectManager()
        listener = await manager.start_listener(0, "127.0.0.1/32", "test")
        port = listener.server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        while not listener.sessions:
            await asyncio.sleep(0)
        session = next(iter(listener.sessions.values()))
        queue = asyncio.Queue(maxsize=2)
        queue.put_nowait(b"first")
        queue.put_nowait(b"second")
        session.subscribers.append(queue)

        writer.close()
        await writer.wait_closed()
        while not session.closed:
            await asyncio.sleep(0)

        self.assertEqual(queue.get_nowait(), b"second")
        self.assertIsNone(queue.get_nowait())

        await manager.stop_listener(listener.id)
        del reader

    async def test_slow_session_subscriber_receives_overflow_marker(self) -> None:
        manager = BackConnectManager()
        listener = await manager.start_listener(0, "127.0.0.1/32", "test")
        port = listener.server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        while not listener.sessions:
            await asyncio.sleep(0)
        session = next(iter(listener.sessions.values()))
        queue = asyncio.Queue(maxsize=2)
        queue.put_nowait(b"first")
        queue.put_nowait(b"second")
        session.subscribers.append(queue)

        writer.write(b"third")
        await writer.drain()
        while not session.transcript:
            await asyncio.sleep(0)

        self.assertEqual(queue.get_nowait(), b"second")
        overflow = queue.get_nowait()
        self.assertIn(b"truncated", overflow)
        self.assertTrue(overflow.endswith(b"third"))

        writer.close()
        await writer.wait_closed()
        await manager.stop_listener(listener.id)
        del reader


class CallbackRouteTests(unittest.TestCase):
    def test_loopback_target_uses_loopback_callback_host(self) -> None:
        self.assertEqual(discover_callback_route("127.0.0.1"), ("127.0.0.1", "127.0.0.1/32"))


if __name__ == "__main__":
    unittest.main()