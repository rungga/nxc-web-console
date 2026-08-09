"""Runs `nxc` as a subprocess per scan request and streams its output live.

Every scan the GUI performs is translated 1:1 into the same argv NetExec's
own CLI expects (`nxc <protocol> <targets...> <flags...>`), so anything you
can do on the CLI can be done here - including an "extra CLI arguments" raw
passthrough field for flags/module options not modeled explicitly in the UI.

Security note: arguments are always passed as a list to
`asyncio.create_subprocess_exec` (never through a shell), so user-supplied
values cannot break out into shell metacharacter injection.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import sqlite3
import time
import uuid
from dataclasses import dataclass, field

from app import config
from app.proto_defs import EXEC_METHODS, PROTOCOLS
from app.queue_utils import offer_latest
from app.schemas import ScanRequest

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# nxc log lines look like: "SMB   10.0.0.5   445   DC01   [+] domain\user:pass (Pwn3d!)"
_PWN_RE = re.compile(r"^\S+\s+(?P<host>\S+)\s+\d+\s+(?P<hostname>\S+)\s+.*\(Pwn3d!\)", re.IGNORECASE)
_SENSITIVE_SINGLE_FLAGS = {
    "--pfx-pass",
    "-x",
    "-X",
    "--execute",
    "--ps-execute",
}
_SENSITIVE_MULTI_FLAGS = {
    "-p",
    "--password",
    "-H",
    "--hash",
    "--aesKey",
    "-o",
    "--options",
}


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_mode: str | None = None
    for value in argv:
        if redact_mode == "single":
            redacted.append("<redacted>")
            redact_mode = None
            continue
        if redact_mode == "multi" and not value.startswith("-"):
            redacted.append("<redacted>")
            continue
        if redact_mode == "multi":
            redact_mode = None
        flag = value.split("=", 1)[0]
        if flag in _SENSITIVE_SINGLE_FLAGS or flag in _SENSITIVE_MULTI_FLAGS:
            if "=" in value:
                redacted.append(f"{flag}=<redacted>")
            else:
                redacted.append(value)
                redact_mode = "single" if flag in _SENSITIVE_SINGLE_FLAGS else "multi"
            continue
        redacted.append(value)
    return redacted


def sensitive_values(argv: list[str]) -> tuple[str, ...]:
    values: list[str] = []
    capture_mode: str | None = None
    for value in argv:
        if capture_mode == "single":
            values.append(value)
            capture_mode = None
            continue
        if capture_mode == "multi" and not value.startswith("-"):
            values.append(value)
            continue
        if capture_mode == "multi":
            capture_mode = None
        flag, separator, inline_value = value.partition("=")
        if flag in _SENSITIVE_SINGLE_FLAGS or flag in _SENSITIVE_MULTI_FLAGS:
            if separator:
                values.append(inline_value)
            else:
                capture_mode = "single" if flag in _SENSITIVE_SINGLE_FLAGS else "multi"
    return tuple(value for value in values if value)


def build_argv(scan: ScanRequest) -> list[str]:
    """Builds the nxc argv list from a ScanRequest, mirroring CLI usage exactly."""
    if not scan.protocol:
        raise ValueError("protocol is required")
    protocol = PROTOCOLS.get(scan.protocol)
    if protocol is None:
        raise ValueError("unknown protocol")
    if not scan.targets:
        raise ValueError("at least one target is required")
    if scan.local_auth and protocol.get("supports_local_auth") is False:
        raise ValueError(f"--local-auth is not supported for {scan.protocol.upper()}")
    if scan.kerberos and protocol.get("supports_kerberos") is False:
        raise ValueError(f"Kerberos is not supported for {scan.protocol.upper()}")
    if scan.execute_powershell and protocol.get("supports_powershell") is False:
        raise ValueError(f"PowerShell execution (-X) is not supported for {scan.protocol.upper()}")
    if scan.exec_method and scan.exec_method not in EXEC_METHODS.get(scan.protocol, []):
        raise ValueError(f"Exec method '{scan.exec_method}' is not supported for {scan.protocol.upper()}")
    if scan.modules and not protocol["supports_modules"]:
        raise ValueError(f"Modules are not supported for {scan.protocol.upper()}")

    argv: list[str] = [scan.protocol, *scan.targets]

    if scan.username:
        argv += ["-u", *scan.username]
    if scan.password:
        argv += ["-p", *scan.password]
    if scan.hashes:
        argv += ["-H", *scan.hashes]
    if scan.domain:
        argv += ["-d", scan.domain]
    if scan.kerberos:
        argv.append("-k")
    if scan.local_auth:
        argv.append("--local-auth")

    if scan.execute_command:
        argv += ["-x", scan.execute_command]
    if scan.execute_powershell:
        argv += ["-X", scan.execute_powershell]
    if scan.exec_method:
        argv += ["--exec-method", scan.exec_method]
    if scan.no_output:
        argv.append("--no-output")

    for module in scan.modules:
        argv += ["-M", module]
    if scan.module_options:
        argv += ["-o", *(f"{opt.key}={opt.value}" for opt in scan.module_options)]

    if scan.extra_args.strip():
        argv += shlex.split(scan.extra_args)

    return argv


@dataclass
class Job:
    id: str
    protocol: str
    argv: list[str]
    status: str = "running"  # running | stopping | completed | failed | stopped
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    return_code: int | None = None
    pwned_hosts: set[str] = field(default_factory=set)
    process: asyncio.subprocess.Process | None = None
    process_ready: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    stop_requested: bool = False
    task: asyncio.Task | None = field(default=None, repr=False)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    secrets: tuple[str, ...] = ()

    @property
    def display_argv(self) -> list[str]:
        return redact_argv(self.argv)

    @property
    def command_preview(self) -> str:
        return " ".join(shlex.quote(a) for a in [config.NXC_BIN, *self.display_argv])


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(config.JOBS_DB_PATH)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                protocol TEXT,
                argv TEXT,
                status TEXT,
                started_at REAL,
                finished_at REAL,
                return_code INTEGER,
                pwned_hosts TEXT
            )
            """
        )
        for job_id, raw_argv in conn.execute("SELECT id, argv FROM jobs").fetchall():
            try:
                argv = json.loads(raw_argv)
            except (TypeError, json.JSONDecodeError):
                argv = []
            safe_argv = json.dumps(redact_argv(argv))
            if safe_argv != raw_argv:
                conn.execute("UPDATE jobs SET argv = ? WHERE id = ?", (safe_argv, job_id))
        conn.commit()
        rows = conn.execute(
            "SELECT id, protocol, argv, status, started_at, finished_at, return_code, pwned_hosts FROM jobs ORDER BY started_at DESC LIMIT ?",
            (config.MAX_RETAINED_JOBS,),
        ).fetchall()
        conn.close()
        for row in rows:
            try:
                argv = json.loads(row[2])
                pwned_hosts = set(json.loads(row[7]))
            except (TypeError, json.JSONDecodeError):
                continue
            status = "failed" if row[3] in {"running", "stopping"} else row[3]
            job = Job(
                id=row[0],
                protocol=row[1],
                argv=argv,
                status=status,
                started_at=row[4],
                finished_at=row[5],
                return_code=row[6],
                pwned_hosts=pwned_hosts,
                log_lines=self._read_log_tail(row[0]),
            )
            self._jobs[job.id] = job

    @staticmethod
    def _read_log_tail(job_id: str) -> list[str]:
        path = config.LOGS_DIR / f"{job_id}.log"
        if not path.exists():
            return []
        with path.open("rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(0, size - 524_288))
            return log_file.read().decode(errors="replace").splitlines()[-5000:]

    def _persist(self, job: Job) -> None:
        conn = sqlite3.connect(config.JOBS_DB_PATH)
        conn.execute(
            """
            INSERT INTO jobs (id, protocol, argv, status, started_at, finished_at, return_code, pwned_hosts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                finished_at=excluded.finished_at,
                return_code=excluded.return_code,
                pwned_hosts=excluded.pwned_hosts
            """,
            (
                job.id,
                job.protocol,
                json.dumps(job.display_argv),
                job.status,
                job.started_at,
                job.finished_at,
                job.return_code,
                json.dumps(sorted(job.pwned_hosts)),
            ),
        )
        conn.commit()
        conn.close()

    def list_jobs(self) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)

    def get_job(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def running_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status in {"running", "stopping"})

    async def start_job(self, scan: ScanRequest) -> Job:
        if self.running_count() >= config.MAX_CONCURRENT_JOBS:
            raise RuntimeError(f"Max concurrent jobs reached ({config.MAX_CONCURRENT_JOBS}). Wait for one to finish.")

        argv = build_argv(scan)
        job_id = str(uuid.uuid4())
        secrets = sensitive_values(argv)
        job = Job(id=job_id, protocol=scan.protocol, argv=argv, secrets=secrets)
        self._jobs[job_id] = job
        self._persist(job)

        job.task = asyncio.create_task(self._run(job))
        job.task.add_done_callback(lambda task, current_job=job: self._handle_task_done(current_job, task))
        return job

    def _handle_task_done(self, job: Job, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is None or job.status not in {"running", "stopping"}:
            return
        if job.process is not None and job.process.returncode is None:
            try:
                job.process.terminate()
            except ProcessLookupError:
                pass
        job.process_ready.set()
        job.status = "stopped" if job.stop_requested else "failed"
        job.finished_at = time.time()
        self._append_line(job, f"[web-gui] ERROR: Job runtime failed ({type(error).__name__}).")
        self._persist(job)
        self._broadcast(job, None)

    async def _run(self, job: Job) -> None:
        log_path = config.LOGS_DIR / f"{job.id}.log"
        try:
            process = await asyncio.create_subprocess_exec(
                config.NXC_BIN,
                *job.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except FileNotFoundError:
            job.process_ready.set()
            job.status = "stopped" if job.stop_requested else "failed"
            job.finished_at = time.time()
            self._append_line(job, f"[web-gui] ERROR: '{config.NXC_BIN}' executable not found on PATH.")
            self._persist(job)
            self._broadcast(job, None)
            return
        except OSError as exc:
            job.process_ready.set()
            job.status = "stopped" if job.stop_requested else "failed"
            job.finished_at = time.time()
            self._append_line(job, f"[web-gui] ERROR: Could not start NetExec: {exc}")
            self._persist(job)
            self._broadcast(job, None)
            return

        job.process = process
        job.process_ready.set()
        if job.stop_requested:
            job.status = "stopping"
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        log_limit_reached = False
        with log_path.open("a", encoding="utf-8") as log_file:
            assert process.stdout is not None
            async for raw_line in process.stdout:
                line = strip_ansi(raw_line.decode(errors="replace")).rstrip("\n")[:65_536]
                self._append_line(job, line)
                if not log_limit_reached and log_file.tell() < config.MAX_JOB_LOG_BYTES:
                    log_file.write(line + "\n")
                elif not log_limit_reached:
                    log_file.write("[web-gui] Log size limit reached; further output is only available in the live console.\n")
                    log_limit_reached = True
                match = _PWN_RE.search(line)
                if match:
                    job.pwned_hosts.add(match.group("host"))

            return_code = await process.wait()

        job.return_code = return_code
        job.status = "stopped" if job.status == "stopping" else ("completed" if return_code == 0 else "failed")
        job.finished_at = time.time()
        self._persist(job)
        self._broadcast(job, None)  # sentinel: signals stream end
        self._prune_history()

    def _append_line(self, job: Job, line: str) -> None:
        for secret in sorted(job.secrets, key=len, reverse=True):
            if len(secret) >= 4:
                line = line.replace(secret, "<redacted>")
            line = line.replace(f":{secret}", ":<redacted>")
        job.log_lines.append(line)
        if len(job.log_lines) > 5000:
            job.log_lines = job.log_lines[-5000:]
        self._broadcast(job, line)

    def _broadcast(self, job: Job, line: str | None) -> None:
        for q in list(job.subscribers):
            item = line
            if line is not None and q.full():
                item = f"[web-gui] WARNING: Live output was truncated because this subscriber fell behind.\n{line}"
            offer_latest(q, item)

    def subscribe(self, job: Job) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        job.subscribers.append(q)
        return q

    def unsubscribe(self, job: Job, q: asyncio.Queue) -> None:
        if q in job.subscribers:
            job.subscribers.remove(q)

    async def stop_job(self, job: Job) -> None:
        if job.status not in {"running", "stopping"}:
            return
        job.stop_requested = True
        job.status = "stopping"
        self._persist(job)

        if job.process is None:
            try:
                await asyncio.wait_for(job.process_ready.wait(), timeout=5)
            except asyncio.TimeoutError:
                return

        process = job.process
        if process is None or process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                return
            await process.wait()

    def _prune_history(self) -> None:
        finished = sorted(
            (job for job in self._jobs.values() if job.status not in {"running", "stopping"}),
            key=lambda job: job.started_at,
            reverse=True,
        )
        for job in finished[config.MAX_RETAINED_JOBS:]:
            self._jobs.pop(job.id, None)
            conn = sqlite3.connect(config.JOBS_DB_PATH)
            conn.execute("DELETE FROM jobs WHERE id = ?", (job.id,))
            conn.commit()
            conn.close()
            (config.LOGS_DIR / f"{job.id}.log").unlink(missing_ok=True)


job_manager = JobManager()
