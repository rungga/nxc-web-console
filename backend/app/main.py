"""FastAPI application: REST + WebSocket API for the NetExec Web GUI, and
static file serving for the frontend SPA.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import config, nxc_db, security
from app.ai_assistant import AiConfigurationError, AiProviderError, generate_suggestions, get_ai_status
from app.backconnect import backconnect_manager, discover_callback_route, is_wsl_environment
from app.job_manager import job_manager
from app.proto_defs import EXEC_METHODS, PROTOCOLS
from app.schemas import (
    AiSuggestionRequest,
    AiSuggestionResponse,
    AiStatusResponse,
    BackConnectListenerRequest,
    BackConnectTriggerRequest,
    ChangePasswordRequest,
    JobDetail,
    JobSummary,
    LoginRequest,
    ScanRequest,
    UserCreateRequest,
    UserPasswordResetRequest,
    UserResponse,
    UserUpdateRequest,
)
from app.security import COOKIE_NAME, get_current_user, require_admin

app = FastAPI(title="NetExec Web GUI", version="1.0.0")

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
_WS_CONNECTION_COUNTS: dict[str, int] = {}


def _acquire_ws_slot(username: str) -> bool:
    count = _WS_CONNECTION_COUNTS.get(username, 0)
    if count >= config.MAX_WS_CONNECTIONS_PER_USER:
        return False
    _WS_CONNECTION_COUNTS[username] = count + 1
    return True


def _release_ws_slot(username: str) -> None:
    count = _WS_CONNECTION_COUNTS.get(username, 0)
    if count <= 1:
        _WS_CONNECTION_COUNTS.pop(username, None)
    else:
        _WS_CONNECTION_COUNTS[username] = count - 1


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _startup_warnings() -> list[str]:
    warnings: list[str] = []
    if not _is_loopback_host(config.WEB_HOST) and not config.COOKIE_SECURE:
        warnings.append("Web server is exposed beyond loopback while secure cookies are disabled; use HTTPS and NXCWEB_COOKIE_SECURE=true.")
    if not _is_loopback_host(config.LISTENER_BIND_HOST):
        warnings.append(
            "Back-connect listeners are exposed beyond loopback; set NXCWEB_LISTENER_BIND to the explicit interface "
            "address or 0.0.0.0, then enforce a strict firewall allowlist."
        )
    return warnings


@app.on_event("startup")
async def on_startup() -> None:
    for warning in _startup_warnings():
        print(f"[web-gui] WARNING: {warning}")
    generated_password = security.bootstrap_admin_account()
    if generated_password:
        print("=" * 70)
        print(" NetExec Web GUI - first run admin account created")
        print(f"   username: {config.ADMIN_USERNAME}")
        print(f"   password: {generated_password}")
        print(" Save this password now, it will not be shown again.")
        print(" You must change it from Settings after logging in.")
        print(" Recovery command: ./run.sh reset-password")
        print("=" * 70)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    for job in job_manager.list_jobs():
        if job.status == "running":
            await job_manager.stop_job(job)
    for listener in list(backconnect_manager.list_listeners()):
        await backconnect_manager.stop_listener(listener.id)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path == "/" or request.url.path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-cache"
    return response


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request, response: Response):
    source = request.client.host if request.client else "unknown"
    if security.is_locked_out(source):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed attempts, try again later")

    if not security.verify_credentials(payload.username, payload.password):
        security.register_failed_attempt(source)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    security.reset_attempts(source)
    account = security.get_user(payload.username)
    if not account:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = security.create_session_token(account["username"])
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=config.SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
        path="/",
    )
    return {
        "username": account["username"],
        "role": account["role"],
        "must_change_password": account["must_change_password"],
    }


@app.post("/api/auth/logout")
async def logout(response: Response, _user: str = Depends(get_current_user)):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user: str = Depends(get_current_user)):
    account = security.get_user(user)
    return {
        "username": user,
        "role": account["role"] if account else security.ROLE_OPERATOR,
        "must_change_password": account["must_change_password"] if account else False,
    }


@app.post("/api/auth/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    user: str = Depends(get_current_user),
):
    if not security.verify_credentials(user, payload.current_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    security.change_password(user, payload.new_password, must_change_password=False)
    response.set_cookie(
        key=COOKIE_NAME,
        value=security.create_session_token(user),
        max_age=config.SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
        path="/",
    )
    return {"ok": True}


@app.get("/api/users", response_model=list[UserResponse])
async def list_users(_admin: str = Depends(require_admin)):
    return security.list_users()


@app.post("/api/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreateRequest, _admin: str = Depends(require_admin)):
    try:
        return security.create_user(payload.username, payload.password, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@app.patch("/api/users/{username}", response_model=UserResponse)
async def update_user(username: str, payload: UserUpdateRequest, admin: str = Depends(require_admin)):
    if username.casefold() == admin.casefold() and (payload.enabled is False or payload.role == security.ROLE_OPERATOR):
        raise HTTPException(status_code=400, detail="You cannot disable or demote your own account")
    try:
        return security.update_user(username, payload.role, payload.enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="User not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/users/{username}/reset-password")
async def reset_user_password(
    username: str,
    payload: UserPasswordResetRequest,
    response: Response,
    admin: str = Depends(require_admin),
):
    try:
        security.change_password(username, payload.new_password, must_change_password=True)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="User not found") from exc
    if username.casefold() == admin.casefold():
        response.set_cookie(
            key=COOKIE_NAME,
            value=security.create_session_token(admin),
            max_age=config.SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=config.COOKIE_SECURE,
            path="/",
        )
    return {"ok": True}


@app.delete("/api/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(username: str, admin: str = Depends(require_admin)):
    if username.casefold() == admin.casefold():
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    try:
        security.delete_user(username)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="User not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Protocol / module metadata
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health(_user: str = Depends(get_current_user)):
    executable = shutil.which(config.NXC_BIN)
    if not executable and Path(config.NXC_BIN).is_file():
        executable = str(Path(config.NXC_BIN).resolve())
    return {
        "status": "ready" if executable else "degraded",
        "nxc_available": bool(executable),
        "nxc_binary": executable or config.NXC_BIN,
        "workspace_root": str(config.NXC_WORKSPACES_DIR),
        "active_workspace": nxc_db.get_active_workspace(),
    }


@app.get("/api/protocols")
async def list_protocols(_user: str = Depends(get_current_user)):
    return {"protocols": PROTOCOLS, "exec_methods": EXEC_METHODS}


@app.get("/api/ai/status", response_model=AiStatusResponse)
async def ai_status(_user: str = Depends(get_current_user)):
    return get_ai_status()


@app.post("/api/ai/suggestions", response_model=AiSuggestionResponse)
async def ai_suggestions(payload: AiSuggestionRequest, _user: str = Depends(get_current_user)):
    try:
        return await generate_suggestions(payload)
    except AiConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


_CATEGORY_HEADERS = {"ENUMERATION", "CREDENTIAL_DUMPING", "PRIVILEGE_ESCALATION"}
_MODULE_LINE_RE = re.compile(r"^(?:\[\*\]\s+)?(?P<name>\S+)\s{2,}(?P<desc>.+)$")
_MODULE_CATALOG_CACHE: dict[tuple[str, str], list[dict]] = {}


def _parse_module_listing(output: str) -> list[dict]:
    modules: list[dict] = []
    requires_admin = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "HIGH PRIVILEGE MODULES" in line:
            requires_admin = True
            continue
        if "LOW PRIVILEGE MODULES" in line or line.upper() in _CATEGORY_HEADERS:
            continue
        match = _MODULE_LINE_RE.match(line)
        if match:
            modules.append({
                "name": match.group("name"),
                "description": match.group("desc").strip(),
                "requires_admin": requires_admin,
            })
    return modules


async def _get_module_listing(protocol: str) -> dict:
    if not PROTOCOLS[protocol]["supports_modules"]:
        return {"modules": [], "available": True, "detail": "Modules are not supported for this protocol"}
    executable = shutil.which(config.NXC_BIN)
    if not executable and Path(config.NXC_BIN).is_file():
        executable = str(Path(config.NXC_BIN).resolve())
    if not executable:
        return {
            "modules": [],
            "available": False,
            "detail": f"'{config.NXC_BIN}' executable is not installed",
        }
    cache_key = (str(Path(executable).resolve()), protocol)
    cached = _MODULE_CATALOG_CACHE.get(cache_key)
    if cached is not None:
        return {"modules": cached, "available": True, "detail": None}
    try:
        process = await asyncio.create_subprocess_exec(
            executable, protocol, "-L",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=20)
    except OSError as exc:
        return {"modules": [], "available": False, "detail": f"Could not start NetExec: {exc}"}
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise HTTPException(status_code=504, detail="Timed out listing modules") from exc

    from app.job_manager import strip_ansi
    output = strip_ansi(stdout.decode(errors="replace"))
    if process.returncode != 0:
        return {
            "modules": [],
            "available": False,
            "detail": output.strip() or f"NetExec exited with code {process.returncode}",
        }
    modules = _parse_module_listing(output)
    _MODULE_CATALOG_CACHE[cache_key] = modules
    return {"modules": modules, "available": True, "detail": None}


@app.get("/api/modules")
async def list_modules(protocol: str, _user: str = Depends(get_current_user)):
    if protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    return await _get_module_listing(protocol)


# ---------------------------------------------------------------------------
# Scan jobs
# ---------------------------------------------------------------------------

def _job_to_summary(job) -> JobSummary:
    return JobSummary(
        id=job.id,
        protocol=job.protocol,
        command_preview=job.command_preview,
        status=job.status,
        started_at=job.started_at,
        finished_at=job.finished_at,
        return_code=job.return_code,
        pwned_hosts=sorted(job.pwned_hosts),
    )


@app.post("/api/jobs", response_model=JobSummary)
async def create_job(scan: ScanRequest, _user: str = Depends(get_current_user)):
    if scan.protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    if scan.modules:
        listing = await _get_module_listing(scan.protocol)
        if not listing["available"]:
            raise HTTPException(status_code=503, detail=listing["detail"] or "NetExec modules are unavailable")
        available_modules = {module["name"] for module in listing["modules"]}
        invalid_modules = sorted(set(scan.modules) - available_modules)
        if invalid_modules:
            names = ", ".join(invalid_modules)
            raise HTTPException(
                status_code=400,
                detail=f"Module(s) not available for {scan.protocol.upper()}: {names}",
            )
    active_workspace = nxc_db.get_active_workspace()
    if scan.workspace and scan.workspace != active_workspace:
        raise HTTPException(
            status_code=409,
            detail=f"NetExec active workspace is '{active_workspace}'. Change it with nxcdb before starting this job.",
        )
    try:
        job = await job_manager.start_job(scan)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return _job_to_summary(job)


@app.get("/api/jobs", response_model=list[JobSummary])
async def list_jobs(_user: str = Depends(get_current_user)):
    return [_job_to_summary(j) for j in job_manager.list_jobs()]


@app.get("/api/jobs/{job_id}", response_model=JobDetail)
async def get_job(job_id: str, _user: str = Depends(get_current_user)):
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    summary = _job_to_summary(job)
    return JobDetail(**summary.model_dump(), argv=job.display_argv, log_tail=job.log_lines[-500:])


@app.post("/api/jobs/{job_id}/stop")
async def stop_job(job_id: str, _user: str = Depends(get_current_user)):
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    await job_manager.stop_job(job)
    return {"ok": True}


@app.websocket("/ws/jobs/{job_id}")
async def job_log_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    token = websocket.cookies.get(COOKIE_NAME) or websocket.query_params.get("token")
    username = security.verify_ws_session(token)
    if not username:
        await websocket.close(code=4401)
        return
    if not _acquire_ws_slot(username):
        await websocket.close(code=4429)
        return

    try:
        job = job_manager.get_job(job_id)
        if not job:
            await websocket.close(code=4404)
            return

        for line in job.log_lines[-200:]:
            await websocket.send_json({"type": "log", "line": line})
        if job.status != "running":
            await websocket.send_json({"type": "end", "status": job.status, "return_code": job.return_code})
            await websocket.close()
            return

        queue = job_manager.subscribe(job)
        try:
            while True:
                line = await queue.get()
                if line is None:
                    await websocket.send_json({"type": "end", "status": job.status, "return_code": job.return_code})
                    break
                await websocket.send_json({"type": "log", "line": line})
        except WebSocketDisconnect:
            pass
        finally:
            job_manager.unsubscribe(job, queue)
    finally:
        _release_ws_slot(username)


# ---------------------------------------------------------------------------
# Hosts / Pwned view (reads NetExec's own workspace databases)
# ---------------------------------------------------------------------------

@app.get("/api/workspaces")
async def list_workspaces(_user: str = Depends(get_current_user)):
    active = nxc_db.get_active_workspace()
    workspaces = nxc_db.list_workspaces()
    if active not in workspaces:
        workspaces.append(active)
    return {"workspaces": sorted(workspaces), "active": active}


@app.get("/api/hosts")
async def get_hosts(protocol: str, workspace: str = "default", _user: str = Depends(get_current_user)):
    if protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    try:
        return {"hosts": nxc_db.get_hosts(workspace, protocol)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/hosts/pwned")
async def get_pwned_hosts(protocol: str, workspace: str = "default", _user: str = Depends(get_current_user)):
    if protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    try:
        return {"hosts": nxc_db.get_pwned_hosts(workspace, protocol)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/hosts/backconnect")
async def get_backconnect_hosts(protocol: str, workspace: str = "default", _user: str = Depends(get_current_user)):
    if protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    try:
        return {"hosts": nxc_db.get_backconnect_hosts(workspace, protocol)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Back Connect (reverse shell payload trigger + listener/session bridge)
# ---------------------------------------------------------------------------

@app.get("/api/backconnect/route")
async def get_backconnect_route(target: str, _user: str = Depends(get_current_user)):
    try:
        detected_callback_host, detected_allowed_source = discover_callback_route(target)
        callback_host = config.CALLBACK_HOST or detected_callback_host
        allowed_source = config.CALLBACK_ALLOWED_SOURCE or detected_allowed_source
        wsl_detected = is_wsl_environment()
        warnings: list[str] = []
        if wsl_detected and not config.CALLBACK_HOST:
            warnings.append(
                "WSL detected. In NAT mode, use the Windows LAN IP as the callback host "
                "or set NXCWEB_CALLBACK_HOST."
            )
        if wsl_detected and _is_loopback_host(config.LISTENER_BIND_HOST):
            warnings.append(
                "The listener is bound to loopback; external callbacks require an explicit "
                "NXCWEB_LISTENER_BIND value and a narrow firewall rule."
            )
        if wsl_detected and not config.CALLBACK_ALLOWED_SOURCE:
            warnings.append(
                "Windows portproxy may appear as the Windows-to-WSL gateway; if a callback is "
                "rejected, use the displayed peer IP as Allowed source."
            )
        return {
            "callback_host": callback_host,
            "allowed_source": allowed_source,
            "detected_callback_host": detected_callback_host,
            "detected_allowed_source": detected_allowed_source,
            "callback_overridden": bool(config.CALLBACK_HOST),
            "source_overridden": bool(config.CALLBACK_ALLOWED_SOURCE),
            "listener_bind_host": config.LISTENER_BIND_HOST,
            "wsl_detected": wsl_detected,
            "warning": " ".join(warnings) or None,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.post("/api/backconnect/listeners")
async def start_listener(req: BackConnectListenerRequest, _user: str = Depends(get_current_user)):
    try:
        listener = await backconnect_manager.start_listener(req.port, req.allowed_source, req.label)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Could not bind port {req.port}: {exc}") from exc
    return {
        "id": listener.id,
        "port": listener.port,
        "label": listener.label,
        "allowed_source": str(listener.allowed_network),
    }


@app.get("/api/backconnect/listeners")
async def list_listeners(_user: str = Depends(get_current_user)):
    return {
        "listeners": [
            {
                "id": listener_.id,
                "port": listener_.port,
                "label": listener_.label,
                "allowed_source": str(listener_.allowed_network),
                "created_at": listener_.created_at,
                "rejected_connections": [
                    {
                        "peer": rejected.peer,
                        "rejected_at": rejected.rejected_at,
                        "reason": rejected.reason,
                    }
                    for rejected in listener_.rejected_connections
                ],
                "sessions": [
                    {"id": s.id, "peer": s.peer, "connected_at": s.connected_at, "closed": s.closed}
                    for s in listener_.sessions.values()
                ],
            }
            for listener_ in backconnect_manager.list_listeners()
        ]
    }


@app.delete("/api/backconnect/listeners/{listener_id}")
async def stop_listener(listener_id: str, _user: str = Depends(get_current_user)):
    await backconnect_manager.stop_listener(listener_id)
    return {"ok": True}


@app.delete("/api/backconnect/sessions/{session_id}")
async def close_session(session_id: str, _user: str = Depends(get_current_user)):
    await backconnect_manager.close_session(session_id)
    return {"ok": True}


@app.post("/api/backconnect/trigger", response_model=JobSummary)
async def trigger_backconnect(req: BackConnectTriggerRequest, _user: str = Depends(get_current_user)):
    if req.protocol not in PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unknown protocol")
    if not PROTOCOLS[req.protocol]["supports_exec"]:
        raise HTTPException(status_code=400, detail="Selected protocol does not support command execution")
    if req.protocol == "ssh" and req.shell_type != "cmd":
        raise HTTPException(status_code=400, detail="SSH back connect requires command execution (-x), not PowerShell (-X)")
    if req.exec_method and req.exec_method not in EXEC_METHODS.get(req.protocol, []):
        raise HTTPException(status_code=400, detail=f"Exec method '{req.exec_method}' is not supported for {req.protocol.upper()}")
    if not req.confirm_authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required")
    active_workspace = nxc_db.get_active_workspace()
    if req.workspace != active_workspace:
        raise HTTPException(
            status_code=409,
            detail=f"NetExec active workspace is '{active_workspace}'. Select it before triggering back connect.",
        )
    try:
        accessible_hosts = nxc_db.get_backconnect_hosts(req.workspace, req.protocol)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    target = req.target.casefold()
    confirmed_access = any(
        target in {str(host.get("host") or "").casefold(), str(host.get("hostname") or "").casefold()}
        for host in accessible_hosts
    )
    if not confirmed_access:
        confirmed_access = any(
            job.protocol == req.protocol and target in {host.casefold() for host in job.pwned_hosts}
            for job in job_manager.list_jobs()
        )
    if not confirmed_access:
        required_access = "SSH shell access or Pwn3d" if req.protocol == "ssh" else "Pwn3d"
        raise HTTPException(
            status_code=409,
            detail=f"Target is not recorded with {required_access} in workspace '{req.workspace}'",
        )

    scan = ScanRequest(
        protocol=req.protocol,
        targets=[req.target],
        username=req.username,
        password=req.password,
        hashes=req.hashes,
        domain=req.domain,
        kerberos=req.kerberos if req.protocol != "ssh" else False,
        local_auth=req.local_auth if req.protocol != "ssh" else False,
        execute_command=req.command if req.shell_type == "cmd" else None,
        execute_powershell=req.command if req.shell_type == "powershell" else None,
        exec_method=req.exec_method,
        no_output=True,
        extra_args=req.extra_args,
        workspace=req.workspace,
    )
    try:
        job = await job_manager.start_job(scan)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return _job_to_summary(job)


@app.websocket("/ws/backconnect/{session_id}")
async def backconnect_session_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    token = websocket.cookies.get(COOKIE_NAME) or websocket.query_params.get("token")
    username = security.verify_ws_session(token)
    if not username:
        await websocket.close(code=4401)
        return
    if not _acquire_ws_slot(username):
        await websocket.close(code=4429)
        return

    try:
        subscription = backconnect_manager.subscribe(session_id)
        if subscription is None:
            await websocket.close(code=4404)
            return
        queue, transcript, session_closed = subscription

        if transcript:
            await websocket.send_json({"type": "data", "data": transcript.decode(errors="replace")})
        if session_closed:
            await websocket.send_json({"type": "closed"})
            backconnect_manager.unsubscribe(session_id, queue)
            return

        async def _reader() -> None:
            while True:
                data = await queue.get()
                if data is None:
                    await websocket.send_json({"type": "closed"})
                    break
                await websocket.send_json({"type": "data", "data": data.decode(errors="replace")})

        async def _writer() -> None:
            while True:
                message = await websocket.receive_text()
                if not await backconnect_manager.send_input(session_id, message.encode()):
                    break

        reader_task = asyncio.create_task(_reader())
        writer_task = asyncio.create_task(_writer())
        try:
            done, _pending = await asyncio.wait({reader_task, writer_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except WebSocketDisconnect:
            pass
        finally:
            reader_task.cancel()
            writer_task.cancel()
            await asyncio.gather(reader_task, writer_task, return_exceptions=True)
            backconnect_manager.unsubscribe(session_id, queue)
    finally:
        _release_ws_slot(username)


# ---------------------------------------------------------------------------
# Frontend static hosting
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.exception_handler(404)
async def spa_fallback(request: Request, exc):
    if request.url.path.startswith("/api") or request.url.path.startswith("/ws"):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    return FileResponse(str(FRONTEND_DIR / "index.html"))
