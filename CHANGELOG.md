# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Back-connect listeners now bind to all interfaces (`0.0.0.0`) by default, matching a manual `nc -l` listener, so authorized remote targets can call back without extra configuration. Set `NXCWEB_LISTENER_BIND=127.0.0.1` to restrict to loopback; per-connection `allowed_source` filtering still authorizes each peer regardless of bind address.

## [1.0.0] - 2026-08-11

### Added

- Interactive `./run.sh reset-password` recovery command with password policy validation.
- Mandatory password change for generated, newly created, and administrator-reset credentials.
- WSL-aware callback route warnings and environment overrides for callback host and accepted source.
- Rejected callback peer diagnostics in the listener API and browser UI.
- WSL2 mirrored and NAT callback setup and troubleshooting documentation.
- Application screenshots for the Scan and WSL2 NAT Back Connect workflows.

### Changed

- Callback hosts can be adjusted in the browser when route auto-detection is not reachable from the target.
- Listener startup registers state before accepting clients, avoiding an early-connection race.

### Security

- Existing accounts migrate without forced lockout, while temporary credentials cannot access operational HTTP or WebSocket endpoints until changed.
- The back-connect listener remains loopback-only by default; external binding still requires explicit operator configuration.

## [0.1.0-beta.1] - 2026-08-09

### Added

- FastAPI and WebSocket console for NetExec job execution and live output.
- Multi-user administrator/operator authentication with session rotation.
- Protocol-aware scan controls and runtime module catalog validation.
- Read-only NetExec workspace host and credential views.
- Authorized back-connect listeners with source-network restrictions.
- Local and remote-provider AI command suggestions with bounded input and output guardrails.
- macOS Lima wrapper for a separately provisioned NetExec runtime.

### Security

- Credential and command redaction in persisted job metadata and logs.
- Bounded request payloads, job concurrency, history, log sizes, transcripts, and subscriber queues.
- Loopback defaults for the web server and back-connect listener.
- Stop-before-process-spawn handling and lossless stream close sentinels.

### Known limitations

- Public beta; not production-ready.
- No built-in TLS termination, process supervisor, or multi-worker coordination.
- Active jobs, listeners, and callback sessions do not recover across restarts.
- Lima provisioning and non-macOS packaging remain manual.