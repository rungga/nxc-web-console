# Changelog

All notable changes to this project will be documented in this file.

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