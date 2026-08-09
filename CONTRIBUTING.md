# Contributing

Contributions to the public beta are welcome when they improve authorized security assessment workflows, reliability, accessibility, documentation, or defensive guardrails.

## Ground rules

- Do not include real credentials, customer targets, assessment output, malware, persistence payloads, or destructive examples.
- Keep NetExec as a separate runtime dependency; do not vendor upstream source or binaries.
- Preserve server-side validation and credential redaction.
- Report security issues through [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

```bash
./run.sh
```

Install development dependencies in the backend virtual environment, then run:

```bash
cd backend
PYTHONPATH=. .venv/bin/python -m unittest discover -s tests -v
cd ..
node --check frontend/static/js/app.js
node --check frontend/static/js/api.js
bash -n run.sh bin/nxc-lima
```

Add focused tests for behavior changes. Keep edits scoped and avoid unrelated formatting or dependency churn.

## Pull requests

Describe the operator workflow, security impact, validation performed, and any compatibility limitations. Public beta changes may break compatibility before 1.0, but migrations and user-visible behavior changes must be documented in [CHANGELOG.md](CHANGELOG.md).