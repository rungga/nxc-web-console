# Security Policy

## Supported versions

`1.0.0` is the supported stable release for local, single-process use in authorized security labs. Non-loopback deployments require the HTTPS, secret-management, and firewall controls documented in the README.

## Reporting a vulnerability

Do not publish vulnerability details, credentials, targets, logs, or proof-of-concept payloads in a public issue.

Use GitHub Private Vulnerability Reporting under the repository **Security** tab. If private reporting is unavailable, contact the repository owner privately through their verified GitHub profile before disclosing technical details.

Include:

- affected version and component;
- reproducible steps using synthetic or authorized targets;
- security impact;
- suggested remediation, when known.

Reports about the NetExec runtime itself should be sent to the upstream [NetExec security process](https://github.com/Pennyw0rth/NetExec/security), not this independent console project.

## Operational security

- Run only against explicitly authorized systems.
- Keep the web server on loopback unless it is protected by HTTPS, authentication, and a firewall.
- Keep callback listeners on loopback unless an authorized external callback requires an explicit interface bind and narrow firewall rule.
- Treat generated and administrator-reset passwords as temporary credentials and replace them immediately after login.
- Never commit API keys, generated passwords, session keys, job databases, or assessment logs.
- Treat AI suggestions and raw CLI arguments as untrusted until reviewed by an authorized operator.