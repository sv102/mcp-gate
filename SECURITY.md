# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities by emailing:

**security@sv-projekt.ru**

Or, if you prefer, use [GitHub Security Advisories](https://github.com/sv102/mcp-gate/security/advisories/new) (private by default).

### What to include

- Description of the vulnerability
- Steps to reproduce or proof-of-concept
- Potential impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and disclosure**: coordinated with reporter, typically within 30 days

### Scope

The following are in scope:

- Authentication bypass (WebUI, MCP transport, API)
- Command injection / whitelist bypass
- SSH credential exposure
- Secret leakage in audit logs, API responses, or WebUI
- Privilege escalation between agents
- Denial of service against the gate itself

### Out of scope

- Vulnerabilities in upstream dependencies (report to the upstream project)
- Social engineering attacks
- Issues requiring physical access to the host

## Acknowledgements

We appreciate responsible disclosure and will credit reporters (with
permission) in the release notes.
