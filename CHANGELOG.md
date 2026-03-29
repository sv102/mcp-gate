# Changelog

All notable changes to MCP Gate are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.1.0] — 2026-03-29

### Added
- **App-level authentication** — three modes: `basic` (built-in login with bcrypt password + HMAC-signed httpOnly cookie, 7-day sessions, first-time setup wizard), `proxy` (trust X-Forwarded-User from Authentik/Keycloak/etc.), `none` (no auth for homelabs behind VPN). Dedicated login page with appearance/i18n support
- **MCP Protocol transport** — Streamable HTTP (`POST /`) + SSE fallback. Claude.ai, Cursor, Windsurf, Continue, Cline connect natively via standard MCP connector
- **OAuth 2.0 authentication** — Dynamic Client Registration, PKCE S256, Bearer tokens (90-day), per-agent binding
- **Agents management** — create agents for Claude, ChatGPT, Gemini, Cursor, Windsurf, Continue, Cline, Open WebUI, Custom. Per-agent command sets, rate limits, allowed hosts
- **Command Sets** — reusable groups of commands with two types: Allow (whitelist) and Deny (blacklist, highest priority). Authorization formula: `(host_allow ∩ agent_allow) - (host_deny ∪ agent_deny)`
- **Parameterized commands** — variables in commands (`docker logs {container} --tail {lines}`) with regex validation, max_length, default values, shell character blocking
- **Secrets Vault** — Fernet-encrypted storage, `$SECRET{id}` substitution at execution time, output scrubbing, per-host binding
- **Unified exec pipeline** — single `execute_command()` for API, Console, and MCP transport. Auth → params → approval → secrets → SSH → scrub → audit
- **Host Setup Instructions** — auto-generated useradd, SSH authorized_keys, sudoers whitelist with exact match arguments
- **Import/Export** — paste JSON or drag-and-drop .json files for hosts, agents, command sets, secrets
- **Audit improvements** — CRUD logging (create/update/delete/toggle/import), quick-filter chips, advanced filters, clickable cells, 24h/7d/clear, JSON/CSV export, WebSocket real-time updates
- **SSH security** — managed `known_hosts` (save-on-first-connect, reject-on-key-change), Ed25519 key generation
- **Appearance theming** — 6 built-in themes, glassmorphism, custom backgrounds, custom logo
- **Dashboard** — compact stat cards, host/agent tiles with ping status and command set tags, clickable 24h/7d metrics
- **i18n** — English and Russian, full coverage
- **Notifications** — Telegram bot and SMTP email alerts
- **Host/Agent duplication** — one-click clone with auto-generated ID

### Changed
- Modular codebase: split into `auth.py`, `executor.py`, `models.py`, `app_state.py`, `tasks.py`, `routes_admin.py`, `routes_ui.py`, `storage.py`, `ssh_client.py`, `params.py`, `notifications.py`, `constants.py`, `mcp_transport.py`
- VERSION centralized in `constants.py`
- API key encryption: Fernet (reversible) instead of bcrypt
- Helper functions renamed for clarity (`_rl` → `_check_rate_limit`, `_vkey` → `_validate_api_key`)
- Entity ID validation: regex `^[a-z0-9][a-z0-9_-]{0,63}$`

### Fixed
- MCP transport now respects approval modes (was bypassing them)
- Approval loop re-checks authorization before auto-approve on timeout
- `list_hosts` correctly separates allow/deny command sets
- Removed duplicate imports, `__import__("time")` hack

### Security
- Built-in authentication system replacing broken basicAuth middleware
- SSH `AutoAddPolicy` replaced with `_ManagedHostKeyPolicy` (MITM protection)
- Approval recheck before timeout auto-approve
- Auth middleware: session-aware, public paths (MCP, health, static, agent exec API) bypass correctly

## [0.0.6] — 2026-03-22

### Added
- Initial public release
- Basic whitelist-only SSH execution
- Web UI with dashboard, hosts, audit log
- 4 approval modes: auto, pessimistic, optimistic, strict
- Rate limiting per host
- Dry run mode
- BasicAuth for admin UI
