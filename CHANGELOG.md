# Changelog

All notable changes to MCP Gate are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.1.3] — 2026-05-15

### Fixed
- **CRITICAL: `get_queue_item` / `update_queue_status` missing from storage** — both
  functions were used by `mcp_transport.py` but never defined, causing `AttributeError`
  on every pending-approval request via MCP transport
- **CRITICAL: `cleanup_expired` set status `"approve"`/`"reject"`** instead of
  `"approved"`/`"rejected"` — mismatch with `mcp_transport.py` status checks meant
  auto-approve and auto-reject on timeout never worked correctly
- **Circular import** — `export_backup()` in `storage.py` did `from main import VERSION`;
  replaced with `from constants import VERSION`
- **MCP approval polling held connection 120 s** — replaced 2 s polling loop in
  `mcp_transport._exec_tool` with `asyncio.wait_for(event.wait(), timeout)`;
  MCP handler now wakes instantly when operator approves/rejects
- **Rate limiting field ignored** — `host.rate_limit` and `agent.rate_limit` were
  stored and displayed but never checked at execution time; now enforced in
  `executor.execute_command()` with sliding 60 s window
- **WebSocket dead-client accumulation** — `ws_broadcast` had no timeout; slow or
  disconnected clients could block the broadcast loop. Added `asyncio.wait_for(timeout=2s)`
  with automatic removal of dead connections
- **SMTP flood on command storms** — Telegram and SMTP shared a single cooldown key;
  SMTP could flood independently. Now each channel has its own cooldown counter
- **Unresolved `{placeholder}` after param substitution** — if template had a
  `{name}` that was not in `params` spec, it passed silently. Now raises `ValueError`

### Added
- **SQLite audit log** — replaced O(N) JSONL full-file reads with indexed SQLite
  (`audit.db`, WAL mode, indexes on ts/host_id/status/source). Automatic one-time
  migration from `audit.jsonl` on first start; old file renamed to `audit.jsonl.bak`
- **SSH connection pool** — reuses paramiko connections per host (TTL 300 s,
  per-host `threading.Lock` for serialised access). Eliminates TCP+SSH handshake
  overhead on every command
- **Command set in-process cache** — `get_command_set()` caches results for 5 s,
  reducing YAML reads on the authorization hot path. Invalidated on write
- **`asyncio.Event`-based approval signalling** — `app_state.create_approval_event(aid)` /
  `signal_approval(aid)` infrastructure; `tasks.approval_loop` and manual approve/reject
  routes both signal the event for instant MCP handler wake-up
- **MCP token management API** — `GET /api/admin/mcp-tokens` (list active OAuth tokens,
  masked), `DELETE /api/admin/mcp-tokens/{hash}` (revoke by SHA-256 prefix),
  `GET /api/admin/mcp-tokens/count`
- **`SECURE_COOKIE` env var** — controls the `Secure` flag on the session cookie.
  Default `0` (no Secure flag) for LAN deployments behind Traefik; set `1` when
  running with direct HTTPS without a TLS-terminating proxy

### Security
- Approval re-authorization now blocks auto-approve if whitelist changed since queuing
- Rate limits enforced at executor level (previously cosmetic UI-only field)

## [0.1.2] — 2026-04-04

### Fixed
- **CRITICAL: Disabled agent still accepted MCP requests** — `_require_mcp_auth()` only
  validated token expiry but did not check `agent.enabled`. Toggling an agent OFF in
  WebUI had no effect on active MCP sessions. Now both `_require_mcp_auth()` and
  `_exec_tool()` verify agent is enabled; disabled agents get HTTP 403 immediately
- **Dashboard "Approvals" card overflow** — pending approvals with long commands or
  many items overflowed the card boundary. Added `max-height` with scroll
- **Host setup script used wrong field name** — `routes_onboarding.py` read
  `h.get("username")` but hosts.yaml stores it as `user`. Always defaulted to
  "mcp-reader" regardless of actual config
- **Duplicate `downloadSetup()` function** in dashboard.html — two identical
  definitions caused the first to be silently overwritten
- **Duplicate `data-i18n` attributes** on dashboard metric labels — cosmetic but
  produced invalid HTML
- **Duplicate Setup button** on host tiles in dashboard
- **Missing SPDX header** in `routes_onboarding.py` — Copyright and GitHub URL
  lines were absent

### Changed
- `.gitignore` — added `*.bak` pattern (previously only `*.bak_*` was covered,
  leaving `*.bak` and `*.bak2` files unignored)
- `.dockerignore` — added `*.bak[0-9]*` pattern and `.github/` exclusion
- README.md — comprehensive rewrite with detailed architecture diagram, all 12+
  screenshots, step-by-step installation guide, Nginx reverse proxy example,
  update instructions, security model explanation

### Security
- Agent disable toggle now immediately blocks all MCP protocol access (OAuth
  tokens are validated against live agent state on every request)

## [0.1.1] — 2026-04-02

### Fixed
- **`$store is not defined` on approval confirm** — Alpine.js `$store` magic property
  is only available in HTML template directives; plain JS callbacks (`resolve()`,
  WebSocket `onmessage`) must use `T()` global helper or `Alpine.store()` directly.
  Replaced all bare `$store.i18n.t()` calls with `T()` in `approvals.html`
- **`GET /api/admin/pending` → 404** — `base.html` fetches this endpoint on every
  page load to initialize the nav badge counter; endpoint was missing.
  Added `GET /api/admin/pending` → `storage.get_pending_approvals()`
- **WebSocket `RuntimeError` spam in logs** — `ws_audit` ping loop raised
  `RuntimeError: Cannot call "send" once a close message has been sent.` when browser
  closed connection without a proper disconnect frame; was not caught by
  `except WebSocketDisconnect`. Changed to `except (WebSocketDisconnect, RuntimeError)`

### Added
- Pending approval toast notification on Dashboard when new approval arrives via WebSocket

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
- **Host Setup Instructions** — three tabs: Quick (user + SSH key), Sudoers (sudo rules from command sets), Full (complete setup). Download .sh button, Deploy Key button (auto-deploy via SSH), Verify sudoers button
- **Host status polling** — live status dots on host cards (grid + list), 30-second refresh
- **Import/Export** — paste JSON or drag-and-drop .json files for hosts, agents, command sets, secrets
- **Audit improvements** — CRUD logging (create/update/delete/toggle/import), quick-filter chips, advanced filters, clickable cells, 24h/7d/clear, JSON/CSV export, WebSocket real-time updates
- **SSH Key Management** — full lifecycle: generate, rotate, deploy to hosts, per-host keys, known_hosts viewer
- **SSH security** — managed known_hosts (TOFU, reject-on-key-change MITM protection), path traversal protection, sanitization, backup export strips key_path
- **Appearance theming** — 6 built-in themes, glassmorphism, custom backgrounds, custom logo
- **Dashboard** — compact stat cards, host/agent tiles with ping status and command set tags, clickable 24h/7d metrics
- **i18n** — English and Russian, full coverage
- **Notifications** — Telegram bot and SMTP email alerts
- **Host/Agent duplication** — one-click clone with auto-generated ID

### Changed
- Modular codebase: split into 14 modules
- VERSION centralized in `constants.py`
- API key encryption: Fernet instead of bcrypt
- Entity ID validation: regex `^[a-z0-9][a-z0-9_-]{0,63}$`

### Fixed
- MCP transport respects approval modes
- Approval loop re-checks authorization before auto-approve

### Security
- Built-in auth system replacing broken basicAuth middleware
- SSH `AutoAddPolicy` replaced with `_ManagedHostKeyPolicy`
- Approval recheck before timeout auto-approve

## [0.0.6] — 2026-03-22

### Added
- Initial public release
- Basic whitelist-only SSH execution
- Web UI with dashboard, hosts, audit log
- 4 approval modes: auto, pessimistic, optimistic, strict
- Rate limiting per host
- Dry run mode
- BasicAuth for admin UI
