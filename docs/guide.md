# MCP Gate — Configuration Guide

This guide covers everything beyond the [Quick Start](../README.md#quick-start). If you haven't set up MCP Gate yet, start there first.

---

## Table of Contents

- [Authentication](#authentication)
- [Security: 2FA and identity confirmation](#security-2fa-and-identity-confirmation)
- [Command Sets](#command-sets)
- [Parameterized Commands](#parameterized-commands)
- [Approval Modes](#approval-modes)
- [Secrets Vault](#secrets-vault)
- [Agents](#agents)
- [Host Setup](#host-setup)
- [Notifications](#notifications)
- [Events and Activity](#events-and-activity)
- [Import / Export](#import--export)
- [Appearance](#appearance)
- [Reverse Proxy Examples](#reverse-proxy-examples)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Authentication

MCP Gate has three authentication modes for the admin UI. Configure in **Settings** or directly in `data/config.yaml` → `instance.auth_type`.

### `basic` (default)

Built-in login with an argon2id-hashed password and a signed session cookie (`SameSite=Strict`) that ends after an idle timeout and an absolute lifetime (both configurable, see [Security](#security-2fa-and-identity-confirmation)). Two-factor authentication (TOTP) is **on by default** and can be switched off.

On first launch you set the admin password and then enroll an authenticator app (2FA). To set a new password from the host:

```bash
docker exec -it mcp-gate python cli.py password
```

API endpoints for auth management:

```
POST /api/auth/login          {"password": "...", "code": "123456"}   # code only when 2FA is on
POST /api/auth/logout
GET  /api/auth/status         → {"authenticated": true, "user": "admin"}
POST /api/auth/change-password {"old_password": "...", "new_password": "..."}
```

### `proxy`

Trust headers set by a reverse proxy (Authentik, Keycloak, Authelia, Caddy Security, etc.):

- `X-Forwarded-User`
- `X-Forwarded-Email`
- `Remote-User`

The first non-empty header becomes the authenticated username. Make sure your proxy strips these headers from external requests to prevent spoofing.

### `none`

No authentication. Use only when MCP Gate is behind a VPN or on an isolated network where the network itself is the trust boundary.

### What auth mode does NOT affect

MCP transport (Claude.ai, Cursor, etc.) and agent API (`/api/exec`) use their own authentication — OAuth 2.0 and API keys respectively. Changing the UI auth mode does not affect agent connectivity.

---

## Security: 2FA and identity confirmation

### Two-factor authentication (TOTP)

- After the first login you scan a QR code with any authenticator app and confirm with a code.
- **10 one-time recovery codes** are shown once: store them somewhere safe.
- "Remember this device" skips the code on that browser for a number of days (Settings → Security).
- To switch 2FA off, use **Settings → Security** (identity confirmation required).

### Identity confirmation (step-up)

Sensitive actions ask for your password and a 2FA code, then stay unlocked for a few minutes: creating agents and issuing keys,
secrets, backup/restore, the admin console, SSH keys, notification channels, security settings and viewing the MCP token.
The UI asks and retries the action automatically.

### Settings → Security

| Setting | Default | Meaning |
|---------|---------|---------|
| Require 2FA | on | Admin login needs a TOTP code |
| Session idle timeout | 60 min | Session ends without activity |
| Session max lifetime | 12 h | Hard limit regardless of activity |
| Remember device | 14 days | `0` = off |
| Failed attempts before lockout | 5 | Per IP |
| Lockout duration | 15 min | |
| Identity confirmation valid | 10 min | |
| Sensitive actions only over HTTPS | off | |
| Accept the legacy global API key | off | Keys without agent restrictions; create a dedicated agent instead |

**End all sessions** revokes every session and remembered device at once.

### Emergency commands

Shell access to the container is root on the gate anyway, so recovery is done there:

```bash
docker exec -it mcp-gate python cli.py totp-reset        # disable 2FA, end all sessions
docker exec -it mcp-gate python cli.py password          # set a new admin password
docker exec -it mcp-gate python cli.py revoke-sessions   # end all sessions and remembered devices
```

### Keys at rest

Put these in `.env` and **keep `.env` in your backups**:

| Variable | Used for |
|----------|----------|
| `MCPGATE_MASTER_KEY` | Encrypts the secrets vault |
| `MCPGATE_KEY_PEPPER` | Agent key hashing (HMAC). Without the variable a pepper is generated in `data/key_pepper` |
| `MCPGATE_SESSION_KEY` | Signs admin sessions |

Generate each with `openssl rand -base64 48`.

---

## Command Sets

Command Sets are reusable groups of SSH commands. Instead of duplicating commands across hosts, you define them once and attach via tags.

### Two types

**Allow** (✓) — whitelisted commands. Green/blue/any color.

**Deny** (✕) — blacklisted commands. Always red. **Highest priority** — if a command matches any deny set, it's blocked regardless of allow sets.

### Authorization formula

```
effective_allow = (host_allow ∩ agent_allow) - (host_deny ∪ agent_deny)
```

In plain language:
- A command must be allowed by **both** the host and the agent (intersection)
- If either the host or the agent has a deny set containing the command, it's blocked (union of denies)
- An agent with no assigned allow sets inherits all host allows (intersection is not restrictive)

### Example setup

Create three command sets:

| Set | Type | Commands |
|-----|------|----------|
| `system-basic` | Allow | `uptime`, `free -h`, `df -h` |
| `docker-service` | Allow | `docker ps`, `docker logs ...`, `docker stats` |
| `deny-destructive` | Deny | `rm`, `reboot`, `docker stop`, `docker rm` |

Assign to hosts:
- **web-server**: `system-basic` + `docker-service` + `deny-destructive`
- **db-server**: `system-basic` + `deny-destructive`

Now `docker ps` works on web-server but not on db-server. And `rm` is blocked everywhere.

### Editing command sets

Changes to a command set apply immediately to all hosts and agents that reference it. No need to update each host individually.

---

## Parameterized Commands

Instead of whitelisting every variation of a command, define parameters with validation:

```yaml
- cmd: "docker logs {container} --tail {lines}"
  description: "Container logs"
  params:
    container:
      pattern: "^[a-z0-9][a-z0-9_.-]{0,63}$"
      description: "Container name"
    lines:
      pattern: "^[0-9]{1,4}$"
      default: "50"
      description: "Number of lines"
```

### How it works

1. Agent sends: `{"command": "docker logs {container} --tail {lines}", "args": {"container": "nginx", "lines": "100"}}`
2. MCP Gate validates each argument against its regex pattern
3. Shell special characters (`` ; | & ` $ ``) are blocked by default
4. After validation, arguments are substituted into the command
5. The final command (`docker logs nginx --tail 100`) is executed via SSH

### Parameter options

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Regex for validation (fullmatch) |
| `description` | No | Shown in UI and to agents |
| `default` | No | Used when agent doesn't provide a value |
| `max_length` | No | Maximum argument length |
| `allow_shell_chars` | No | Set `true` to allow `` ; | & ` $ `` (use with caution) |

---

## Approval Modes

Each host has an approval mode that controls what happens **after** a command passes the whitelist check.

| Mode | On submit | On timeout | Use case |
|------|-----------|------------|----------|
| `auto` | Execute immediately | — | Trusted hosts, read-only commands |
| `optimistic` | Queue for approval | Auto-approve | Default. Balance of safety and convenience |
| `pessimistic` | Queue for approval | Auto-reject | Sensitive hosts, human required |
| `strict` | Queue for approval | Wait forever | Production, critical infrastructure |

### Per-command override

Individual whitelist entries can override the host's approval mode. For example, a host in `auto` mode can have `reboot` set to `strict`, requiring manual approval for that specific command while allowing everything else to run immediately.

### Approving/rejecting

Pending approvals appear on the Dashboard and in the Audit Log. You can approve or reject from either place. Telegram/email notifications can alert you when approval is needed (see [Notifications](#notifications)).

---

## Secrets Vault

Store sensitive values (passwords, API tokens, database credentials) encrypted and use them in commands without the LLM agent ever seeing the real values.

### Adding a secret

Go to **Secrets → Add Secret**:
- **ID**: identifier used in commands (e.g., `db_password`)
- **Value**: the actual secret (encrypted with Fernet immediately)
- **Allowed hosts**: which hosts can use this secret (security boundary)

### Using secrets in commands

Add a whitelisted command with `$SECRET{id}` placeholder:

```
PGPASSWORD=$SECRET{db_password} psql -h localhost -U admin -c "SELECT 1"
```

At execution time:
1. `$SECRET{db_password}` is replaced with the real value from the vault
2. The command runs via SSH
3. If the output contains the secret value, it's replaced with `[REDACTED]`
4. The audit log never contains the real secret

### Encryption details

Secrets are encrypted with Fernet (symmetric, AES-128-CBC + HMAC-SHA256). The encryption key is stored in `data/ssh_keys/secrets.key` and is generated on first boot. **Back up this file** — without it, encrypted secrets cannot be recovered.

---

## Agents

Agents represent the LLM clients that connect to MCP Gate. Each agent has its own permissions, rate limits, and API key.

### Agent types

Claude, ChatGPT, Gemini, Cursor, Windsurf, Continue, Cline, Open WebUI, Custom.

The type affects the icon in the UI but not the functionality — all agents use the same API and MCP protocol.

### Agent settings

| Setting | Description |
|---------|-------------|
| **Command Sets** | Which command sets this agent can use (allow/deny). Combined with host sets via the authorization formula |
| **Allowed Hosts** | Restrict agent to specific hosts (empty = all enabled hosts) |
| **Rate Limit** | Max requests per minute for this agent |
| **API Key** | Stored only as an HMAC-SHA256 hash, **shown once** when issued. Used for `/api/exec` calls |
| **Allowed IP / CIDR** | The key is accepted only from these addresses (empty = any) |
| **Key lifetime (days)** | `0` = never expires; an expired key is refused with the reason |
| **Auto-off (minutes)** | `0` = normal toggle. `> 0` = timed (just-in-time) grant: switching the agent on opens it for N minutes, then it switches itself off |
| **Enabled** | Toggle agent on/off without deleting |

The agent card shows when and from which IP the key was last used. A refused key gets a clear reason: disabled, grant expired, key expired or IP not allowed. Lost a key? Issue a new one: it cannot be shown again.

### MCP connector agents

When Claude.ai or Cursor connects via MCP, an agent is created automatically during the OAuth flow. The agent ID is derived from the OAuth client registration.

### Multiple agents

You can create separate agents for different use cases:
- `claude-readonly` — only `system-basic` commands, all hosts
- `claude-docker` — `system-basic` + `docker-service`, specific hosts
- `cursor-dev` — broader access for development workflows

---

## Host Setup

After adding a host in the UI, you need to prepare the target server. MCP Gate generates all the commands for you.

### Auto-generated instructions

Open the host detail page → **Host Setup Instructions**. You'll get ready-to-copy commands for:

1. **Create SSH user** — dedicated `mcp-reader` user with no password login
2. **Deploy SSH key** — the public key from MCP Gate's generated Ed25519 keypair
3. **Configure sudoers** — whitelist specific commands with exact argument matching

Example generated sudoers:
```
mcp-reader ALL=(ALL) NOPASSWD: /usr/bin/journalctl -p err --since '24 hours ago' --no-pager -n 50
mcp-reader ALL=(ALL) NOPASSWD: /usr/sbin/smartctl -a /dev/sda
```

This is defense-in-depth: even if MCP Gate's whitelist is bypassed, the OS-level sudoers prevents unauthorized command execution.

### SSH key management

MCP Gate generates an Ed25519 keypair on first boot, stored in `data/ssh_keys/`. The same keypair is used for all hosts. The public key is shown in Host Setup Instructions.

Known hosts are managed automatically:
- **First connection**: fingerprint is saved (trust-on-first-use)
- **Subsequent connections**: fingerprint is verified. If it changes, the connection is rejected (MITM protection)

### Testing connectivity

Use the **SSH Test** button on the host page to verify connectivity before running commands.

---

## Notifications

MCP Gate sends alerts through notify-gate (recommended), Telegram and/or email.

### Telegram

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID (send `/start` to [@userinfobot](https://t.me/userinfobot))
3. Go to **Settings → Notifications** and fill in Bot Token and Chat ID

### Email (SMTP)

Configure in **Settings → Notifications**:
- SMTP server and port
- Username and password
- Sender and recipient addresses

### What triggers notifications

- Commands pending approval (optimistic/pessimistic/strict modes)
- Commands auto-approved or auto-rejected on timeout
- Blocked commands (whitelist violations)
- Security and operations events (see [Events and Activity](#events-and-activity))

---

## Events and Activity

### Events

Logins and failures, agent / host / command set / secret changes, key issue, SSH keys, console commands, exports, approvals,
timed grants, blocked commands, refused agent keys and OAuth are classified in one place and delivered through a **durable outbox
with retries**. A flood of similar events is aggregated into one message. Per-event on/off and severity, and a delivery journal,
are on the **Notifications** page.

Delivery to notify-gate (JSON source) is configured in `.env`:

```bash
NOTIFY_GATE_URL=http://notify-gate:8010
NOTIFY_GATE_SOURCE=mcp-gate
NOTIFY_GATE_TOKEN=<source token>
```

Telegram and SMTP from the UI work as a fallback or in parallel.

### Activity dashboard

The Dashboard shows commands per hour (ok / blocked / error / pending) for 24 hours, 7 days or 30 days, split per agent and per host,
with authentication failures and the top block reasons. The counters survive audit trimming.

### Prometheus

`GET /metrics` is served on the same port and is limited by `METRICS_CIDRS` (default `127.0.0.1/32`):

```yaml
scrape_configs:
  - job_name: mcp-gate
    metrics_path: /metrics
    static_configs:
      - targets: ["mcp-gate:8000"]
```

Behind a reverse proxy set `TRUSTED_PROXIES`, so the real client IP appears in audit entries and events.

---

## Import / Export

All entities (hosts, agents, command sets, secrets) support import and export as JSON.

### Export

Each management page has an **Export** button that downloads the current data as a `.json` file.

### Import

Two methods:
- **Paste JSON** — open the Import modal, paste JSON text, preview the count, and confirm
- **Upload File** — drag-and-drop or select a `.json` file

Import validates JSON structure and shows a preview before applying. Existing items with the same ID are overwritten.

### Full backup

Use **Settings → Backup** to export everything (config, hosts, agents, command sets, secrets) as a single archive.

---

## Appearance

Go to **Settings → Appearance** to customize:

- **Theme** — 6 built-in color themes
- **Background** — upload a custom background image
- **Logo** — upload a custom logo for the navigation sidebar
- **Glassmorphism** — translucent UI panels with backdrop blur

Appearance settings are stored in `data/config.yaml` and custom assets in `data/assets/`.

---

## Reverse Proxy Examples

### Traefik (basic)

```yaml
http:
  routers:
    mcp-gate:
      rule: "Host(`mcp-gate.example.com`)"
      service: mcp-gate
      tls:
        certResolver: le
  services:
    mcp-gate:
      loadBalancer:
        servers:
          - url: "http://mcp-gate:8000"
```

### Traefik with IP allowlist and rate limiting

```yaml
http:
  middlewares:
    mcp-lan:
      ipAllowList:
        sourceRange: ["192.168.0.0/24", "10.0.0.0/8"]
    mcp-ratelimit:
      rateLimit:
        average: 60
        burst: 20
  routers:
    mcp-gate:
      rule: "Host(`mcp-gate.example.com`)"
      middlewares: ["mcp-lan", "mcp-ratelimit"]
      service: mcp-gate
      tls:
        certResolver: le
  services:
    mcp-gate:
      loadBalancer:
        servers:
          - url: "http://mcp-gate:8000"
```

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name mcp-gate.example.com;

    ssl_certificate     /etc/ssl/certs/mcp-gate.pem;
    ssl_certificate_key /etc/ssl/private/mcp-gate.key;

    location / {
        proxy_pass http://mcp-gate:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for audit live updates)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Caddy

```
mcp-gate.example.com {
    reverse_proxy mcp-gate:8000
}
```

### Proxy auth mode (Authentik, Keycloak, etc.)

When using `proxy` auth mode, your identity provider should set the `X-Forwarded-User` header. Example with Traefik + Authentik:

```yaml
http:
  middlewares:
    authentik:
      forwardAuth:
        address: "http://authentik:9000/outpost.goauthentik.io/auth/traefik"
        trustForwardHeader: true
        authResponseHeaders:
          - X-authentik-username
          - X-Forwarded-User
  routers:
    mcp-gate:
      rule: "Host(`mcp-gate.example.com`)"
      middlewares: ["authentik"]
      service: mcp-gate
```

Set `auth_type: proxy` in MCP Gate settings. The `X-Forwarded-User` header from Authentik becomes the authenticated admin username.

---

## Monitoring

### Health endpoint

```
GET /health
→ {"status": "ok", "version": "0.0.7", "hosts_total": 2, "hosts_enabled": 2, "agents": 1}
```

Use this with Uptime Kuma, Prometheus Blackbox Exporter, or any HTTP health checker. The endpoint requires no authentication.

### Audit log

The audit log (`data/audit.jsonl`) is append-only JSONL. Each line is a JSON object with:

```json
{
  "ts": 1711700000.0,
  "host_id": "web-server",
  "command": "uptime",
  "status": "ok",
  "source": "claude",
  "duration_ms": 230,
  "exit_code": 0
}
```

You can ingest this file into any log aggregator (Loki, ELK, etc.) for long-term analysis.

Auto-trim: the audit log is automatically trimmed based on retention settings (default: 90 days, max 10K entries). Configure in Settings.

---

## Troubleshooting

### Container starts but UI shows 502

The app needs 10-15 seconds to start. Check `docker logs mcp-gate` for errors. Common causes:
- Missing `MCP_TOKEN` in `.env`
- Port 8090 already in use
- Data directory permissions

### SSH test fails

- Verify the target host is reachable from the container: `docker exec mcp-gate ping -c1 TARGET_IP`
- Check that the public key is in `~/.ssh/authorized_keys` on the target
- Verify the SSH user exists and has the correct permissions
- Check `data/ssh_keys/known_hosts` — if the host key changed, remove the old entry

### MCP connector won't connect

- `MCP_BASE_URL` must be set to the publicly accessible URL (HTTPS required)
- The URL must be reachable from the internet (Claude.ai connects from Anthropic's servers)
- Check that your reverse proxy forwards `/oauth/`, `/.well-known/`, and MCP transport paths correctly

### Agent API returns 403

- Verify the API key is correct (shown only once on creation)
- Check that the command is in the agent's effective whitelist
- Check rate limits — if exceeded, wait and retry

### Lost admin password

Remove `admin_password_hash` from `data/config.yaml` and restart the container. The first-time setup wizard will appear again.

### Lost API key

API keys cannot be recovered (Fernet-encrypted). Delete the agent and create a new one. For MCP connector agents, disconnect and reconnect from your LLM client.
