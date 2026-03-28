# MCP Gate

**SSH Access Control for LLM Agents**

MCP Gate is a self-hosted web service that provides secure, controlled SSH access from LLM agents (Claude, GPT, etc.) to your infrastructure. Instead of giving AI assistants unrestricted shell access, MCP Gate enforces whitelists, approval workflows, rate limiting, and full audit logging.

![Dashboard](docs/screenshots/dashboard.png)

## The Problem

LLM agents need to execute commands on your servers for monitoring, diagnostics, and automation. Direct SSH access is dangerous — one hallucinated `rm -rf` can destroy your infrastructure. MCP Gate sits between the agent and your servers, ensuring only approved commands run.

## How It Works

```
LLM Agent (Claude, GPT, ...)
        │
   MCP Connector / API call
        │
        ▼
   ┌─────────────┐
   │  MCP Gate    │  ← Whitelist check
   │              │  ← Rate limiting
   │  (this app)  │  ← Approval workflow
   │              │  ← Audit logging
   └──────┬──────┘
          │
     SSH (paramiko)
          │
          ▼
   Target Servers
   (only whitelisted commands)
```

## Features

| Feature | Description |
|---------|-------------|
| **Whitelist-only execution** | Only pre-approved commands can run. Everything else is blocked and logged |
| **Command Sets** | Reusable groups of commands that attach to hosts via tags |
| **4 Approval Modes** | `auto`, `pessimistic`, `optimistic`, `strict` |
| **Secrets Vault** | Fernet-encrypted storage. Use `$SECRET{id}` in commands — substituted server-side, scrubbed from responses |
| **Audit Log** | Every request logged. Export as JSON/CSV. Live WebSocket updates |
| **Rate Limiting** | Per-host request limits to prevent LLM loops |
| **Notifications** | Telegram bot and SMTP email alerts |
| **Appearance Theming** | 6 built-in themes, glassmorphism, custom backgrounds |
| **i18n** | English and Russian |
| **Dry Run Mode** | Test whitelists without executing anything |
| **Import/Export** | Backup and restore everything |

## Screenshots

| Dashboard | Hosts | Command Sets |
|-----------|-------|-------------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Hosts](docs/screenshots/hosts.png) | ![Command Sets](docs/screenshots/command-sets.png) |

| Secrets Vault | Audit Log | Settings |
|---------------|-----------|----------|
| ![Secrets](docs/screenshots/secrets.png) | ![Audit](docs/screenshots/audit.png) | ![Settings](docs/screenshots/settings.png) |

| Notifications |
|---------------|
| ![Alerts](docs/screenshots/alerts.png) |

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/sv102/mcp-gate.git
cd mcp-gate
cp .env.example .env
# Edit .env — generate MCP_TOKEN with: openssl rand -hex 32
```

### 2. Start

```bash
docker compose up -d
```

### 3. Open the UI

Navigate to `http://your-server:8090`. On first launch, a bootstrap wizard generates your SSH key pair and API key. **Save the API key immediately — it's shown only once.**

### 4. Add a host

Go to **Hosts → Add Host**, fill in the hostname, SSH user, and whitelisted commands.

### 5. Deploy the SSH key

Copy the generated public key and add it to `~/.ssh/authorized_keys` on each target server.

### 6. Connect your LLM agent

```bash
curl -X POST https://your-server/api/exec \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host_id": "my-server", "command": "uptime"}'
```

## Architecture

```
┌──────────────────────────────────────┐
│            MCP Gate Container        │
│                                      │
│  FastAPI (Python 3.12)               │
│  ├── /api/exec       ← Agent API    │
│  ├── /api/hosts      ← Host list    │
│  ├── /dashboard      ← Web UI       │
│  └── /ws/audit       ← Live events  │
│                                      │
│  Paramiko SSH client                 │
│  Fernet encryption (secrets)         │
│  YAML/JSONL persistence              │
└──────────────────────────────────────┘
```

### Data Files

| File | Purpose |
|------|---------|
| `/data/config.yaml` | Main configuration |
| `/data/hosts.yaml` | SSH host definitions |
| `/data/command_sets.yaml` | Reusable command sets |
| `/data/secrets.yaml` | Fernet-encrypted secrets |
| `/data/audit.jsonl` | Audit log (JSONL) |
| `/data/ssh_keys/` | Generated SSH key pair |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Path to persistent data directory |
| `MCP_TOKEN` | — | API authentication token |

### Reverse Proxy (Traefik example)

```yaml
http:
  routers:
    mcp-gate:
      rule: "Host(`mcp-gate.example.com`)"
      middlewares: [mcp-gate-auth, mcp-gate-lan]
      service: mcp-gate
  middlewares:
    mcp-gate-auth:
      basicAuth:
        users: ["admin:$apr1$YOUR_HASH"]
    mcp-gate-lan:
      ipAllowList:
        sourceRange: ["192.168.0.0/24"]
  services:
    mcp-gate:
      loadBalancer:
        servers: [{url: "http://mcp-gate:8000"}]
```

### Approval Modes

| Mode | Behavior |
|------|----------|
| `auto` | Execute immediately |
| `pessimistic` | Wait for approval; timeout → reject |
| `optimistic` | Wait for approval; timeout → execute |
| `strict` | Wait forever until manually resolved |

## Security

- **Whitelist-only**: Commands not in the whitelist are blocked before SSH
- **Secrets never leak**: `$SECRET{id}` resolved server-side, never in responses or logs
- **Full audit**: Every request logged with context
- **Rate limiting**: Prevents LLM loops
- **LAN-only by default**: ipAllowList behind reverse proxy
- **Dedicated SSH key**: Ed25519, generated on first boot

## API Reference

### Execute Command
```
POST /api/exec
Headers: X-API-Key: <key>
Body: {"host_id": "srv", "command": "uptime"}
→ {"status": "ok", "output": "...", "duration_ms": 230}
```

### List Hosts
```
GET /api/hosts → [{id, name, commands}]
```

### Health
```
GET /health → {"status": "ok", "version": "0.0.1"}
```

## Tech Stack

Python 3.12 · FastAPI · Paramiko · Fernet · Jinja2 + Alpine.js · YAML/JSONL · Docker

## Roadmap

- [ ] OIDC/SSO (Authentik, Keycloak)
- [ ] Multi-user RBAC
- [ ] Parameterized commands
- [ ] Scheduled/cron commands
- [ ] Webhooks
- [ ] Official Docker Hub image

## Support the Project

If MCP Gate is useful to you, consider supporting its development:

**Cryptocurrency:**

| Currency | Address |
|----------|---------|
| Bitcoin (BTC) | `bc1qzg8fgty3306upse4fhl66ltfthyyf9r5guhlle` |
| Ethereum (ETH) | `0x6C68fD15B760b3c6a1F981b5e19e25A64b07F603` |
| Ethereum Classic (ETC) | `0x061aeA68810500A44bceD5b81Cd2dD3e4Ca0d782` |
| TON | `UQBPijPtuEAPUHrVKbTQKE4We8mOvX1ZMY7XSkruuWklMLN1` |

You can also ⭐ **star this repository** — it helps with visibility and costs nothing!

## License

[AGPLv3](LICENSE) — Free for self-hosted use. If you modify and offer it as a service, you must share the source.

## Author

**Sergey** — [@sv_102](https://t.me/sv_102) · [GitHub](https://github.com/sv102)

---

*MCP Gate — because your AI assistant shouldn't have root.*