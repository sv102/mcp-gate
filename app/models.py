"""models.py — Pydantic models for MCP Gate API."""
from typing import Optional
from pydantic import BaseModel


class ExecReq(BaseModel):
    host_id: str
    command: str
    source: str = "mcp"
    args: Optional[dict] = None


class HostM(BaseModel):
    id: str; name: str = ""; hostname: str; port: int = 22; user: str = "mcp-reader"
    key_path: str = "/data/ssh_keys/mcp_ed25519"; group: str = ""; enabled: bool = True
    dry_run: bool = False; approval_mode: str = "pessimistic"; approval_timeout: int = 300
    rate_limit: int = 10; exec_delay: float = 0; max_output_lines: int = 200; ssh_timeout: int = 30
    command_sets: list[str] = []; whitelist: list[dict] = []; description: str = ""
    sandbox_path: str = ""


class ModeChg(BaseModel):
    mode: str


class AgentM(BaseModel):
    id: str; name: str = ""; agent_type: str = "custom"; icon: str = ""
    enabled: bool = True; description: str = ""; rate_limit: int = 60
    allowed_hosts: list[str] = []; command_sets: list[str] = []; api_key: str = ""


class CmdSetM(BaseModel):
    id: str; name: str = ""; description: str = ""; category: str = "read"
    color: str = "#6366f1"; commands: list[dict] = []
    type: str = "allow"  # "allow" or "deny"
    enabled: bool = True


class SecretM(BaseModel):
    id: str; name: str = ""; service: str = ""; description: str = ""
    value: str = ""; hosts: list[str] = []


class TgCfg(BaseModel):
    enabled: bool = False; bot_token: str = ""; chat_id: str = ""


class SmtpCfg(BaseModel):
    enabled: bool = False; host: str = ""; port: int = 587; user: str = ""
    password: str = ""; to_email: str = ""


class PwReq(BaseModel):
    password: str


class AuditS(BaseModel):
    retention_days: int = 90


class BootReq(BaseModel):
    generate_key: bool = True
