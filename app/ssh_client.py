"""
ssh_client.py — SSH client for mcp-gate.
Managed known_hosts: saves fingerprint on first connect, verifies after.
"""

import os
import subprocess
import time
import logging
from pathlib import Path
from typing import Optional

import paramiko

from storage import SSH_KEYS_DIR

log = logging.getLogger("mcp-gate.ssh")
SSH_TIMEOUT = 30
MAX_OUTPUT_BYTES = 65536
KNOWN_HOSTS_FILE = SSH_KEYS_DIR / "known_hosts"


def generate_keypair(key_name: str = "mcp_ed25519") -> tuple[str, str]:
    priv_path = SSH_KEYS_DIR / key_name
    pub_path = SSH_KEYS_DIR / f"{key_name}.pub"

    if priv_path.exists():
        pub_str = pub_path.read_text().strip() if pub_path.exists() else ""
        if not pub_str:
            key = paramiko.Ed25519Key.from_private_key_file(str(priv_path))
            pub_str = f"ssh-ed25519 {key.get_base64()} mcp-gate"
        return str(priv_path), pub_str

    subprocess.run([
        "ssh-keygen", "-t", "ed25519", "-f", str(priv_path),
        "-N", "", "-C", "mcp-gate"
    ], check=True, capture_output=True)
    os.chmod(priv_path, 0o600)

    pub_str = pub_path.read_text().strip()
    return str(priv_path), pub_str


def get_public_key(key_name: str = "mcp_ed25519") -> Optional[str]:
    pub_path = SSH_KEYS_DIR / f"{key_name}.pub"
    if pub_path.exists():
        return pub_path.read_text().strip()
    return None


def test_connection(host: dict) -> dict:
    try:
        client = _connect(host)
        client.close()
        return {"ok": True, "message": "Connection successful"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def execute(host: dict, command: str) -> dict:
    t0 = time.time()
    try:
        client = _connect(host)
        _, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)

        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
        err = stderr.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")

        truncated = False
        try:
            extra = stdout.read(1)
            if extra:
                truncated = True
                out += "\n... [truncated at 64KB]"
        except Exception:
            pass

        client.close()
        duration_ms = int((time.time() - t0) * 1000)

        return {
            "status": "ok",
            "output": out,
            "stderr": err,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "truncated": truncated,
        }
    except paramiko.AuthenticationException:
        return {"status": "error", "error": "SSH auth failed", "duration_ms": int((time.time() - t0) * 1000)}
    except paramiko.SSHException as e:
        return {"status": "error", "error": f"SSH: {e}", "duration_ms": int((time.time() - t0) * 1000)}
    except TimeoutError:
        return {"status": "error", "error": f"Timeout ({SSH_TIMEOUT}s)", "duration_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"status": "error", "error": str(e), "duration_ms": int((time.time() - t0) * 1000)}


class _ManagedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Save host key on first connect, verify on subsequent connects."""

    def missing_host_key(self, client, hostname, key):
        host_keys = client.get_host_keys()
        existing = host_keys.lookup(hostname)
        if existing:
            # Key changed — potential MITM
            log.warning(f"HOST KEY CHANGED for {hostname}! Rejecting.")
            raise paramiko.SSHException(
                f"Host key for {hostname} has changed. "
                f"Remove old key from {KNOWN_HOSTS_FILE} if this is expected."
            )
        # First connection — save key
        log.info(f"Saving new host key for {hostname}")
        host_keys.add(hostname, key.get_name(), key)
        try:
            KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            host_keys.save(str(KNOWN_HOSTS_FILE))
        except Exception as e:
            log.warning(f"Failed to save known_hosts: {e}")


def _connect(host: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()

    # Load known hosts if exists
    if KNOWN_HOSTS_FILE.exists():
        try:
            client.load_host_keys(str(KNOWN_HOSTS_FILE))
        except Exception as e:
            log.warning(f"Failed to load known_hosts: {e}")

    client.set_missing_host_key_policy(_ManagedHostKeyPolicy())

    key_path = host.get("key_path", str(SSH_KEYS_DIR / "mcp_ed25519"))
    pkey = paramiko.Ed25519Key.from_private_key_file(key_path)

    client.connect(
        hostname=host["hostname"],
        port=host.get("port", 22),
        username=host.get("user", "mcp-reader"),
        pkey=pkey,
        timeout=SSH_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client
