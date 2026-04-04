# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""routes_onboarding.py — Host setup script generator for MCP Gate."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import storage

router = APIRouter(tags=["onboarding"])


@router.get("/api/admin/hosts/{host_id}/setup-script")
async def host_setup_script(host_id: str):
    """Generate a bash setup script for a new host."""
    h = storage.get_host(host_id)
    if not h:
        raise HTTPException(404, detail="Host not found")

    import ssh_client as _sc
    key_name = h.get("key_path", "").replace("/data/ssh_keys/", "") or _sc.DEFAULT_KEY_NAME
    meta = _sc.get_key_metadata(key_name)
    pubkey = meta.get("public_key", "") if meta else ""
    if not pubkey:
        raise HTTPException(400, detail="SSH key pair not found. Generate keys first.")

    username = h.get("user", "mcp-reader")  # FIXED: was "username"
    hostname = h.get("hostname", "")
    port = h.get("port", 22)

    # Collect sudo commands from assigned command sets
    sudo_cmds = []
    for sid in h.get("command_sets", []):
        cs = storage.get_command_set(sid)
        if not cs or cs.get("type") == "deny":
            continue
        for cmd_entry in cs.get("commands", []):
            cmd = cmd_entry if isinstance(cmd_entry, str) else cmd_entry.get("cmd", "")
            if cmd.startswith("sudo "):
                sudo_cmds.append(cmd[5:].strip())

    # Build bash script
    L = []
    L.append("#!/bin/bash")
    L.append("# ================================================")
    L.append("# MCP Gate — Host Setup Script")
    L.append(f"# Host: {host_id} ({hostname}:{port})")
    L.append("# Run as root on the target host")
    L.append("# ================================================")
    L.append("set -e")
    L.append("")
    L.append(f'USERNAME="{username}"')
    L.append(f'PUBKEY="{pubkey}"')
    L.append("")
    L.append(f'echo "== MCP Gate Setup for {host_id} =="')
    L.append("")
    # 1. User
    L.append('echo "[1/4] Creating user $USERNAME..."')
    L.append('if id "$USERNAME" &>/dev/null; then')
    L.append('    echo "  User $USERNAME already exists"')
    L.append("else")
    L.append('    useradd -m -s /bin/bash "$USERNAME"')
    L.append('    echo "  User $USERNAME created"')
    L.append("fi")
    L.append("")
    # 2. SSH key
    L.append('echo "[2/4] Installing SSH key..."')
    L.append("mkdir -p /home/$USERNAME/.ssh")
    L.append('echo "$PUBKEY" > /home/$USERNAME/.ssh/authorized_keys')
    L.append("chmod 700 /home/$USERNAME/.ssh")
    L.append("chmod 600 /home/$USERNAME/.ssh/authorized_keys")
    L.append("chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh")
    L.append('echo "  SSH key installed"')
    L.append("")
    # 3. Sudoers
    L.append('echo "[3/4] Configuring sudoers..."')
    if sudo_cmds:
        L.append("mkdir -p /etc/sudoers.d")
        L.append("cat > /etc/sudoers.d/mcp-gate-$USERNAME << 'SUDOERS'")
        seen = set()
        for cmd in sudo_cmds:
            if cmd not in seen:
                L.append(f"{username} ALL=(ALL) NOPASSWD: {cmd}")
                seen.add(cmd)
        L.append("SUDOERS")
        L.append("chmod 440 /etc/sudoers.d/mcp-gate-$USERNAME")
        L.append('command -v visudo &>/dev/null && visudo -c -f /etc/sudoers.d/mcp-gate-$USERNAME')
        L.append(f'echo "  Sudoers configured ({len(seen)} rules)"')
    else:
        L.append('echo "  No sudo commands needed"')
    L.append("")
    # 4. Verify
    L.append('echo "[4/4] Verification..."')
    L.append('id "$USERNAME"')
    L.append('echo ""')
    L.append('echo "================================================"')
    L.append('echo "Done! Click SSH Test in MCP Gate WebUI."')
    L.append('echo "If it fails check: firewall, SSH pubkey auth, network."')
    L.append('echo "================================================"')

    script = "\n".join(L) + "\n"

    return JSONResponse({
        "script": script,
        "host_id": host_id,
        "username": username,
        "hostname": hostname,
        "port": port,
        "sudo_commands": len(sudo_cmds),
    })
