# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""Emergency admin actions (shell access to the container = root on the gate anyway):
  docker exec -it mcp-gate python cli.py totp-reset       disable 2FA, end all sessions
  docker exec -it mcp-gate python cli.py password         set a new admin password, end all sessions
  docker exec -it mcp-gate python cli.py revoke-sessions  end all sessions and remembered devices"""
import getpass
import sys

import auth
import events
import storage


def _log(cmd: str):
    storage.append_audit({"command": f"cli: {cmd}", "source": "admin", "status": "ok", "host_id": "-"})
    events.emit("security", f"CLI {cmd}", "")


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "totp-reset":
        auth.totp_disable()
        auth.bump_epoch()
        _log(cmd)
        print("2FA disabled, all sessions ended. Enable it again in Settings → Security.")
    elif cmd == "password":
        p = getpass.getpass("New admin password: ")
        if len(p) < 8 or p != getpass.getpass("Repeat: "):
            print("min 8 characters, both entries equal")
            return 1
        auth.set_password(p)
        _log(cmd)
        print("Password changed, all sessions ended.")
    elif cmd == "revoke-sessions":
        auth.bump_epoch()
        _log(cmd)
        print("All sessions and remembered devices revoked.")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
