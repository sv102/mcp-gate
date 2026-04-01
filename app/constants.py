# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""constants.py — Shared constants for MCP Gate."""

VERSION = "0.1.1"
DEV_BUILD = 0   # internal iteration counter; 0 = clean published release

def full_version():
    """Return version with dev build: '0.1.0.7' or '0.1.0' if DEV_BUILD=0."""
    return f"{VERSION}.{DEV_BUILD}" if DEV_BUILD else VERSION
