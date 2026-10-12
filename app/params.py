# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
params.py — Parameterized command matching for MCP Gate.
Validates and substitutes {named} parameters in whitelist templates.

Changes vs previous (v0.1.4 hotfix):
  - _params_as_dict(): command_sets.yaml stores each entry's "params" as a
    LIST of {name, regex, ...} dicts, not a dict keyed by name. The previous
    code did params_spec = wl_entry.get("params", {}) and then treated the
    result as a dict (`pname not in params_spec`), which is always True for
    a list-of-dicts -> every parameterized command failed with
    "Param 'X' in template but missing from params spec", even though the
    spec was present and correct in the YAML.
  - Field name: YAML uses "regex", code was reading "pattern". Both are
    now accepted (pattern takes precedence if somehow both are present).
  - validate_and_substitute: leftover placeholder check after substitution.
    If any {name} patterns remain after all substitutions, raises ValueError.
    Prevents silent no-ops when param spec has gaps vs template.
"""

import posixpath
import re
import shlex
from typing import Optional

SHELL_DANGEROUS = re.compile(r'[;|&`$()\\\n\r\x00]')
DEFAULT_MAX_LENGTH = 2048
PARAM_PLACEHOLDER = re.compile(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}')

# SV_MCPGATE_V015: policy for every absolute-path parameter (value starting with "/").
# Lexical only — host symlinks are NOT resolved; host-side permissions stay the real boundary.
DENY_PATH_DIRS = ("/root", "/proc", "/opt/mcp-gate/data", "/var/lib/marzban", "/etc/ssl/private")
DENY_PATH_FILES = ("/etc/shadow", "/etc/gshadow")
DENY_PATH_PREFIXES = ("/etc/sudoers", "/etc/ssh/ssh_host_")
DENY_PATH_PARTS = ("/.ssh/", "/.gnupg/", "/.docker/", "/.kube/", "/.aws/", "/ssh_keys/")


def _check_path(pname: str, value: str) -> None:
    if not value.startswith("/"):
        return
    if "//" in value or ".." in value.split("/"):
        raise ValueError(f"Param '{pname}': path traversal ('..' or '//') not allowed")
    p = posixpath.normpath(value)
    if (p in DENY_PATH_FILES or p.startswith(DENY_PATH_PREFIXES)
            or any(p == d or p.startswith(d + "/") for d in DENY_PATH_DIRS)
            or any(x in p + "/" for x in DENY_PATH_PARTS)):
        raise ValueError(f"Param '{pname}': path '{p}' is protected")


def _params_as_dict(params_field) -> dict:
    """Normalize a whitelist entry's 'params' field to a dict keyed by name.

    command_sets.yaml stores params as a list:
        params:
          - name: path
            regex: ...
            max_length: 200
    Older/alternate formats may already provide a dict; support both so
    this stays a non-breaking normalization rather than a schema migration.
    """
    if isinstance(params_field, dict):
        return params_field
    if isinstance(params_field, list):
        return {p["name"]: p for p in params_field if isinstance(p, dict) and "name" in p}
    return {}


def entry_has_params(wl_entry: dict) -> bool:
    return bool(wl_entry.get("params"))


def get_param_names(cmd_template: str) -> set:
    return set(PARAM_PLACEHOLDER.findall(cmd_template))


def validate_and_substitute(wl_entry: dict, args: Optional[dict]) -> str:
    cmd_template = wl_entry["cmd"]
    params_spec = _params_as_dict(wl_entry.get("params"))
    if not params_spec:
        return cmd_template

    args = dict(args) if args else {}
    placeholders = get_param_names(cmd_template)

    for pname in placeholders:
        if pname not in params_spec:
            raise ValueError(f"Param '{pname}' in template but missing from params spec")

    for pname in placeholders:
        spec = params_spec[pname]
        if pname not in args:
            if "default" in spec:
                args[pname] = spec["default"]
            else:
                raise ValueError(f"Required param '{pname}' not provided")

    extra = set(args.keys()) - placeholders
    if extra:
        raise ValueError(f"Unknown param(s): {', '.join(sorted(extra))}")

    result = cmd_template
    for pname in sorted(placeholders):
        value = str(args[pname])
        spec = params_spec[pname]

        max_len = spec.get("max_length", DEFAULT_MAX_LENGTH)
        if len(value) > max_len:
            raise ValueError(f"Param '{pname}': length {len(value)} exceeds max {max_len}")

        if not value and "default" not in spec:
            raise ValueError(f"Param '{pname}': empty value")

        if not spec.get("allow_shell_chars", False):
            m = SHELL_DANGEROUS.search(value)
            if m:
                raise ValueError(f"Param '{pname}': forbidden shell char '{m.group()}'")

        pattern = spec.get("pattern") or spec.get("regex")
        if not pattern:
            raise ValueError(f"Param '{pname}': no validation pattern defined")

        try:
            if not re.fullmatch(pattern, value):
                raise ValueError(f"Param '{pname}': value rejected by pattern")
        except re.error as e:
            raise ValueError(f"Param '{pname}': bad regex: {e}")

        _check_path(pname, value)
        # SV_MCPGATE_V015: every value becomes exactly one shell word
        result = result.replace("{" + pname + "}", shlex.quote(value))

    # Leftover placeholder guard: detect any {name} patterns remaining after substitution.
    # This catches template/spec inconsistencies that would silently pass unresolved.
    leftover = PARAM_PLACEHOLDER.findall(result)
    if leftover:
        raise ValueError(
            f"Unresolved placeholders after substitution: {{{', '.join(leftover)}}}. "
            "Check that params spec covers all template placeholders."
        )

    return result


def describe_params(wl_entry: dict) -> list:
    params_spec = _params_as_dict(wl_entry.get("params"))
    if not params_spec:
        return []
    return [
        {
            "name": pname,
            "description": spec.get("description", ""),
            "pattern": spec.get("pattern") or spec.get("regex", ""),
            "default": spec.get("default"),
            "max_length": spec.get("max_length", DEFAULT_MAX_LENGTH),
            "required": "default" not in spec,
        }
        for pname, spec in params_spec.items()
    ]
