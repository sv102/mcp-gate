# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
params.py — Parameterized command matching for MCP Gate.
Validates and substitutes {named} parameters in whitelist templates.

Changes vs previous:
  - validate_and_substitute: leftover placeholder check after substitution.
    If any {name} patterns remain after all substitutions, raises ValueError.
    Prevents silent no-ops when param spec has gaps vs template.
"""

import re
from typing import Optional

SHELL_DANGEROUS = re.compile(r'[;|&`$()\\]')
DEFAULT_MAX_LENGTH = 2048
PARAM_PLACEHOLDER = re.compile(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}')


def entry_has_params(wl_entry: dict) -> bool:
    return bool(wl_entry.get("params"))


def get_param_names(cmd_template: str) -> set:
    return set(PARAM_PLACEHOLDER.findall(cmd_template))


def validate_and_substitute(wl_entry: dict, args: Optional[dict]) -> str:
    cmd_template = wl_entry["cmd"]
    params_spec = wl_entry.get("params", {})
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

        pattern = spec.get("pattern")
        if not pattern:
            raise ValueError(f"Param '{pname}': no validation pattern defined")

        try:
            if not re.fullmatch(pattern, value):
                raise ValueError(f"Param '{pname}': value rejected by pattern")
        except re.error as e:
            raise ValueError(f"Param '{pname}': bad regex: {e}")

        result = result.replace("{" + pname + "}", value)

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
    params_spec = wl_entry.get("params", {})
    if not params_spec:
        return []
    return [
        {
            "name": pname,
            "description": spec.get("description", ""),
            "pattern": spec.get("pattern", ""),
            "default": spec.get("default"),
            "max_length": spec.get("max_length", DEFAULT_MAX_LENGTH),
            "required": "default" not in spec,
        }
        for pname, spec in params_spec.items()
    ]
