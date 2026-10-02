"""Destructive command pattern detection.

Each pattern is a tuple of (signature, compiled_regex, human_reason).
The signature is what appears in the audit trail and the block message.
"""

from __future__ import annotations

import re

# ---------- Patterns ----------

# Recursive deletion targeting anything outside the project root.
# We match the command shape here; the path check happens in core.py
# because it needs the project_root to decide.
_RM_RF = re.compile(
    r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b",
    re.IGNORECASE,
)

# Download-piped-to-shell: curl ... | bash, wget ... | sh, etc.
_DOWNLOAD_TO_SHELL = re.compile(
    r"\b(curl|wget|fetch)\b[^|]*\|\s*(bash|sh|zsh|ksh|dash)\b",
    re.IGNORECASE,
)

# Base64-decoded execution: eval $(base64 -d ...), base64 -d | bash, etc.
_BASE64_EXEC = re.compile(
    r"(base64\s+(-d|--decode))|(\beval\s+\$\()",
    re.IGNORECASE,
)

# Port scanners and brute-force tools.
_ROGUE_TOOLS = re.compile(
    r"\b(nmap|masscan|hydra|medusa|zmap)\b",
    re.IGNORECASE,
)

# Kernel-level destructive ops.
_DISK_DESTROY = re.compile(
    r"\b(mkfs(\.[a-z0-9]+)?|dd\s+if=|dd\s+of=/dev/)\b",
    re.IGNORECASE,
)

# Fork bomb shape.
_FORK_BOMB = re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:", re.IGNORECASE)

# chmod 777 on system paths.
_CHMOD_SYSTEM = re.compile(
    r"\bchmod\s+(-R\s+)?777\s+/(etc|usr|bin|sbin|var|root)\b",
    re.IGNORECASE,
)

# Overwrite of critical system files.
_OVERWRITE_SYSTEM = re.compile(
    r">\s*/(etc/passwd|etc/shadow|etc/sudoers|boot/)",
    re.IGNORECASE,
)


PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "RECURSIVE_DELETE",
        _RM_RF,
        "Recursive deletion (rm -rf) detected.",
    ),
    (
        "DOWNLOAD_TO_SHELL_PIPE",
        _DOWNLOAD_TO_SHELL,
        "Download-piped-to-shell pattern detected: unverified script would execute in the shell.",
    ),
    (
        "BASE64_EXEC",
        _BASE64_EXEC,
        "Base64-decoded or obfuscated execution detected.",
    ),
    (
        "ROGUE_TOOL",
        _ROGUE_TOOLS,
        "Port scanner or brute-force tool detected.",
    ),
    (
        "DISK_DESTROY",
        _DISK_DESTROY,
        "Disk-level destructive operation detected.",
    ),
    (
        "FORK_BOMB",
        _FORK_BOMB,
        "Fork bomb pattern detected.",
    ),
    (
        "CHMOD_SYSTEM",
        _CHMOD_SYSTEM,
        "Permission change on system path detected.",
    ),
    (
        "OVERWRITE_SYSTEM",
        _OVERWRITE_SYSTEM,
        "Overwrite of critical system file detected.",
    ),
]


def scan_command(command: str) -> tuple[str, str] | None:
    """Return (signature, reason) if the command matches a destructive pattern.

    Returns None if the command is clean at the pattern level.
    """
    for signature, pattern, reason in PATTERNS:
        if pattern.search(command):
            return signature, reason
    return None