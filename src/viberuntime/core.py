"""Core: gate every subprocess.run call before execution.

Public entry point: `run()`. It mirrors the subprocess.run signature
where it matters (command, shell, timeout, check) and raises
VibeRuntimeBlocked instead of executing a dangerous command.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Sequence

from .audit import write_entry
from .blocklist import scan_command
from .exceptions import VibeRuntimeBlocked, VibeRuntimeConfirmationRequired
from .network import check_hosts

DEFAULT_PROJECT_ROOT = Path.cwd()
DEFAULT_TIMEOUT = 60.0


def _normalize_command(command: str | Sequence[str]) -> str:
    """Return the command as a single string for pattern matching.

    If command is a list, join with spaces. This is intentional: we do
    not try to parse shell quoting; we match against the raw string.
    """
    if isinstance(command, str):
        return command
    return " ".join(str(part) for part in command)


def _check_destructive_path(command: str, project_root: Path) -> tuple[str, str] | None:
    """Reject rm -rf targeting paths outside the project root.

    Only triggers if the command matched the rm -rf pattern. Otherwise
    returns None.
    """
    from .blocklist import _RM_RF  # local import to avoid exposing the regex

    if not _RM_RF.search(command):
        return None

    # Look for absolute paths and ~ in the command.
    risky_targets = ["/", "~", "/etc", "/usr", "/var", "/root", "/boot", "/bin", "/sbin", "/opt"]
    for target in risky_targets:
        # Match target as a standalone token (space-separated).
        if f" {target} " in f" {command} ":
            return (
                "RECURSIVE_DELETE_OUTSIDE_ROOT",
                f"Recursive deletion targeting '{target}' is outside the project root.",
            )

    return None


def run(
    command: str | Sequence[str],
    *,
    allowed_hosts: set[str] | frozenset[str] | None = None,
    project_root: Path | str | None = None,
    audit_file: Path | str | None = None,
    shell: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Gated replacement for subprocess.run.

    Runs every safety check before delegating to subprocess.run.

    Args:
        command: Command string or argument list.
        allowed_hosts: Optional network allowlist. Defaults to DEFAULT_ALLOWLIST.
        project_root: Optional project root path. Defaults to cwd.
        audit_file: Optional audit file path.
        shell: Forwarded to subprocess.run. Prefer False.
        timeout: Forwarded to subprocess.run.
        check: Forwarded to subprocess.run.
        **kwargs: Any additional subprocess.run keyword arguments.

    Returns:
        subprocess.CompletedProcess from the executed command.

    Raises:
        VibeRuntimeBlocked: If the command matches a destructive pattern
            or targets a host outside the allowlist.
        VibeRuntimeConfirmationRequired: If the command needs manual sign-off.
    """
    cmd_str = _normalize_command(command)
    root = Path(project_root) if project_root else DEFAULT_PROJECT_ROOT

    # --- Check 1: destructive pattern blocklist ---
    match = scan_command(cmd_str)
    if match:
        signature, reason = match

        # Special-case: rm -rf is only blocked if it targets outside root.
        if signature == "RECURSIVE_DELETE":
            path_issue = _check_destructive_path(cmd_str, root)
            if path_issue is None:
                # rm -rf inside the project root is allowed.
                pass
            else:
                signature, reason = path_issue
                write_entry(cmd_str, "BLOCKED", signature, reason, audit_file)
                raise VibeRuntimeBlocked(reason, signature, cmd_str)
        else:
            write_entry(cmd_str, "BLOCKED", signature, reason, audit_file)
            raise VibeRuntimeBlocked(reason, signature, cmd_str)

    # --- Check 2: network allowlist ---
    host_issue = check_hosts(cmd_str, allowed_hosts)
    if host_issue is not None:
        host, reason = host_issue
        signature = "NETWORK_HOST_NOT_ALLOWED"
        write_entry(cmd_str, "BLOCKED", signature, reason, audit_file)
        raise VibeRuntimeBlocked(reason, signature, cmd_str)

    # --- All checks passed — execute ---
    write_entry(cmd_str, "CLEAR", "NONE", "", audit_file)

    return subprocess.run(
        command,
        shell=shell,
        timeout=timeout,
        check=check,
        **kwargs,
    )