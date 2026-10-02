"""Tests for the destructive pattern blocklist."""

from __future__ import annotations

import pytest

from viberuntime.blocklist import scan_command


# --- Blocked patterns ---

@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "pwd",
        "git status",
        "python -m pytest",
        "pip install requests",
        "npm install",
        "cat README.md",
        "echo hello",
    ],
)
def test_clean_commands(command: str) -> None:
    result = scan_command(command)
    assert result is None, f"unexpected block for: {command}"


# --- rm -rf is a blocklist-level match; path filtering happens in core.py ---

@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ./build",
        "rm -rf node_modules",
    ],
)
def test_rm_rf_matches_at_blocklist_level(command: str) -> None:
    """scan_command flags all rm -rf as RECURSIVE_DELETE.

    The distinction between 'inside project root' (allow) and 'outside'
    (block) is made in core.py, not here.
    """
    result = scan_command(command)
    assert result is not None
    signature, _reason = result
    assert signature == "RECURSIVE_DELETE"