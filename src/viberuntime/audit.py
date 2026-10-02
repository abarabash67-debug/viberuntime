"""Append-only audit trail for every gated action.

Each entry contains a block hash, ISO-8601 timestamp, verdict, and the
signature that triggered it. No command content is stored beyond the
signature — this keeps secrets out of the audit log.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUDIT_FILE = Path(".viberuntime-audit.log")


def _hash_block(command: str, verdict: str, signature: str) -> str:
    """SHA-256 of the command, verdict, and signature.

    The hash is a fingerprint, not a reversible encoding. Two identical
    blocks produce the same hash; two different blocks never collide.
    """
    payload = f"{command}|{verdict}|{signature}".encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def write_entry(
    command: str,
    verdict: str,
    signature: str,
    reason: str = "",
    audit_file: Path | str | None = None,
) -> dict:
    """Append an audit entry to the log file and return the entry as a dict.

    Args:
        command: The full command string (stored only as a hash).
        verdict: CLEAR, BLOCKED, or HUMAN_CONFIRMATION_REQUIRED.
        signature: Threat signature, or "NONE" for CLEAR verdicts.
        reason: Human-readable reason, empty for CLEAR verdicts.
        audit_file: Optional path override; defaults to .viberuntime-audit.log.

    Returns:
        The audit entry as a dict (also written to disk).
    """
    target = Path(audit_file) if audit_file else DEFAULT_AUDIT_FILE

    entry = {
        "block_hash": _hash_block(command, verdict, signature),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "signature": signature,
        "reason": reason,
        "auditor": "viberuntime v1.0.0",
    }

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + os.linesep)

    return entry


def read_entries(audit_file: Path | str | None = None) -> list[dict]:
    """Read every entry from the audit log. Returns an empty list if missing."""
    target = Path(audit_file) if audit_file else DEFAULT_AUDIT_FILE
    if not target.exists():
        return []

    entries: list[dict] = []
    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries