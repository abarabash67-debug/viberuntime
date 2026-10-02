"""Custom exceptions for viberuntime."""

from __future__ import annotations


class VibeRuntimeError(Exception):
    """Base exception for all viberuntime errors."""


class VibeRuntimeBlocked(VibeRuntimeError):
    """Raised when a command is blocked by the guardrail.

    Attributes:
        reason: Human-readable reason for the block.
        signature: Threat signature (e.g. DOWNLOAD_TO_SHELL_PIPE).
        command: The command that was blocked.
    """

    def __init__(self, reason: str, signature: str, command: str = "") -> None:
        self.reason = reason
        self.signature = signature
        self.command = command
        super().__init__(f"[{signature}] {reason}")


class VibeRuntimeConfirmationRequired(VibeRuntimeError):
    """Raised when a command needs human confirmation before execution.

    Attributes:
        reason: Human-readable reason for the confirmation request.
        signature: Threat signature.
        command: The command awaiting confirmation.
    """

    def __init__(self, reason: str, signature: str, command: str = "") -> None:
        self.reason = reason
        self.signature = signature
        self.command = command
        super().__init__(f"[{signature}] {reason}")