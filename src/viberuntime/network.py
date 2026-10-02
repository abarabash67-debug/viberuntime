"""Network allowlist enforcement.

Every outbound host referenced in a command must appear in the allowlist.
Anything else is blocked by default (deny-all).
"""

from __future__ import annotations

import re

# Host extraction: matches URLs and bare hostnames in common command forms.
_URL_HOST = re.compile(r"https?://([^/\s:]+)", re.IGNORECASE)
_CURL_HOST = re.compile(r"\b(?:curl|wget|fetch)\s+(?:-[a-zA-Z]+\s+)*https?://([^/\s:]+)", re.IGNORECASE)


DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "github.com",
        "pypi.org",
        "files.pythonhosted.org",
        "npmjs.com",
        "registry.npmjs.org",
    }
)


def extract_hosts(command: str) -> set[str]:
    """Extract every host referenced in a command string.

    Returns a set of lowercase hostnames (without scheme, port, or path).
    """
    hosts: set[str] = set()

    for match in _URL_HOST.finditer(command):
        hosts.add(match.group(1).lower())

    for match in _CURL_HOST.finditer(command):
        hosts.add(match.group(1).lower())

    return hosts


def check_hosts(
    command: str,
    allowlist: frozenset[str] | set[str] | None = None,
) -> tuple[str, str] | None:
    """Return (host, reason) if a host is not on the allowlist.

    Returns None if all hosts are allowed, or if there are no hosts.
    """
    allowed = frozenset(allowlist) if allowlist else DEFAULT_ALLOWLIST
    hosts = extract_hosts(command)

    for host in hosts:
        if host not in allowed:
            return host, f"Host '{host}' is not on the network allowlist."

    return None