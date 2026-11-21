"""Domain-list parsing and normalisation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")


def normalize_domain(raw: str) -> str | None:
    """Normalise one domain from a CLI argument or list file.

    Accepts bare hostnames, URLs, wildcard prefixes, trailing dots, and
    ``host:port`` forms. Returns a lower-case IDNA (ASCII) hostname, or
    ``None`` when the input is not a usable DNS name.
    """

    value = raw.strip().lstrip("\ufeff")
    if not value or value.startswith("#"):
        return None
    value = value.split("#", 1)[0].strip()
    if not value:
        return None

    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
    except ValueError:
        return None

    host = parsed.hostname
    if not host:
        return None
    host = host.strip().rstrip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    if not host or " " in host or "/" in host or "\\" in host:
        return None

    try:
        if ipaddress.ip_address(host):
            return None
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not 1 <= len(label) <= 63 or not _LABEL.fullmatch(label):
            return None
    return ascii_host


def read_domains(lines: Iterable[str]) -> tuple[list[str], list[tuple[int, str, str]]]:
    """Parse lines of domains.

    Returns ``(domains, errors)`` where errors are ``(line_number, raw_line,
    reason)`` tuples. Blank lines and full-line comments are ignored.
    """

    domains: list[str] = []
    errors: list[tuple[int, str, str]] = []
    seen: set[str] = set()

    for line_number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        domain = normalize_domain(stripped)
        if domain is None:
            errors.append((line_number, stripped, "not a valid domain name"))
            continue
        if domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    return domains, errors
