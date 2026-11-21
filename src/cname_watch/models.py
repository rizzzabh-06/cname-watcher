"""Core data types shared by the scanner and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Outcome of scanning one subdomain."""

    DANGLING = "dangling"
    CLAIMABLE = "claimable"
    CLEAN = "clean"
    NOT_FOUND = "not-found"
    ERROR = "error"

    @property
    def is_candidate(self) -> bool:
        return self in (Verdict.DANGLING, Verdict.CLAIMABLE)

    @property
    def label(self) -> str:
        return {
            Verdict.DANGLING: "DANGLING",
            Verdict.CLAIMABLE: "CLAIMABLE",
            Verdict.CLEAN: "CLEAN",
            Verdict.NOT_FOUND: "NOT FOUND",
            Verdict.ERROR: "ERROR",
        }[self]


class TerminalState(str, Enum):
    """What happened at the end of a CNAME chain (or at the input name)."""

    RESOLVED = "resolved"
    NXDOMAIN = "nxdomain"
    NO_ADDRESS = "no-address"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CnameLink:
    owner: str
    target: str

    def to_dict(self) -> dict[str, str]:
        return {"owner": self.owner, "target": self.target}


@dataclass(slots=True)
class Resolution:
    """The CNAME chain and terminal DNS state for one input name."""

    query: str
    chain: list[CnameLink] = field(default_factory=list)
    terminal: str = ""
    state: TerminalState = TerminalState.NO_ADDRESS
    addresses: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def cname_target(self) -> str | None:
        """The final CNAME target, or ``None`` when the input has no CNAME."""

        return self.chain[-1].target if self.chain else None

    @property
    def has_cname(self) -> bool:
        return bool(self.chain)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "chain": [link.to_dict() for link in self.chain],
            "terminal": self.terminal,
            "state": self.state.value,
            "addresses": self.addresses,
            "error": self.error,
        }


@dataclass(slots=True)
class ProbeAttempt:
    """A single HTTP(S) request made while fingerprinting."""

    url: str
    status_code: int | None = None
    content_type: str | None = None
    body: str = ""
    error: str | None = None
    body_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "body_bytes": self.body_bytes,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class FingerprintMatch:
    """A provider fingerprint that matched an HTTP response."""

    rule_id: str
    provider: str
    matched_text: str
    url: str
    status_code: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "provider": self.provider,
            "matched_text": self.matched_text,
            "url": self.url,
            "status_code": self.status_code,
            "snippet": self.snippet,
        }


@dataclass(slots=True)
class HttpProbe:
    """All HTTP evidence gathered for one subdomain."""

    attempts: list[ProbeAttempt] = field(default_factory=list)
    match: FingerprintMatch | None = None

    @property
    def error(self) -> str | None:
        if not self.attempts:
            return None
        if any(attempt.status_code is not None for attempt in self.attempts):
            return None
        return self.attempts[0].error

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "match": self.match.to_dict() if self.match else None,
        }


@dataclass(slots=True)
class ScanResult:
    """The result for one input subdomain."""

    domain: str
    verdict: Verdict
    reason: str
    resolution: Resolution
    provider: str | None = None
    http: HttpProbe | None = None
    detail: str = ""

    @property
    def is_candidate(self) -> bool:
        return self.verdict.is_candidate

    @property
    def evidence(self) -> str:
        """A compact one-line explanation suitable for a table or CSV."""

        if self.http and self.http.match:
            match = self.http.match
            return (
                f"{match.provider}: {match.matched_text} at {match.url} (HTTP {match.status_code})"
            )
        return self.detail

    @property
    def http_status(self) -> int | None:
        if self.http and self.http.match:
            return self.http.match.status_code
        if self.http:
            for attempt in self.http.attempts:
                if attempt.status_code is not None:
                    return attempt.status_code
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "verdict": self.verdict.value,
            "candidate": self.is_candidate,
            "reason": self.reason,
            "provider": self.provider,
            "resolution": self.resolution.to_dict(),
            "http": self.http.to_dict() if self.http else None,
            "detail": self.detail,
        }
