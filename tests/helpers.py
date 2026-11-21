"""Shared test helpers: fake DNS answers and result factories."""

from __future__ import annotations

from typing import Any

import dns.resolver

from cname_watch.models import (
    CnameLink,
    FingerprintMatch,
    HttpProbe,
    Resolution,
    ScanResult,
    TerminalState,
    Verdict,
)


class FakeCname:
    def __init__(self, target: str) -> None:
        self.target = target


class FakeAddress:
    def __init__(self, address: str) -> None:
        self.address = address

    def __str__(self) -> str:
        return self.address


class FakeAnswer:
    def __init__(self, records: list[Any] | None = None) -> None:
        self._records = records or []
        self.rrset = object() if self._records else None

    def __iter__(self):
        return iter(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def __getitem__(self, index: int):
        return self._records[index]


def cname(target: str) -> FakeAnswer:
    return FakeAnswer([FakeCname(target)])


def addresses(*values: str) -> FakeAnswer:
    return FakeAnswer([FakeAddress(value) for value in values])


def nxdomain() -> dns.resolver.NXDOMAIN:
    return dns.resolver.NXDOMAIN()


class StubResolver:
    """Minimal async resolver keyed by ``(name, record_type)``."""

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, name: str, rdtype: str, raise_on_no_answer: bool = False):
        self.calls.append((name, rdtype))
        value = self.responses.get((name, rdtype))
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return FakeAnswer([])
        return value


def make_result(
    domain: str = "blog.example.com",
    verdict: Verdict = Verdict.DANGLING,
    *,
    provider: str | None = "GitHub Pages",
    target: str | None = "old-blog.github.io",
    detail: str = "CNAME target does not resolve (NXDOMAIN)",
    http: HttpProbe | None = None,
    state: TerminalState | None = None,
) -> ScanResult:
    has_cname = target is not None and verdict is not Verdict.NOT_FOUND
    chain = [CnameLink(domain, target)] if has_cname and target else []
    if state is None:
        state = {
            Verdict.DANGLING: TerminalState.NXDOMAIN,
            Verdict.CLAIMABLE: TerminalState.RESOLVED,
            Verdict.CLEAN: TerminalState.RESOLVED,
            Verdict.NOT_FOUND: TerminalState.NXDOMAIN,
            Verdict.ERROR: TerminalState.ERROR,
        }[verdict]
    resolution = Resolution(
        query=domain,
        chain=chain,
        terminal=target or domain,
        state=state,
        addresses=["192.0.2.1"] if state is TerminalState.RESOLVED else [],
        error="lookup failed" if state is TerminalState.ERROR else None,
    )
    return ScanResult(
        domain=domain,
        verdict=verdict,
        reason="test",
        resolution=resolution,
        provider=provider if has_cname else None,
        http=http,
        detail=detail,
    )


def make_match(
    *,
    provider: str = "GitHub Pages",
    rule_id: str = "github-pages",
    url: str = "http://blog.example.com/",
    status_code: int = 404,
    matched_text: str = "There isn't a GitHub Pages site here",
    snippet: str = "There isn't a GitHub Pages site here.",
) -> FingerprintMatch:
    return FingerprintMatch(
        rule_id=rule_id,
        provider=provider,
        matched_text=matched_text,
        url=url,
        status_code=status_code,
        snippet=snippet,
    )
