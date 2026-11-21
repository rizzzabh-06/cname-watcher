#!/usr/bin/env python3
"""Exercise the scanner against real providers without owning a domain.

Only DNS is faked: each demo hostname is given a CNAME pointing at a real,
genuinely unclaimed provider endpoint. The HTTP fingerprinting then runs for
real against GitHub Pages, AWS S3, and Vercel, plus one clean site and one
classic dangling CNAME.

Run from a checkout after installing the package:

    python scripts/demo.py

The demo exits 0 when every verdict matches the expectation below, and 1
otherwise. It never claims or modifies anything at the provider.
"""

from __future__ import annotations

import asyncio
import sys

import dns.resolver

from cname_watch.models import Verdict
from cname_watch.report import render_table, summary_line
from cname_watch.scanner import ScanOptions, build_http_client, scan_domain


class FakeCname:
    def __init__(self, target: str) -> None:
        self.target = target


class FakeAddress:
    def __init__(self, address: str) -> None:
        self.address = address

    def __str__(self) -> str:
        return self.address


class FakeAnswer:
    def __init__(self, records: list[object] | None = None) -> None:
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


class StubResolver:
    """Answer only the demo names; anything else looks like an empty answer."""

    def __init__(self, responses: dict[tuple[str, str], object]) -> None:
        self.responses = responses

    async def resolve(self, name: str, rdtype: str, raise_on_no_answer: bool = False):
        value = self.responses.get((name, rdtype))
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return FakeAnswer()
        return value


# domain, CNAME target, expected verdict, expected provider
DEMOS: tuple[tuple[str, str, Verdict, str | None], ...] = (
    (
        "demo-github.example.com",
        "nonexistent-zzz-abc.github.io",
        Verdict.CLAIMABLE,
        "GitHub Pages",
    ),
    (
        "demo-s3.example.com",
        "nonexistent-zzz-abc.s3.us-east-1.amazonaws.com",
        Verdict.CLAIMABLE,
        "Amazon S3",
    ),
    (
        "demo-vercel.example.com",
        "nonexistent-zzz-abc.vercel.app",
        Verdict.CLAIMABLE,
        "Vercel",
    ),
    (
        "demo-live.example.com",
        "rust-lang.github.io",
        Verdict.CLEAN,
        "GitHub Pages",
    ),
    (
        "demo-dangling.example.com",
        "cname-watch-does-not-exist.example",
        Verdict.DANGLING,
        None,
    ),
)


def resolver_for(domain: str, target: str) -> StubResolver:
    responses: dict[tuple[str, str], object] = {
        (domain, "CNAME"): cname(target + "."),
        (target, "CNAME"): None,
        (target, "AAAA"): None,
    }
    if target.endswith(".example"):
        responses[(target, "A")] = dns.resolver.NXDOMAIN()
    else:
        responses[(target, "A")] = addresses("192.0.2.1")
    return StubResolver(responses)


async def main() -> int:
    client = build_http_client(timeout=8.0, concurrency=4)
    results = []
    try:
        for domain, target, _expected, _provider in DEMOS:
            print(f"Scanning {domain} -> {target} ...", file=sys.stderr)
            result = await scan_domain(
                domain,
                resolver_for(domain, target),
                ScanOptions(timeout=8.0),
                client,
            )
            results.append(result)
    finally:
        await client.aclose()

    print(render_table(results, show_all=True, include_summary=False))
    print()
    print(summary_line(results))
    print()

    failures: list[str] = []
    for result, (_, _target, expected, provider) in zip(results, DEMOS, strict=True):
        if result.verdict is not expected:
            failures.append(
                f"{result.domain}: expected {expected.label}, got {result.verdict.label}"
            )
        elif provider is not None and result.provider != provider:
            failures.append(
                f"{result.domain}: expected provider {provider!r}, got {result.provider!r}"
            )

    if failures:
        print("Demo FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("Demo passed: all expected verdicts matched.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
