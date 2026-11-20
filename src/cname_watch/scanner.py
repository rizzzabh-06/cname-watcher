"""The scan pipeline: DNS analysis, provider inference, and HTTP fingerprinting."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field

import httpx

from . import __version__
from .dns_chain import MAX_DEPTH, resolve_chain
from .models import (
    FingerprintMatch,
    HttpProbe,
    ProbeAttempt,
    Resolution,
    ScanResult,
    TerminalState,
    Verdict,
)
from .probe import fetch, make_snippet
from .rules import BUILTIN_RULES, Rule, provider_for_target

_HTTP_HEADERS = {"User-Agent": f"cname-watch/{__version__} (defensive takeover check)"}


@dataclass(slots=True)
class ScanOptions:
    timeout: float = 5.0
    concurrency: int = 20
    max_depth: int = MAX_DEPTH
    probe_http: bool = True
    allow_http: bool = True
    rules: tuple[Rule, ...] = field(default_factory=lambda: BUILTIN_RULES)


def build_http_client(
    timeout: float = 5.0,
    concurrency: int = 20,
    verify_tls: bool = False,
) -> httpx.AsyncClient:
    """Build the shared async HTTP client.

    Redirects are not followed: provider error pages are served directly and
    following redirects can leave the domain that is being checked. TLS
    verification is off by default because an unclaimed custom domain often
    has no certificate for its hostname; use ``verify_tls=True`` when the
    target domains all have valid certificates.
    """

    return httpx.AsyncClient(
        follow_redirects=False,
        verify=verify_tls,
        trust_env=False,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 3.5)),
        limits=httpx.Limits(
            max_connections=max(1, concurrency),
            max_keepalive_connections=max(1, concurrency),
        ),
        headers=_HTTP_HEADERS,
    )


async def scan_domains(
    domains: Iterable[str],
    resolver: object,
    options: ScanOptions | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[ScanResult]:
    """Scan domains concurrently, preserving input order."""

    options = options or ScanOptions()
    domain_list = list(domains)
    if not domain_list:
        return []

    semaphore = asyncio.Semaphore(max(1, options.concurrency))

    async def run(domain: str) -> ScanResult:
        async with semaphore:
            try:
                return await scan_domain(domain, resolver, options, client)
            except Exception as exc:  # defensive: one bad domain must not stop the scan
                return _error_result(domain, exc)

    raw = await asyncio.gather(*(run(domain) for domain in domain_list), return_exceptions=True)
    results: list[ScanResult] = []
    for domain, item in zip(domain_list, raw, strict=True):
        if isinstance(item, BaseException):
            results.append(_error_result(domain, item))
        else:
            results.append(item)
    return results


async def scan_domain(
    domain: str,
    resolver: object,
    options: ScanOptions | None = None,
    client: httpx.AsyncClient | None = None,
) -> ScanResult:
    """Scan one subdomain."""

    options = options or ScanOptions()
    try:
        resolution = await resolve_chain(domain, resolver, options.max_depth)
    except Exception as exc:  # defensive: a resolver bug should not abort the run
        return _error_result(domain, exc)

    if resolution.state is TerminalState.ERROR:
        return ScanResult(
            domain=domain,
            verdict=Verdict.ERROR,
            reason="dns-error",
            resolution=resolution,
            detail=f"DNS lookup failed: {resolution.error or 'unknown error'}",
        )

    target = resolution.cname_target
    provider = provider_for_target(target, options.rules)

    if not resolution.chain:
        if resolution.state is TerminalState.NXDOMAIN:
            return ScanResult(
                domain=domain,
                verdict=Verdict.NOT_FOUND,
                reason="input-nxdomain",
                resolution=resolution,
                detail="Domain does not exist (NXDOMAIN)",
            )
        if resolution.state is TerminalState.NO_ADDRESS:
            return ScanResult(
                domain=domain,
                verdict=Verdict.NOT_FOUND,
                reason="input-no-address",
                resolution=resolution,
                detail="Domain has no A or AAAA records",
            )
        return ScanResult(
            domain=domain,
            verdict=Verdict.CLEAN,
            reason="no-cname",
            resolution=resolution,
            detail="No CNAME record; not a CNAME takeover candidate",
        )

    if resolution.state is TerminalState.NXDOMAIN:
        return ScanResult(
            domain=domain,
            verdict=Verdict.DANGLING,
            reason="cname-nxdomain",
            resolution=resolution,
            provider=provider,
            detail=f"CNAME target {resolution.terminal} does not resolve (NXDOMAIN)",
        )

    if resolution.state is TerminalState.NO_ADDRESS:
        return ScanResult(
            domain=domain,
            verdict=Verdict.DANGLING,
            reason="cname-no-address",
            resolution=resolution,
            provider=provider,
            detail=f"CNAME target {resolution.terminal} has no A or AAAA records",
        )

    http: HttpProbe | None = None
    if options.probe_http and provider is not None and client is not None:
        http = await _probe_provider(
            domain=domain,
            target=target,
            terminal=resolution.terminal,
            client=client,
            options=options,
        )
        if http.match is not None:
            match = http.match
            return ScanResult(
                domain=domain,
                verdict=Verdict.CLAIMABLE,
                reason="provider-fingerprint",
                resolution=resolution,
                provider=match.provider,
                http=http,
                detail=(
                    f"{match.provider} reports the resource as unclaimed "
                    f"(HTTP {match.status_code} at {match.url})"
                ),
            )

    if provider is None:
        detail = "CNAME target resolves; no fingerprint rule for this target"
    elif http is not None and http.error:
        detail = f"CNAME target resolves; HTTP probe failed ({http.error})"
    else:
        detail = f"CNAME target resolves; no {provider} takeover fingerprint matched"

    return ScanResult(
        domain=domain,
        verdict=Verdict.CLEAN,
        reason="resolved",
        resolution=resolution,
        provider=provider,
        http=http,
        detail=detail,
    )


async def _probe_provider(
    domain: str,
    target: str | None,
    terminal: str,
    client: httpx.AsyncClient,
    options: ScanOptions,
) -> HttpProbe:
    """Probe the custom domain, then the CNAME target as a fallback."""

    attempts: list[ProbeAttempt] = []
    rules = options.rules

    # The custom hostname is what an attacker would use in a takeover. HTTP is
    # tried first because the provider may not yet have a certificate for it.
    custom_schemes = ("http", "https") if options.allow_http else ("https",)
    for scheme in custom_schemes:
        attempt = await fetch(f"{scheme}://{domain}/", client)
        attempts.append(attempt)
        match = _match_attempt(target, attempt, rules)
        attempt.body = ""  # only the snippet is retained after matching
        if match is not None:
            return HttpProbe(attempts=attempts, match=match)

    if terminal and terminal != domain and target:
        # Only use the target as a fallback when the custom hostname does not
        # appear to be serving a live site. A healthy 2xx/3xx (or a protected
        # 401/403) response means the domain is already in use.
        custom_host_is_live = any(
            attempt.status_code is not None
            and (200 <= attempt.status_code < 400 or attempt.status_code in (401, 403))
            for attempt in attempts
        )
        if not custom_host_is_live:
            target_schemes = ("https", "http") if options.allow_http else ("https",)
            for scheme in target_schemes:
                attempt = await fetch(f"{scheme}://{terminal}/", client)
                attempts.append(attempt)
                match = _match_attempt(target, attempt, rules)
                attempt.body = ""  # only the snippet is retained after matching
                if match is not None:
                    return HttpProbe(attempts=attempts, match=match)

    return HttpProbe(attempts=attempts)


def _match_attempt(
    target: str | None,
    attempt: ProbeAttempt,
    rules: tuple[Rule, ...],
) -> FingerprintMatch | None:
    if attempt.error or attempt.status_code is None:
        return None

    for rule in rules:
        matched_text = rule.matches_response(
            target=target,
            status_code=attempt.status_code,
            content_type=attempt.content_type,
            body=attempt.body,
        )
        if matched_text is not None:
            return FingerprintMatch(
                rule_id=rule.id,
                provider=rule.provider,
                matched_text=matched_text,
                url=attempt.url,
                status_code=attempt.status_code,
                snippet=make_snippet(attempt.body, matched_text),
            )
    return None


def _error_result(domain: str, exc: BaseException) -> ScanResult:
    message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    resolution = Resolution(
        query=domain,
        terminal=domain,
        state=TerminalState.ERROR,
        error=message[:300],
    )
    return ScanResult(
        domain=domain,
        verdict=Verdict.ERROR,
        reason="internal-error",
        resolution=resolution,
        detail=f"Scan failed: {message[:300]}",
    )
