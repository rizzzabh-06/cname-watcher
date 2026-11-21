from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from cname_watch.models import TerminalState, Verdict
from cname_watch.scanner import ScanOptions, scan_domain, scan_domains
from tests.helpers import StubResolver, addresses, cname, nxdomain


def resolved_resolver(domain: str, target: str) -> StubResolver:
    return StubResolver(
        {
            (domain, "CNAME"): cname(target + "."),
            (target, "CNAME"): None,
            (target, "A"): addresses("192.0.2.50"),
            (target, "AAAA"): None,
        }
    )


def dangling_resolver(domain: str, target: str) -> StubResolver:
    return StubResolver(
        {
            (domain, "CNAME"): cname(target + "."),
            (target, "CNAME"): nxdomain(),
        }
    )


def client_for(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )


@pytest.mark.parametrize(
    ("domain", "target", "body", "content_type", "provider"),
    [
        (
            "blog.example.com",
            "old-blog.github.io",
            "<p>There isn't a GitHub Pages site here.</p>",
            "text/html",
            "GitHub Pages",
        ),
        (
            "assets.example.com",
            "acme-bucket.s3.amazonaws.com",
            "<Error><Code>NoSuchBucket</Code></Error>",
            "application/xml",
            "Amazon S3",
        ),
        (
            "preview.example.com",
            "demo.vercel.app",
            "The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND",
            "text/plain",
            "Vercel",
        ),
        (
            "app.example.com",
            "demo.azurewebsites.net",
            "<h1>404 Web Site not found.</h1>",
            "text/html",
            "Azure App Service",
        ),
    ],
)
async def test_claimable_provider_fingerprints(domain, target, body, content_type, provider):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(404, headers={"content-type": content_type}, text=body)

    async with client_for(handler) as client:
        result = await scan_domain(
            domain,
            resolved_resolver(domain, target),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.CLAIMABLE
    assert result.reason == "provider-fingerprint"
    assert result.provider == provider
    assert result.is_candidate
    assert result.http is not None
    assert result.http.match is not None
    assert result.http.match.provider == provider
    assert requests[0].url.host == domain
    assert result.http.attempts[0].body == ""
    assert result.http.attempts[0].body_bytes > 0


async def test_dangling_cname_target():
    result = await scan_domain(
        "blog.example.com",
        dangling_resolver("blog.example.com", "old-blog.github.io"),
        ScanOptions(),
    )

    assert result.verdict is Verdict.DANGLING
    assert result.reason == "cname-nxdomain"
    assert result.provider == "GitHub Pages"
    assert result.resolution.state is TerminalState.NXDOMAIN
    assert "does not resolve" in result.detail


async def test_cname_target_without_addresses_is_dangling():
    resolver = StubResolver(
        {
            ("www.example.com", "CNAME"): cname("empty.github.io."),
            ("empty.github.io", "CNAME"): None,
            ("empty.github.io", "A"): None,
            ("empty.github.io", "AAAA"): None,
        }
    )

    result = await scan_domain("www.example.com", resolver, ScanOptions())

    assert result.verdict is Verdict.DANGLING
    assert result.reason == "cname-no-address"


async def test_input_nxdomain_is_not_a_candidate():
    resolver = StubResolver({("missing.example.com", "CNAME"): nxdomain()})

    result = await scan_domain("missing.example.com", resolver, ScanOptions())

    assert result.verdict is Verdict.NOT_FOUND
    assert result.reason == "input-nxdomain"
    assert not result.is_candidate


async def test_no_cname_is_clean():
    resolver = StubResolver(
        {
            ("www.example.com", "CNAME"): None,
            ("www.example.com", "A"): addresses("192.0.2.60"),
        }
    )

    result = await scan_domain("www.example.com", resolver, ScanOptions())

    assert result.verdict is Verdict.CLEAN
    assert result.reason == "no-cname"


async def test_resolved_provider_with_no_fingerprint_is_clean():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"}, text="hello")

    async with client_for(handler) as client:
        result = await scan_domain(
            "blog.example.com",
            resolved_resolver("blog.example.com", "old-blog.github.io"),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.CLEAN
    assert result.http is not None
    assert result.http.match is None
    assert len(requests) == 2
    assert "no GitHub Pages takeover fingerprint" in result.detail


async def test_target_probe_is_used_as_fallback():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "old-blog.github.io":
            return httpx.Response(
                404,
                headers={"content-type": "text/html"},
                text="There isn't a GitHub Pages site here.",
            )
        raise httpx.ConnectError("custom host is unreachable", request=request)

    async with client_for(handler) as client:
        result = await scan_domain(
            "blog.example.com",
            resolved_resolver("blog.example.com", "old-blog.github.io"),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.CLAIMABLE
    assert result.http is not None
    assert result.http.match is not None
    assert result.http.match.url.startswith("https://old-blog.github.io/")
    assert len(result.http.attempts) == 3


async def test_target_fingerprint_does_not_override_a_custom_host_response():
    """A target-side 404 must not make an existing Host-routed bucket look claimable."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "old-bucket.s3.amazonaws.com":
            return httpx.Response(
                404,
                headers={"content-type": "application/xml"},
                text="<Error><Code>NoSuchBucket</Code></Error>",
            )
        return httpx.Response(
            404,
            headers={"content-type": "application/xml"},
            text="<Error><Code>NoSuchKey</Code></Error>",
        )

    async with client_for(handler) as client:
        result = await scan_domain(
            "assets.example.com",
            resolved_resolver("assets.example.com", "old-bucket.s3.amazonaws.com"),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.CLEAN
    assert result.provider == "Amazon S3"
    assert result.http is not None
    assert result.http.match is None
    assert len(result.http.attempts) == 2


async def test_unknown_provider_target_skips_http_probing():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, text="hello")

    async with client_for(handler) as client:
        result = await scan_domain(
            "app.example.com",
            resolved_resolver("app.example.com", "service.example.net"),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.CLEAN
    assert result.provider is None
    assert result.http is None
    assert requests == []


async def test_probe_can_be_disabled():
    result = await scan_domain(
        "blog.example.com",
        resolved_resolver("blog.example.com", "old-blog.github.io"),
        ScanOptions(probe_http=False),
    )

    assert result.verdict is Verdict.CLEAN
    assert result.http is None
    assert "fingerprinting disabled" in result.detail


async def test_https_only_skips_plain_http():
    schemes: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        schemes.append(request.url.scheme)
        return httpx.Response(
            404,
            headers={"content-type": "text/html"},
            text="There isn't a GitHub Pages site here.",
        )

    async with client_for(handler) as client:
        result = await scan_domain(
            "blog.example.com",
            resolved_resolver("blog.example.com", "old-blog.github.io"),
            ScanOptions(allow_http=False),
            client,
        )

    assert result.verdict is Verdict.CLAIMABLE
    assert schemes == ["https"]


async def test_http_failures_are_reported_as_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async with client_for(handler) as client:
        result = await scan_domain(
            "blog.example.com",
            resolved_resolver("blog.example.com", "old-blog.github.io"),
            ScanOptions(),
            client,
        )

    assert result.verdict is Verdict.ERROR
    assert result.reason == "http-error"
    assert not result.is_candidate
    assert result.http is not None
    assert result.http.error is not None
    assert "HTTP probe failed" in result.detail
    assert len(result.http.attempts) == 4


async def test_dns_error_is_reported():
    resolver = StubResolver({("www.example.com", "CNAME"): RuntimeError("boom")})

    result = await scan_domain("www.example.com", resolver, ScanOptions())

    assert result.verdict is Verdict.ERROR
    assert result.reason == "internal-error"
    assert "boom" in result.detail


async def test_scan_domains_preserves_order_and_isolates_errors():
    resolver = StubResolver(
        {
            ("a.example.com", "CNAME"): None,
            ("a.example.com", "A"): addresses("192.0.2.1"),
            ("b.example.com", "CNAME"): None,
            ("b.example.com", "A"): addresses("192.0.2.2"),
            ("c.example.com", "CNAME"): RuntimeError("unexpected failure"),
        }
    )

    results = await scan_domains(
        ["a.example.com", "c.example.com", "b.example.com"],
        resolver,
        ScanOptions(probe_http=False),
    )

    assert [result.domain for result in results] == [
        "a.example.com",
        "c.example.com",
        "b.example.com",
    ]
    assert [result.verdict for result in results] == [
        Verdict.CLEAN,
        Verdict.ERROR,
        Verdict.CLEAN,
    ]


async def test_scan_domains_handles_empty_input():
    assert await scan_domains([], StubResolver({}), ScanOptions()) == []
