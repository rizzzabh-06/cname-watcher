from __future__ import annotations

import httpx

from cname_watch.probe import fetch, make_snippet


def client_for(handler, *, follow_redirects: bool = False) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=follow_redirects,
    )


async def test_fetch_returns_status_headers_and_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            headers={"content-type": "text/html; charset=utf-8"},
            text="not found",
        )

    async with client_for(handler) as client:
        attempt = await fetch("http://example.com/", client)

    assert attempt.status_code == 404
    assert attempt.content_type == "text/html; charset=utf-8"
    assert attempt.body == "not found"
    assert attempt.error is None
    assert attempt.url == "http://example.com/"


async def test_fetch_caps_the_response_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000)

    async with client_for(handler) as client:
        attempt = await fetch("http://example.com/", client, max_body_bytes=100)

    assert attempt.status_code == 200
    assert len(attempt.body) == 100


async def test_fetch_does_not_follow_redirects_by_default():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://elsewhere.example/"})

    async with client_for(handler) as client:
        attempt = await fetch("http://example.com/", client)

    assert attempt.status_code == 302
    assert len(requests) == 1
    assert requests[0].url.host == "example.com"


async def test_fetch_reports_network_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name resolution failed", request=request)

    async with client_for(handler) as client:
        attempt = await fetch("http://missing.example/", client)

    assert attempt.status_code is None
    assert attempt.error is not None
    assert "ConnectError" in attempt.error
    assert "name resolution failed" in attempt.error


def test_snippet_strips_markup_and_scripts():
    body = (
        "<html><script>do_not_show()</script><style>.x{}</style>"
        "<h1>There isn't a GitHub Pages site here.</h1></html>"
    )

    snippet = make_snippet(body, "there isn't a github pages site here")

    assert "There isn't a GitHub Pages site here." in snippet
    assert "do_not_show" not in snippet
    assert "<" not in snippet
    assert "\n" not in snippet


def test_snippet_removes_terminal_control_characters():
    snippet = make_snippet("<p>NoSuchBucket\x1b[31m owned</p>", "nosuchbucket")
    assert "\x1b" not in snippet
    assert snippet == "NoSuchBucket[31m owned"


def test_snippet_unescapes_html_entities():
    snippet = make_snippet("<p>NoSuchBucket &amp; no owner</p>", "nosuchbucket")
    assert snippet == "NoSuchBucket & no owner"


def test_snippet_falls_back_when_match_was_hidden():
    assert make_snippet("<script>hidden</script>", "hidden") == ""
