from __future__ import annotations

import dns.exception
import pytest

from cname_watch.dns_chain import resolve_chain
from cname_watch.models import TerminalState
from tests.helpers import StubResolver, addresses, cname, nxdomain


async def test_single_hop_resolves():
    resolver = StubResolver(
        {
            ("www.example.com", "CNAME"): cname("target.example.net."),
            ("target.example.net", "CNAME"): None,
            ("target.example.net", "A"): addresses("192.0.2.10"),
            ("target.example.net", "AAAA"): addresses("2001:db8::10"),
        }
    )

    result = await resolve_chain("www.example.com", resolver)

    assert result.state is TerminalState.RESOLVED
    assert result.terminal == "target.example.net"
    assert result.cname_target == "target.example.net"
    assert result.addresses == ["192.0.2.10", "2001:db8::10"]
    assert len(result.chain) == 1


async def test_multiple_hops_are_followed():
    resolver = StubResolver(
        {
            ("a.example.com", "CNAME"): cname("b.example.net."),
            ("b.example.net", "CNAME"): cname("c.example.org."),
            ("c.example.org", "CNAME"): None,
            ("c.example.org", "A"): addresses("192.0.2.20"),
        }
    )

    result = await resolve_chain("a.example.com", resolver)

    assert result.state is TerminalState.RESOLVED
    assert [link.target for link in result.chain] == ["b.example.net", "c.example.org"]
    assert result.terminal == "c.example.org"


async def test_nxdomain_after_cname_is_dangling():
    resolver = StubResolver(
        {
            ("blog.example.com", "CNAME"): cname("old-blog.github.io."),
            ("old-blog.github.io", "CNAME"): nxdomain(),
        }
    )

    result = await resolve_chain("blog.example.com", resolver)

    assert result.state is TerminalState.NXDOMAIN
    assert result.terminal == "old-blog.github.io"
    assert result.cname_target == "old-blog.github.io"


async def test_input_nxdomain_has_no_chain():
    resolver = StubResolver({("missing.example.com", "CNAME"): nxdomain()})

    result = await resolve_chain("missing.example.com", resolver)

    assert result.state is TerminalState.NXDOMAIN
    assert result.chain == []
    assert result.cname_target is None


async def test_cname_to_name_without_addresses():
    resolver = StubResolver(
        {
            ("www.example.com", "CNAME"): cname("empty.example.net."),
            ("empty.example.net", "CNAME"): None,
            ("empty.example.net", "A"): None,
            ("empty.example.net", "AAAA"): None,
        }
    )

    result = await resolve_chain("www.example.com", resolver)

    assert result.state is TerminalState.NO_ADDRESS
    assert result.chain


async def test_no_cname_with_addresses():
    resolver = StubResolver(
        {
            ("www.example.com", "CNAME"): None,
            ("www.example.com", "A"): addresses("192.0.2.30"),
        }
    )

    result = await resolve_chain("www.example.com", resolver)

    assert result.state is TerminalState.RESOLVED
    assert result.chain == []
    assert result.addresses == ["192.0.2.30"]


async def test_cname_loop_is_an_error():
    resolver = StubResolver(
        {
            ("a.example.com", "CNAME"): cname("b.example.com."),
            ("b.example.com", "CNAME"): cname("a.example.com."),
        }
    )

    result = await resolve_chain("a.example.com", resolver)

    assert result.state is TerminalState.ERROR
    assert "loop" in (result.error or "").lower()


async def test_chain_depth_limit():
    resolver = StubResolver(
        {
            ("a.example.com", "CNAME"): cname("b.example.com."),
            ("b.example.com", "CNAME"): cname("c.example.com."),
        }
    )

    result = await resolve_chain("a.example.com", resolver, max_depth=1)

    assert result.state is TerminalState.ERROR
    assert "exceeds" in (result.error or "")


async def test_dns_failure_is_an_error():
    resolver = StubResolver({("www.example.com", "CNAME"): dns.exception.Timeout()})

    result = await resolve_chain("www.example.com", resolver)

    assert result.state is TerminalState.ERROR
    assert "Timeout" in (result.error or "")


async def test_axfr_style_error_is_an_error():
    resolver = StubResolver({("www.example.com", "CNAME"): dns.exception.DNSException("boom")})

    result = await resolve_chain("www.example.com", resolver)

    assert result.state is TerminalState.ERROR
    assert "boom" in (result.error or "")


@pytest.mark.parametrize(
    "target",
    [
        "acme.s3.amazonaws.com",
        "acme.s3.us-east-1.amazonaws.com",
        "acme.s3-website-us-east-1.amazonaws.com",
    ],
)
async def test_s3_style_targets_resolve_normally(target: str):
    resolver = StubResolver(
        {
            ("assets.example.com", "CNAME"): cname(target + "."),
            (target, "CNAME"): None,
            (target, "A"): addresses("192.0.2.40"),
        }
    )

    result = await resolve_chain("assets.example.com", resolver)

    assert result.state is TerminalState.RESOLVED
    assert result.cname_target == target
