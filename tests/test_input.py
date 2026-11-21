from __future__ import annotations

import pytest

from cname_watch.input import normalize_domain, read_domains


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("https://blog.example.com/path?q=1", "blog.example.com"),
        ("http://blog.example.com:8080/", "blog.example.com"),
        ("blog.example.com:8443", "blog.example.com"),
        ("*.dev.example.com", "dev.example.com"),
        ("https://*.dev.example.com/path", "dev.example.com"),
        ("  blog.example.com  ", "blog.example.com"),
        ("\ufeffblog.example.com", "blog.example.com"),
        ("blog.example.com # production", "blog.example.com"),
        ("münich.example", "xn--mnich-kva.example"),
        ("foo_bar.example.com", "foo_bar.example.com"),
        ("xn--mnich-kva.example", "xn--mnich-kva.example"),
        ("*.example.com.", "example.com"),
        ("example.com/", "example.com"),
    ],
)
def test_normalize_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "# comment",
        "localhost",
        "http://",
        "bad domain.example.com",
        "-bad.example.com",
        "bad-.example.com",
        "bad..example.com",
        "1.2.3.4",
        "2001:db8::1",
    ],
)
def test_normalize_invalid(raw):
    assert normalize_domain(raw) is None


def test_read_domains_skips_comments_and_duplicates():
    domains, errors = read_domains(
        [
            "# production",
            "",
            "blog.example.com",
            "BLOG.example.com.",
            "https://assets.example.com/path",
            "not a domain",
            "bad..example.com",
        ]
    )

    assert domains == ["blog.example.com", "assets.example.com"]
    assert len(errors) == 2
    assert errors[0][0] == 6
    assert errors[1][0] == 7


def test_read_domains_returns_line_numbers():
    domains, errors = read_domains(["ok.example.com", "bad"])

    assert domains == ["ok.example.com"]
    assert errors == [(2, "bad", "not a valid domain name")]
