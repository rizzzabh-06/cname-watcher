from __future__ import annotations

import json

import pytest

from cname_watch.rules import (
    BUILTIN_RULES,
    Rule,
    RuleError,
    load_rules,
    merge_rules,
    parse_rules,
    provider_for_target,
)


def rule(rule_id: str) -> Rule:
    return next(item for item in BUILTIN_RULES if item.id == rule_id)


@pytest.mark.parametrize(
    ("target", "provider"),
    [
        ("acme.s3.amazonaws.com", "Amazon S3"),
        ("acme.s3.us-east-1.amazonaws.com", "Amazon S3"),
        ("s3.amazonaws.com", "Amazon S3"),
        ("s3.us-east-1.amazonaws.com", "Amazon S3"),
        ("s3-us-gov-west-1.amazonaws.com", "Amazon S3"),
        ("acme.s3-website-eu-west-1.amazonaws.com", "Amazon S3"),
        ("acme.s3-us-gov-west-1.amazonaws.com", "Amazon S3"),
        ("acme.s3.cn-north-1.amazonaws.com.cn", "Amazon S3"),
        ("user.github.io", "GitHub Pages"),
        ("preview.vercel.app", "Vercel"),
        ("cname.vercel-dns.com", "Vercel"),
        ("cname.vercel-dns-017.com", "Vercel"),
        ("app.azurewebsites.net", "Azure App Service"),
        ("edge.trafficmanager.net", "Azure App Service"),
        ("unknown.example.net", None),
        (None, None),
    ],
)
def test_provider_inference(target, provider):
    assert provider_for_target(target) == provider


def test_s3_fingerprint():
    item = rule("aws-s3")
    assert item.matches_target("acme.s3.amazonaws.com")
    assert (
        item.matches_response(
            "acme.s3.amazonaws.com",
            404,
            "application/xml",
            "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code></Error>",
        )
        == "NoSuchBucket"
    )


def test_s3_html_website_fingerprint():
    item = rule("aws-s3")
    assert item.matches_target("acme.s3-website-us-east-1.amazonaws.com")
    matched = item.matches_response(
        "acme.s3-website-us-east-1.amazonaws.com",
        404,
        "text/html",
        "<h1>The specified bucket does not exist</h1>",
    )
    assert matched == "The specified bucket does not exist"


def test_s3_existing_but_forbidden_bucket_does_not_match():
    item = rule("aws-s3")
    assert (
        item.matches_response(
            "acme.s3.amazonaws.com",
            403,
            "application/xml",
            "<Error><Code>AccessDenied</Code></Error>",
        )
        is None
    )


def test_github_pages_fingerprint_is_case_insensitive():
    item = rule("github-pages")
    assert item.matches_target("old-blog.github.io")
    assert item.matches_response(
        "old-blog.github.io",
        404,
        "text/html; charset=utf-8",
        "<p>THERE ISN'T A GITHUB PAGES SITE HERE</p>",
    )


def test_vercel_fingerprint():
    item = rule("vercel")
    assert (
        item.matches_response(
            "demo.vercel.app",
            404,
            "text/plain; charset=utf-8",
            "The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND",
        )
        == "DEPLOYMENT_NOT_FOUND"
    )


def test_azure_fingerprint():
    item = rule("azure-app-service")
    assert (
        item.matches_response(
            "demo.azurewebsites.net",
            404,
            "text/html",
            "<h1>404 Web Site not found.</h1>",
        )
        == "404 Web Site not found"
    )


@pytest.mark.parametrize(
    ("rule_id", "target", "status", "content_type", "body"),
    [
        (
            "github-pages",
            "old-blog.github.io",
            200,
            "text/html",
            "There isn't a GitHub Pages site here",
        ),
        ("github-pages", "example.net", 404, "text/html", "There isn't a GitHub Pages site here"),
        (
            "github-pages",
            "old-blog.github.io",
            404,
            "image/png",
            "There isn't a GitHub Pages site here",
        ),
        ("github-pages", "old-blog.github.io", 404, "text/html", ""),
        ("vercel", "demo.vercel.app", 404, "application/octet-stream", "DEPLOYMENT_NOT_FOUND"),
    ],
)
def test_non_matches(rule_id, target, status, content_type, body):
    assert rule(rule_id).matches_response(target, status, content_type, body) is None


def test_missing_content_type_still_matches_text_body():
    assert rule("aws-s3").matches_response(
        "acme.s3.amazonaws.com",
        404,
        None,
        "<Error><Code>NoSuchBucket</Code></Error>",
    )


def test_parse_rules_accepts_list_and_object():
    item = {
        "id": "example-cloud",
        "provider": "Example Cloud",
        "cname": ["*.example-cloud.net"],
        "status": [404],
        "body": ["app not found"],
        "description": "demo",
    }
    from_list = parse_rules([item])
    from_object = parse_rules({"rules": [item]})
    assert from_list == from_object
    assert from_list[0].provider == "Example Cloud"


def test_parse_rules_rejects_bad_input():
    valid = {
        "id": "example-cloud",
        "provider": "Example Cloud",
        "cname": ["*.example-cloud.net"],
        "body": ["app not found"],
    }
    cases = [
        "not a list",
        [{"id": "Bad Id", "provider": "x", "cname": ["*.x"], "body": ["x"]}],
        [
            {"id": "dup", "provider": "x", "cname": ["*.x"], "body": ["x"]},
            {"id": "dup", "provider": "y", "cname": ["*.y"], "body": ["y"]},
        ],
        [{"id": "missing-body", "provider": "x", "cname": ["*.x"]}],
        [{**valid, "status": [200, 999]}],
        [{**valid, "cname": []}],
        [{**valid, "unknown": True}],
    ]
    for data in cases:
        with pytest.raises(RuleError):
            parse_rules(data)


def test_load_rules_from_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "example-cloud",
                        "provider": "Example Cloud",
                        "cname": ["*.example-cloud.net"],
                        "status": [404],
                        "body": ["app not found"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_rules(path)

    assert len(rules) == 1
    assert rules[0].matches_target("demo.example-cloud.net")


def test_load_rules_reports_missing_file(tmp_path):
    with pytest.raises(RuleError, match="cannot read"):
        load_rules(tmp_path / "missing.json")


def test_load_rules_reports_invalid_json(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(RuleError, match="invalid JSON"):
        load_rules(path)


def test_merge_rules_overrides_by_id():
    custom = Rule(
        id="github-pages",
        provider="Custom GitHub",
        cname_patterns=("*.github.io",),
        status_codes=(404,),
        body_patterns=("custom",),
    )

    merged = merge_rules(BUILTIN_RULES, [custom])

    assert len(merged) == len(BUILTIN_RULES)
    assert provider_for_target("user.github.io", merged) == "Custom GitHub"


def test_rules_to_dict_round_trips():
    item = rule("aws-s3")
    data = item.to_dict()
    assert data["id"] == "aws-s3"
    assert data["status"] == [404]
    assert data["cname"]
