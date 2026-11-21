"""Provider fingerprints used to recognise unclaimed cloud resources.

A rule only applies when the terminal CNAME target matches one of its
``cname_patterns``. The HTTP status and response body must then also match.
This two-factor check keeps generic 404 pages from being reported as takeovers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_TEXT_TYPES = {
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "application/xhtml+xml",
    "application/xml",
    "application/javascript",
    "application/ecmascript",
    "text/xml",
}


class RuleError(ValueError):
    """Raised when a custom rule file is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    """A provider-specific dangling-resource fingerprint."""

    id: str
    provider: str
    cname_patterns: tuple[str, ...]
    status_codes: tuple[int, ...]
    body_patterns: tuple[str, ...]
    description: str = ""

    def matches_target(self, target: str | None) -> bool:
        if not target:
            return False
        candidate = target.rstrip(".").lower()
        return any(fnmatchcase(candidate, pattern.lower()) for pattern in self.cname_patterns)

    def matches_response(
        self,
        target: str | None,
        status_code: int | None,
        content_type: str | None,
        body: str,
    ) -> str | None:
        """Return the matched body text, or ``None`` if the rule does not match."""

        if not self.matches_target(target):
            return None
        if status_code is None:
            return None
        if self.status_codes and status_code not in self.status_codes:
            return None
        if not _is_textual(content_type, body):
            return None

        haystack = body.lower()
        for pattern in self.body_patterns:
            index = haystack.find(pattern.lower())
            if index >= 0:
                return body[index : index + len(pattern)]
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider": self.provider,
            "cname": list(self.cname_patterns),
            "status": list(self.status_codes),
            "body": list(self.body_patterns),
            "description": self.description,
        }


def _is_textual(content_type: str | None, body: str) -> bool:
    if not body:
        return False
    if not content_type:
        return True
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type.startswith("text/") or media_type in _TEXT_TYPES:
        return True
    return media_type.startswith("application/") and (
        media_type.endswith("+xml") or media_type.endswith("+json")
    )


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        id="aws-s3",
        provider="Amazon S3",
        cname_patterns=(
            "s3.amazonaws.com",
            "*.s3.amazonaws.com",
            "s3.*.amazonaws.com",
            "*.s3.*.amazonaws.com",
            "s3-*.amazonaws.com",
            "*.s3-*.amazonaws.com",
            "s3.amazonaws.com.cn",
            "*.s3.amazonaws.com.cn",
            "s3.*.amazonaws.com.cn",
            "*.s3.*.amazonaws.com.cn",
            "s3-*.amazonaws.com.cn",
            "*.s3-*.amazonaws.com.cn",
        ),
        status_codes=(404,),
        body_patterns=(
            "nosuchbucket",
            "the specified bucket does not exist",
        ),
        description="The S3 bucket referenced by the CNAME does not exist.",
    ),
    Rule(
        id="github-pages",
        provider="GitHub Pages",
        cname_patterns=("*.github.io",),
        status_codes=(404,),
        body_patterns=("there isn't a github pages site here",),
        description="The GitHub Pages site referenced by the CNAME has not been claimed.",
    ),
    Rule(
        id="vercel",
        provider="Vercel",
        cname_patterns=(
            "*.vercel.app",
            "*.now.sh",
            "cname.vercel-dns.com",
            "*.vercel-dns.com",
            "cname.vercel-dns-*.com",
        ),
        status_codes=(404,),
        body_patterns=(
            "deployment_not_found",
            "the deployment could not be found",
        ),
        description="The Vercel deployment referenced by the CNAME does not exist.",
    ),
    Rule(
        id="azure-app-service",
        provider="Azure App Service",
        cname_patterns=(
            "*.azurewebsites.net",
            "*.cloudapp.net",
            "*.cloudapp.azure.com",
            "*.trafficmanager.net",
        ),
        status_codes=(404,),
        body_patterns=(
            "404 web site not found",
            "this site is not configured",
            "web app not found",
        ),
        description="The Azure App Service app referenced by the CNAME is not assigned.",
    ),
)


def provider_for_target(target: str | None, rules: Iterable[Rule] = BUILTIN_RULES) -> str | None:
    """Infer the provider from the CNAME target alone."""

    for rule in rules:
        if rule.matches_target(target):
            return rule.provider
    return None


def parse_rules(data: Any) -> tuple[Rule, ...]:
    """Validate and convert decoded JSON into rules."""

    if isinstance(data, dict):
        unknown = set(data) - {"rules"}
        if unknown:
            raise RuleError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
        data = data.get("rules")
    if not isinstance(data, list):
        raise RuleError("expected a list of rules or an object with a 'rules' list")

    rules: list[Rule] = []
    seen: set[str] = set()
    allowed_keys = {"id", "provider", "cname", "status", "body", "description"}

    for position, item in enumerate(data, start=1):
        where = f"rule #{position}"
        if not isinstance(item, dict):
            raise RuleError(f"{where}: expected an object")

        unknown = set(item) - allowed_keys
        if unknown:
            raise RuleError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise RuleError(f"{where}: 'id' must match {_RULE_ID.pattern}")
        if rule_id in seen:
            raise RuleError(f"{where}: duplicate id {rule_id!r}")
        seen.add(rule_id)

        provider = item.get("provider")
        if not isinstance(provider, str) or not provider.strip():
            raise RuleError(f"{where}: 'provider' must be a non-empty string")

        cname = item.get("cname")
        if (
            not isinstance(cname, list)
            or not cname
            or not all(isinstance(pattern, str) and pattern.strip() for pattern in cname)
        ):
            raise RuleError(f"{where}: 'cname' must be a non-empty list of strings")

        status = item.get("status", [])
        if not isinstance(status, list) or not all(
            isinstance(code, int) and not isinstance(code, bool) and 100 <= code <= 599
            for code in status
        ):
            raise RuleError(f"{where}: 'status' must be a list of HTTP status codes")

        body = item.get("body")
        if (
            not isinstance(body, list)
            or not body
            or not all(isinstance(pattern, str) and pattern.strip() for pattern in body)
        ):
            raise RuleError(f"{where}: 'body' must be a non-empty list of strings")

        description = item.get("description", "")
        if not isinstance(description, str):
            raise RuleError(f"{where}: 'description' must be a string")

        rules.append(
            Rule(
                id=rule_id,
                provider=provider.strip(),
                cname_patterns=tuple(pattern.strip() for pattern in cname),
                status_codes=tuple(status),
                body_patterns=tuple(pattern.strip() for pattern in body),
                description=description.strip(),
            )
        )

    return tuple(rules)


def load_rules(path: str | Path) -> tuple[Rule, ...]:
    """Load custom rules from a JSON file."""

    rule_path = Path(path)
    try:
        raw = rule_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read {rule_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuleError(f"invalid JSON in {rule_path}: {exc}") from exc
    return parse_rules(data)


def merge_rules(
    base: Iterable[Rule] = BUILTIN_RULES, extra: Iterable[Rule] = ()
) -> tuple[Rule, ...]:
    """Return ``base`` with ``extra`` rules added; matching ids replace built-ins."""

    merged = {rule.id: rule for rule in base}
    for rule in extra:
        merged[rule.id] = rule
    return tuple(merged.values())
