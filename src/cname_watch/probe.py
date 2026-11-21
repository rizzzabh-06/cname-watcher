"""Bounded HTTP(S) probing and response-text cleanup."""

from __future__ import annotations

import html
import re

import httpx

from .models import ProbeAttempt

MAX_BODY_BYTES = 128 * 1024
_SNIPPET_RADIUS = 130
_SCRIPT_STYLE = re.compile(r"(?is)<(script|style)\b[^>]*>.*?</\1\s*>")
_TAG = re.compile(r"(?s)<[^>]+>")
_WHITESPACE = re.compile(r"\s+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


async def fetch(
    url: str,
    client: httpx.AsyncClient,
    max_body_bytes: int = MAX_BODY_BYTES,
) -> ProbeAttempt:
    """GET ``url`` without following redirects and keep a bounded body."""

    try:
        async with client.stream("GET", url) as response:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                remaining = max_body_bytes - size
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
                if size >= max_body_bytes:
                    break

            raw = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            try:
                body = raw.decode(encoding, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")

            return ProbeAttempt(
                url=str(response.url),
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                body=body,
                body_bytes=len(raw),
            )
    except httpx.HTTPError as exc:
        message = str(exc).strip()
        error = f"{type(exc).__name__}: {message}"[:300] if message else type(exc).__name__
        return ProbeAttempt(url=url, error=error)


def make_snippet(body: str, matched_text: str, radius: int = _SNIPPET_RADIUS) -> str:
    """Turn an HTML/JSON body into a short, single-line evidence snippet."""

    text = _SCRIPT_STYLE.sub(" ", body)
    text = _TAG.sub(" ", text)
    text = html.unescape(text)
    text = _CONTROL.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return ""

    index = text.lower().find(matched_text.lower())
    if index < 0:
        return text[: radius * 2].strip()

    start = max(0, index - radius)
    end = min(len(text), index + len(matched_text) + radius)
    snippet = text[start:end].strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet[:360]
