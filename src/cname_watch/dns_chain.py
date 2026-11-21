"""CNAME chain resolution built on dnspython's asyncio resolver."""

from __future__ import annotations

from collections.abc import Sequence

import dns.asyncresolver
import dns.exception
import dns.resolver

from .models import CnameLink, Resolution, TerminalState

MAX_DEPTH = 10


def build_resolver(
    timeout: float = 5.0,
    nameservers: Sequence[str] | None = None,
) -> dns.asyncresolver.Resolver:
    """Create an async resolver with a bounded total lookup time."""

    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.retry_servfail = True
    if nameservers:
        resolver.nameservers = list(nameservers)
    return resolver


def _describe(exc: BaseException) -> str:
    message = str(exc).strip()
    name = type(exc).__name__
    return f"{name}: {message}"[:300] if message else name


async def resolve_chain(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    max_depth: int = MAX_DEPTH,
) -> Resolution:
    """Follow CNAME records and report the terminal DNS state.

    A CNAME is followed explicitly (rather than relying on the resolver's
    implicit chasing) so each hop and the failure point can be reported.
    """

    chain: list[CnameLink] = []
    current = domain
    seen = {domain.lower()}

    for _ in range(max_depth + 1):
        try:
            answer = await resolver.resolve(current, "CNAME", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.NXDOMAIN,
            )
        except dns.exception.DNSException as exc:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.ERROR,
                error=_describe(exc),
            )

        rrset = getattr(answer, "rrset", None)
        if answer is None or rrset is None or len(answer) == 0:
            break

        try:
            target = str(answer[0].target).rstrip(".").lower()
        except (AttributeError, IndexError, ValueError) as exc:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.ERROR,
                error=f"malformed CNAME response: {_describe(exc)}",
            )

        if not target:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.ERROR,
                error="malformed CNAME response: empty target",
            )

        chain.append(CnameLink(owner=current, target=target))
        if target in seen:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=target,
                state=TerminalState.ERROR,
                error=f"CNAME loop detected at {target}",
            )
        seen.add(target)
        current = target
    else:
        return Resolution(
            query=domain,
            chain=chain,
            terminal=current,
            state=TerminalState.ERROR,
            error=f"CNAME chain exceeds {max_depth} hops",
        )

    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(current, record_type, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.NXDOMAIN,
            )
        except dns.exception.DNSException as exc:
            return Resolution(
                query=domain,
                chain=chain,
                terminal=current,
                state=TerminalState.ERROR,
                error=_describe(exc),
            )
        if answer is not None and getattr(answer, "rrset", None) is not None:
            addresses.extend(str(record) for record in answer)

    state = TerminalState.RESOLVED if addresses else TerminalState.NO_ADDRESS
    return Resolution(
        query=domain,
        chain=chain,
        terminal=current,
        state=state,
        addresses=addresses,
    )
