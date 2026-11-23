"""DNS-aware address enforcement that the HTTP client cannot bypass.

Validating a hostname before the request is not enough: the HTTP client
resolves the name again when it opens the socket, so a second DNS answer could
point at a loopback or metadata address (DNS rebinding / TOCTOU).

``SafeResolver`` closes that gap by *being* the resolver handed to
``aiohttp.TCPConnector``. The connector dials exactly the addresses the
resolver returned, so the checked answer is the dialed answer; there is no
second, unchecked lookup between validation and connect. Every address in the
answer is checked, not only the first one.

Limits that remain, and are documented rather than hidden:

* a connection already pooled by the connector is reused without new
  resolution, so the address was checked when the pool entry was created
* DNS caching inside the backing resolver means a cached answer is reused; the
  answer is still validated on every ``resolve`` call
* if a caller bypasses ``Engine`` and builds its own session without
  ``SafeResolver``, enforcement does not apply
* only IP-literal and resolver-level knowledge is used; HTTPS certificate
  checks are the TLS layer's responsibility
"""

from __future__ import annotations

import socket
from collections.abc import Mapping, Sequence

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from core.exceptions import ScopeViolationError
from core.security import is_global_address


class SafeResolver(AbstractResolver):
    """Resolver that refuses answers containing non-public addresses."""

    def __init__(
        self,
        *,
        allow_private: bool = False,
        backing: AbstractResolver | Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.allow_private = allow_private
        if isinstance(backing, Mapping):
            self._static: Mapping[str, Sequence[str]] | None = {
                key.lower(): value for key, value in backing.items()
            }
            self._backing: AbstractResolver | None = None
        else:
            self._static = None
            self._backing = backing if backing is not None else aiohttp.resolver.DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        """Resolve ``host`` and enforce the address policy on every answer."""
        if self._static is not None:
            results = self._static_results(host, port, family)
        else:
            backing = self._backing
            if backing is None:  # pragma: no cover - constructor guarantees one or the other
                raise ScopeViolationError(host, reason="no resolver backing configured")
            results = await backing.resolve(host, port, family=family)

        self.enforce(host, [str(entry.get("host", "")) for entry in results])
        return results

    def _static_results(
        self, host: str, port: int, family: socket.AddressFamily
    ) -> list[ResolveResult]:
        addresses = self._static.get(host.lower()) if self._static else None
        if not addresses:
            raise ScopeViolationError(host, reason="host did not resolve")
        return [
            ResolveResult(
                hostname=host,
                host=address,
                port=port,
                family=socket.AF_INET6 if ":" in address else socket.AF_INET,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
            for address in addresses
        ]

    def enforce(self, host: str, addresses: list[str]) -> None:
        """Raise when any resolved address is outside the allowed address space."""
        if not addresses:
            raise ScopeViolationError(host, reason="host did not resolve")
        if self.allow_private:
            return

        for address in addresses:
            if not is_global_address(address):
                raise ScopeViolationError(
                    host,
                    reason=f"hostname resolves to non-public address {address}",
                    allowed_host=host,
                )

    async def close(self) -> None:
        if self._backing is not None:
            await self._backing.close()
