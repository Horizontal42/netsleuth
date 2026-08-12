from __future__ import annotations

import dns.asyncresolver
import dns.exception

from netsleuth.ip_geo import nat64_prefix_from_aaaa

_IPV4ONLY_ARPA = "ipv4only.arpa"


async def detect_nat64(timeout: float) -> str | None:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    try:
        answer = await resolver.resolve(_IPV4ONLY_ARPA, "AAAA")
    except dns.exception.DNSException:
        return None
    return nat64_prefix_from_aaaa([str(r) for r in answer])
