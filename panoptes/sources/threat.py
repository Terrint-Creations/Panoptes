"""Threat intelligence & reputation (SpiderFoot-style): Tor, GreyNoise, DNS blocklists, RIPEstat."""
from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source

IP_BLOCKLISTS = {
    "zen.spamhaus.org": "Spamhaus ZEN", "bl.spamcop.net": "SpamCop", "b.barracudacentral.org": "Barracuda",
    "dnsbl.sorbs.net": "SORBS", "psbl.surriel.com": "PSBL", "dnsbl-1.uceprotect.net": "UCEPROTECT L1",
    "all.s5h.net": "s5h", "dnsbl.dronebl.org": "DroneBL",
}
DOMAIN_BLOCKLISTS = {"dbl.spamhaus.org": "Spamhaus DBL", "multi.surbl.org": "SURBL", "multi.uribl.com": "URIBL"}


async def _dnsbl(query: str, zones: dict[str, str], ctx: Context) -> list[tuple[str, str]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6

    async def one(zone, label):
        try:
            answers = [r.to_text() for r in await resolver.resolve(f"{query}.{zone}", "A")]
        except (dns.exception.DNSException, OSError):
            return None
        # 127.255.255.x / 127.0.1.255 / 127.0.0.1 from URIBL = "query refused" (public resolver), not a listing
        real = [a for a in answers if a.startswith("127.") and not a.startswith(("127.255.255.", "127.0.1.255"))
                and not (zone == "multi.uribl.com" and a == "127.0.0.1")]
        return (label, ", ".join(real)) if real else None

    return [r for r in await asyncio.gather(*(one(z, l) for z, l in zones.items())) if r]


async def _tor_exits(ctx: Context) -> set[str]:
    try:
        r = await ctx.get("https://check.torproject.org/torbulkexitlist", headers=API_HEADERS, timeout=30)
        return {l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")}
    except httpx.HTTPError:
        return set()


class IPReputationSource(Source):
    name = "ip-reputation"
    kinds = ("ip",)
    description = "Tor exit check, GreyNoise classification, 8 DNS blocklists, RIPEstat routing/ASN holder"

    async def search(self, entity: Entity, ctx: Context):
        ip = entity.value
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return
        base = dict(source=self.name, target=entity)
        tor, gn, listings, ripe = await asyncio.gather(
            ctx.once("tor-exits", lambda: _tor_exits(ctx)), self._greynoise(ip, ctx),
            _dnsbl(".".join(reversed(ip.split("."))), IP_BLOCKLISTS, ctx) if addr.version == 4 else asyncio.sleep(0, []),
            self._ripe(ip, ctx))
        if ip in tor:
            yield Finding(category="threat", title="Tor exit node", value="This IP is a current Tor exit relay",
                          confidence=0.99, url=f"https://metrics.torproject.org/rs.html#search/{ip}",
                          data={"severity": "medium"}, **base)
        if gn:
            cls = gn.get("classification") or ("benign service" if gn.get("riot") else "not seen scanning")
            sev = {"malicious": "high", "unknown": "low"}.get(cls, "info")
            yield Finding(category="threat", title="GreyNoise", value=f"{cls}{' - ' + gn['name'] if gn.get('name') else ''}",
                          url=gn.get("link") or f"https://viz.greynoise.io/ip/{ip}", confidence=0.85,
                          data={"severity": sev, "noise": gn.get("noise"), "riot": gn.get("riot"),
                                "last_seen": gn.get("last_seen")}, **base)
        for label, code in listings:
            yield Finding(category="threat", title=f"Blocklisted: {label}", value=f"listed ({code})", confidence=0.9,
                          data={"severity": "medium"}, **base)
        if not listings and addr.version == 4:
            yield Finding(category="threat", title="DNS blocklists", value=f"Not listed on {len(IP_BLOCKLISTS)} blocklists",
                          confidence=0.8, data={"severity": "info"}, **base)
        for title, value in ripe:
            yield Finding(category="network", title=title, value=value, url=f"https://stat.ripe.net/{ip}",
                          confidence=0.95, **{**base, "source": "ripestat"})

    async def _greynoise(self, ip, ctx):
        try:
            r = await ctx.get(f"https://api.greynoise.io/v3/community/{ip}", headers=API_HEADERS)
            return r.json() if r.status_code in (200, 404) else None
        except (httpx.HTTPError, ValueError):
            return None

    async def _ripe(self, ip, ctx):
        out = []
        try:
            r = await ctx.get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip},
                              headers=API_HEADERS)
            d = r.json().get("data", {})
            if d.get("prefix"):
                out.append(("Announced prefix", d["prefix"]))
            for asn in d.get("asns", [])[:3]:
                r2 = await ctx.get("https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{asn}"},
                                   headers=API_HEADERS)
                holder = r2.json().get("data", {}).get("holder")
                out.append(("Origin AS", f"AS{asn} {holder or ''}".strip()))
        except (httpx.HTTPError, ValueError):
            pass
        return out


class DomainReputationSource(Source):
    name = "domain-reputation"
    kinds = ("domain",)
    description = "Domain blocklists (Spamhaus DBL, SURBL, URIBL)"

    async def search(self, entity: Entity, ctx: Context):
        listings = await _dnsbl(entity.value, DOMAIN_BLOCKLISTS, ctx)
        for label, code in listings:
            yield Finding(category="threat", title=f"Blocklisted: {label}", value=f"listed ({code})", source=self.name,
                          target=entity, confidence=0.9, data={"severity": "high"})
        if not listings:
            yield Finding(category="threat", title="Domain blocklists", value=f"Not listed on {len(DOMAIN_BLOCKLISTS)} blocklists",
                          source=self.name, target=entity, confidence=0.8, data={"severity": "info"})
