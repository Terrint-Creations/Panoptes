"""IP address intelligence: consensus geolocation, ownership, exposure, reverse DNS."""
from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.reversename
import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source
from panoptes.sources.domain import _rdap_entities


class GeoIPSource(Source):
    """Queries several geolocation providers and reports where they agree."""

    name = "geoip"
    kinds = ("ip",)
    description = "Geolocation and ASN merged from ip-api, ipwho.is and ipinfo (agreement raises confidence)"

    async def search(self, entity: Entity, ctx: Context):
        ip = entity.value
        providers = {"ip-api": self._ipapi, "ipwho.is": self._ipwhois, "ipinfo": self._ipinfo}

        async def run(name, fn):
            try:
                return name, await fn(ip, ctx)
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                ctx.log(f"geoip/{name}: {exc.__class__.__name__}", "warning")
                return name, {}

        results = await asyncio.gather(*(run(n, f) for n, f in providers.items()))
        votes: dict[str, dict[str, set[str]]] = {}
        for pname, fields in results:
            for field, value in fields.items():
                if value not in (None, ""):
                    votes.setdefault(field, {}).setdefault(str(value).strip(), set()).add(pname)
        answered = sum(1 for _, f in results if f) or 1
        for field in ("Country", "Region", "City", "Postal code", "Coordinates", "Time zone", "ISP", "Organisation", "ASN", "Usage flags"):
            for value, srcs in sorted(votes.get(field, {}).items(), key=lambda kv: -len(kv[1])):
                conf = 0.55 + 0.4 * (len(srcs) / answered)
                url = None
                if field == "Coordinates":
                    lat, lon = value.split(",")
                    url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=11/{lat}/{lon}"
                yield Finding(category="geolocation", title=field, value=value, source=self.name, target=entity,
                              sources=srcs, confidence=conf, url=url)

    async def _ipapi(self, ip, ctx):
        d = await ctx.get_json(f"http://ip-api.com/json/{ip}",
                               params={"fields": "status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile"})
        if d.get("status") != "success":
            return {}
        flags = [k for k in ("proxy", "hosting", "mobile") if d.get(k)]
        return {"Country": d.get("country"), "Region": d.get("regionName"), "City": d.get("city"),
                "Postal code": d.get("zip"), "Coordinates": _coords(d.get("lat"), d.get("lon")),
                "Time zone": d.get("timezone"), "ISP": d.get("isp"), "Organisation": d.get("org"),
                "ASN": (d.get("as") or "").split(" ")[0] or None,
                "Usage flags": ", ".join(flags) or None}

    async def _ipwhois(self, ip, ctx):
        d = await ctx.get_json(f"https://ipwho.is/{ip}")
        if not d.get("success"):
            return {}
        conn = d.get("connection") or {}
        return {"Country": d.get("country"), "Region": d.get("region"), "City": d.get("city"),
                "Postal code": d.get("postal"), "Coordinates": _coords(d.get("latitude"), d.get("longitude")),
                "Time zone": (d.get("timezone") or {}).get("id"), "ISP": conn.get("isp"),
                "Organisation": conn.get("org"), "ASN": f"AS{conn['asn']}" if conn.get("asn") else None}

    async def _ipinfo(self, ip, ctx):
        token = ctx.config.get("ipinfo_token")
        d = await ctx.get_json(f"https://ipinfo.io/{ip}/json", params={"token": token} if token else None)
        if d.get("bogon") or "error" in d:
            return {}
        asn, _, org = (d.get("org") or "").partition(" ")
        lat, _, lon = (d.get("loc") or "").partition(",")
        return {"Country": _country_name(d.get("country")), "Region": d.get("region"), "City": d.get("city"),
                "Postal code": d.get("postal"), "Coordinates": _coords(lat, lon) if lat else None,
                "Time zone": d.get("timezone"), "Organisation": org or None, "ASN": asn or None}


def _coords(lat, lon):
    try:
        return f"{float(lat):.2f},{float(lon):.2f}"
    except (TypeError, ValueError):
        return None


_COUNTRIES = {"US": "United States", "GB": "United Kingdom", "DE": "Germany", "FR": "France", "NL": "Netherlands",
              "CA": "Canada", "AU": "Australia", "JP": "Japan", "CN": "China", "RU": "Russia", "IN": "India",
              "BR": "Brazil", "SG": "Singapore", "IE": "Ireland", "SE": "Sweden", "FI": "Finland", "ES": "Spain",
              "IT": "Italy", "PL": "Poland", "UA": "Ukraine", "KR": "South Korea", "HK": "Hong Kong",
              "CH": "Switzerland", "BE": "Belgium", "NO": "Norway", "DK": "Denmark", "AT": "Austria", "MX": "Mexico"}


def _country_name(code):
    return _COUNTRIES.get(code, code)


class ReverseDNSSource(Source):
    name = "reverse-dns"
    kinds = ("ip",)
    description = "PTR (reverse DNS) hostname"

    async def search(self, entity: Entity, ctx: Context):
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.options.timeout
        try:
            answers = await resolver.resolve(dns.reversename.from_address(entity.value), "PTR")
        except (dns.exception.DNSException, OSError, ValueError):
            return
        for a in answers:
            host = a.to_text().rstrip(".")
            pivots = [Entity("domain", host)] if host.count(".") <= 2 else []
            yield Finding(category="network", title="Reverse DNS", value=host, source=self.name, target=entity,
                          confidence=0.99, pivots=pivots)


class RDAPIPSource(Source):
    name = "rdap-ip"
    kinds = ("ip",)
    description = "Network ownership via RDAP: netblock, owner organisation, abuse contacts"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.get(f"https://rdap.org/ip/{entity.value}", headers=API_HEADERS)
            if r.status_code != 200:
                return
            d = r.json()
        except (httpx.HTTPError, ValueError):
            return
        url = next((l["href"] for l in d.get("links", []) if l.get("rel") == "self"), None)
        base = dict(source=self.name, target=entity, confidence=0.97, url=url)
        if d.get("name"):
            yield Finding(category="network", title="Network name", value=d["name"], **base)
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in d.get("cidr0_cidrs", [])]
        rng = f"{d.get('startAddress')} - {d.get('endAddress')}" if d.get("startAddress") else None
        if cidrs or rng:
            yield Finding(category="network", title="Netblock", value=", ".join(cidrs) or rng, **base)
        if d.get("country"):
            yield Finding(category="network", title="Registry country", value=d["country"], **base)
        for f in _rdap_entities(d.get("entities", []), entity, self.name, url):
            f.pivots = [p for p in f.pivots if p.kind != "phone"]
            yield f


class InternetDBSource(Source):
    name = "internetdb"
    kinds = ("ip",)
    description = "Shodan InternetDB: open ports, hostnames, software (CPEs), known vulnerabilities"

    async def search(self, entity: Entity, ctx: Context):
        ip = entity.value
        if not ipaddress.ip_address(ip).is_global:
            ctx.log(f"internetdb: {ip} is not a public address", "warning")
            return
        try:
            r = await ctx.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code != 200:
                return
            d = r.json()
        except (httpx.HTTPError, ValueError):
            return
        url = f"https://www.shodan.io/host/{ip}"
        base = dict(source=self.name, target=entity, url=url)
        if d.get("ports"):
            yield Finding(category="exposure", title="Open ports", value=", ".join(map(str, d["ports"])),
                          confidence=0.9, **base)
        for host in d.get("hostnames", []):
            yield Finding(category="network", title="Hostname", value=host, confidence=0.85,
                          pivots=[Entity("domain", host)] if host.count(".") <= 2 else [], **base)
        if d.get("cpes"):
            yield Finding(category="exposure", title="Software", value=", ".join(d["cpes"][:20]), confidence=0.8, **base)
        if d.get("tags"):
            yield Finding(category="exposure", title="Tags", value=", ".join(d["tags"]), confidence=0.85, **base)
        for cve in d.get("vulns", [])[:50]:
            yield Finding(category="exposure", title="Vulnerability", value=cve,
                          url=f"https://nvd.nist.gov/vuln/detail/{cve}", source=self.name, target=entity,
                          confidence=0.6, data={"note": "inferred from software version, not verified"})
