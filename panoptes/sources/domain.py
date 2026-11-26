"""Domain intelligence: DNS, registration, combined subdomain enumeration, website, history."""
from __future__ import annotations

import asyncio
import re

import dns.asyncresolver
import dns.exception
import httpx

from panoptes.detect import social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, extract_emails

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


class DNSSource(Source):
    name = "dns"
    kinds = ("domain",)
    description = "DNS records, SPF/DMARC policy and resolved IPs"

    async def search(self, entity: Entity, ctx: Context):
        domain = entity.value
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.options.timeout

        async def q(name, rtype):
            try:
                return rtype, [r.to_text() for r in await resolver.resolve(name, rtype)]
            except (dns.exception.DNSException, OSError):
                return rtype, []

        results = await asyncio.gather(*(q(domain, t) for t in RECORD_TYPES), q(f"_dmarc.{domain}", "TXT"))
        base = dict(source=self.name, target=entity, confidence=0.99)
        for rtype, records in results[:-1]:
            for rec in records:
                pivots = [Entity("ip", rec)] if rtype in ("A", "AAAA") else []
                yield Finding(category="dns", title=rtype, value=rec.strip('"') if rtype == "TXT" else rec,
                              pivots=pivots, **base)
                if rtype == "TXT" and rec.strip('"').startswith("v=spf1"):
                    includes = re.findall(r"include:(\S+)", rec)
                    if includes:
                        yield Finding(category="dns", title="SPF senders", value=", ".join(includes), **base)
        dmarc = [r.strip('"') for r in results[-1][1] if "v=DMARC1" in r]
        if dmarc:
            yield Finding(category="dns", title="DMARC", value=dmarc[0], **base)
            for addr in re.findall(r"mailto:([^,;\s]+)", dmarc[0]):
                yield Finding(category="email", title="DMARC report address", value=addr.lower(), source=self.name,
                              target=entity, confidence=0.7)
        elif any(r for _, r in results[:-1]):
            yield Finding(category="dns", title="DMARC", value="No DMARC policy (domain spoofable)", **base)


class RDAPDomainSource(Source):
    name = "rdap"
    kinds = ("domain",)
    description = "Registration data via RDAP (modern WHOIS): registrar, dates, status, contacts"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.get(f"https://rdap.org/domain/{entity.value}", headers=API_HEADERS)
        except httpx.HTTPError as exc:
            ctx.log(f"rdap: {exc.__class__.__name__}", "warning")
            return
        if r.status_code != 200:
            return
        d = r.json()
        base = dict(source=self.name, target=entity, confidence=0.97,
                    url=next((l["href"] for l in d.get("links", []) if l.get("rel") == "self"), None))
        for ev in d.get("events", []):
            action = ev.get("eventAction", "")
            if action in ("registration", "expiration", "last changed"):
                yield Finding(category="registration", title=action.capitalize(), value=ev.get("eventDate", ""), **base)
        if d.get("status"):
            yield Finding(category="registration", title="Status", value=", ".join(d["status"]), **base)
        ns = [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]
        if ns:
            yield Finding(category="registration", title="Nameservers", value=", ".join(ns), **base)
        for f in _rdap_entities(d.get("entities", []), entity, self.name, base["url"]):
            yield f


def _vcard(entity: dict) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] in ("fn", "org", "email", "tel", "adr"):
            val = item[3]
            if item[0] == "adr" and isinstance(val, list):
                val = ", ".join(str(v) for v in val if v and not isinstance(v, list))
            if isinstance(item[1], dict) and item[1].get("label") and item[0] == "adr":
                val = item[1]["label"]
            if val:
                out[item[0]] = str(val)
    return out


REDACTED = re.compile(r"redact|privacy|withheld|not disclosed|data protected|gdpr", re.I)


def _rdap_entities(entities: list, target: Entity, source: str, url: str | None):
    for ent in entities:
        roles = ent.get("roles", [])
        card = _vcard(ent)
        role = "/".join(roles) or "contact"
        for field, label in (("fn", "name"), ("org", "organisation"), ("email", "email"), ("tel", "phone"), ("adr", "address")):
            val = card.get(field)
            if not val or REDACTED.search(val):
                continue
            pivots = []
            if field == "email":
                pivots = [Entity("email", val.removeprefix("mailto:").lower())]
            elif field == "tel":
                pivots = [Entity("phone", val.removeprefix("tel:"))]
            elif field == "org" and "registrant" in roles:
                pivots = [Entity("company", val)]
            yield Finding(category="registration", title=f"{role.capitalize()} {label}", value=val,
                          source=source, target=target, confidence=0.9 if "registrar" not in roles else 0.97,
                          url=url, pivots=pivots if "registrar" not in roles and "abuse" not in roles else [])
        yield from _rdap_entities(ent.get("entities", []), target, source, url)


class SubdomainSource(Source):
    """Passive subdomain enumeration from several datasets, merged and cross-confirmed."""

    name = "subdomains"
    kinds = ("domain",)
    description = ("Passive subdomain discovery merged from crt.sh, CertSpotter, HackerTarget, subdomain.center, "
                   "urlscan.io, RapidDNS and AlienVault OTX (with otx_api_key), then resolved to find live hosts")

    async def search(self, entity: Entity, ctx: Context):
        domain = entity.value
        providers = {
            "crt.sh": self._crtsh, "certspotter": self._certspotter, "hackertarget": self._hackertarget,
            "subdomain.center": self._subcenter, "urlscan": self._urlscan, "rapiddns": self._rapiddns,
        }
        if ctx.config.get("otx_api_key"):
            providers["alienvault"] = self._otx
        total, done = len(providers), 0
        ctx.progress(self.name, entity, 0, total)
        found: dict[str, set[str]] = {}

        async def run(pname, fn):
            try:
                return pname, await fn(domain, ctx)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                ctx.log(f"subdomains/{pname}: {exc.__class__.__name__}", "warning")
                return pname, set()

        for fut in asyncio.as_completed([run(n, f) for n, f in providers.items()]):
            pname, names = await fut
            done += 1
            ctx.progress(self.name, entity, done, total)
            for n in names:
                n = n.strip().lower().lstrip("*.").rstrip(".")
                if n.endswith("." + domain) and re.fullmatch(r"[a-z0-9.\-_]+", n):
                    found.setdefault(n, set()).add(pname)

        ctx.log(f"subdomains: {len(found)} unique subdomains of {domain} from {total} datasets")
        ranked = sorted(found.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        if len(ranked) > ctx.options.max_subdomains:
            ctx.log(f"subdomains: showing top {ctx.options.max_subdomains}", "warning")
            ranked = ranked[: ctx.options.max_subdomains]
        resolved: dict[str, list[str]] = {}
        if ctx.options.active_dns and ranked:
            from panoptes.sources.recon import resolve_many
            resolved = await resolve_many([n for n, _ in ranked[:1000]], ctx)
            ctx.log(f"subdomains: {sum(1 for v in resolved.values() if v)} of {len(resolved)} resolve (live)")
        for name, srcs in ranked:
            ips = resolved.get(name)
            data = {"datasets": sorted(srcs)}
            if name in resolved:
                data.update(live=bool(ips), ips=ips)
            yield Finding(category="subdomain", title=name, value=name, source=self.name, target=entity,
                          sources=srcs, confidence=1 - 0.4 ** len(srcs), data=data)

    async def _crtsh(self, domain, ctx):
        for attempt in range(3):  # crt.sh is frequently overloaded; it usually answers on a retry
            r = await ctx.client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=60)
            if r.status_code < 500:
                break
            await asyncio.sleep(3 * (attempt + 1))
        r.raise_for_status()
        return {n for row in r.json() for n in row.get("name_value", "").split("\n")}

    async def _certspotter(self, domain, ctx):
        r = await ctx.get("https://api.certspotter.com/v1/issuances",
                          params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
        r.raise_for_status()
        return {n for row in r.json() for n in row.get("dns_names", [])}

    async def _hackertarget(self, domain, ctx):
        r = await ctx.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
        if "API count exceeded" in r.text or "error" in r.text[:50].lower():
            return set()
        return {line.split(",")[0] for line in r.text.splitlines() if "," in line}

    async def _otx(self, domain, ctx):
        r = await ctx.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                          headers={"X-OTX-API-KEY": ctx.config.get("otx_api_key")})
        r.raise_for_status()
        return {row.get("hostname", "") for row in r.json().get("passive_dns", [])}

    async def _subcenter(self, domain, ctx):
        r = await ctx.get("https://api.subdomain.center/", params={"domain": domain}, timeout=45)
        r.raise_for_status()
        data = r.json()
        return set(data) if isinstance(data, list) else set()

    async def _rapiddns(self, domain, ctx):
        r = await ctx.get(f"https://rapiddns.io/subdomain/{domain}", params={"full": 1}, timeout=45)
        r.raise_for_status()
        return set(re.findall(r"[a-z0-9][a-z0-9.\-]*\." + re.escape(domain), r.text.lower()))

    async def _urlscan(self, domain, ctx):
        r = await ctx.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 1000})
        r.raise_for_status()
        out = set()
        for row in r.json().get("results", []):
            for part in ("page", "task"):
                d = (row.get(part) or {}).get("domain")
                if d:
                    out.add(d)
        return out


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (signed), as used by Shodan for favicon hashes."""
    c1, c2, h, n = 0xcc9e2d51, 0x1b873593, seed, len(data)
    rot = lambda x, r: ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF
    for i in range(n // 4):
        k = int.from_bytes(data[4 * i:4 * i + 4], "little")
        k = rot((k * c1) & 0xFFFFFFFF, 15) * c2 & 0xFFFFFFFF
        h = (rot(h ^ k, 13) * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail, k = data[n // 4 * 4:], 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        h ^= rot((k * c1) & 0xFFFFFFFF, 15) * c2 & 0xFFFFFFFF
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


TECH_HINTS = {
    "wp-content": "WordPress", "Shopify.theme": "Shopify", "cdn.shopify": "Shopify", "__NEXT_DATA__": "Next.js",
    "data-reactroot": "React", "ng-version": "Angular", "Drupal.settings": "Drupal", "Joomla": "Joomla",
    "squarespace": "Squarespace", "wix.com": "Wix", "ghost-": "Ghost", "gtag(": "Google Analytics",
    "googletagmanager": "Google Tag Manager", "cloudflare": "Cloudflare", "hs-scripts": "HubSpot",
    "cdn.jsdelivr": "jsDelivr", "jquery": "jQuery", "bootstrap": "Bootstrap", "webflow": "Webflow",
}


class WebsiteSource(Source):
    name = "website"
    kinds = ("domain",)
    description = "Homepage fingerprint: title, server, technologies, emails, linked social profiles, security.txt"

    async def search(self, entity: Entity, ctx: Context):
        domain = entity.value
        r = None
        for scheme in ("https", "http"):
            try:
                r = await ctx.get(f"{scheme}://{domain}/", timeout=ctx.options.timeout)
                break
            except httpx.HTTPError:
                continue
        if r is None:
            return
        url = str(r.url)
        base = dict(source=self.name, target=entity, url=url)
        html = r.text[:2_000_000]
        yield Finding(category="web", title="HTTP status", value=f"{r.status_code} at {url}", confidence=0.99, **base)
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m and m.group(1).strip():
            yield Finding(category="web", title="Page title", value=re.sub(r"\s+", " ", m.group(1)).strip()[:300],
                          confidence=0.99, **base)
        for h in ("server", "x-powered-by", "x-generator", "via"):
            if r.headers.get(h):
                yield Finding(category="web", title=f"Header {h}", value=r.headers[h], confidence=0.95, **base)
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
        techs = {name for needle, name in TECH_HINTS.items() if needle.lower() in html.lower()}
        if gen:
            techs.add(gen.group(1))
        if techs:
            yield Finding(category="web", title="Technologies", value=", ".join(sorted(techs)), confidence=0.7, **base)
        from panoptes.sources.darkweb import find_trackers
        for label, ids in find_trackers(html).items():
            for tid in sorted(ids):
                yield Finding(category="web", title=f"Tracking ID: {label}", value=tid, confidence=0.95,
                              data={"note": "the same ID on another site usually means the same owner"}, **base)
        icon = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)', html, re.I)
        icon_url = str(r.url.join(icon.group(1))) if icon else f"{r.url.scheme}://{r.url.host}/favicon.ico"
        try:
            ir = await ctx.get(icon_url, timeout=10)
            if ir.status_code == 200 and ir.content and len(ir.content) < 500_000:
                import base64 as _b64
                h = mmh3_32(_b64.encodebytes(ir.content))
                q = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
                yield Finding(category="web", title="Favicon hash (Shodan)", value=str(h), confidence=0.9,
                              data={"note": "search it on Shodan/FOFA to find other servers - often the origin behind a CDN"},
                              **{**base, "url": q})
        except httpx.HTTPError:
            pass
        for email in sorted(extract_emails(html)):
            yield Finding(category="email", title="Email on website", value=email, confidence=0.8,
                          pivots=[Entity("email", email)], **base)
        handles = set()
        for link in re.findall(r'href=["\']([^"\']+)["\']', html):
            h = social_handle(link)
            if h:
                handles.add((link.split("?")[0], h))
        for link, h in sorted(handles):
            yield Finding(category="profile", title="Linked social profile", value=link, confidence=0.8,
                          pivots=[Entity("username", h)], **{**base, "url": link})
        try:
            sec = await ctx.get(f"https://{domain}/.well-known/security.txt")
            if sec.status_code == 200 and "contact:" in sec.text.lower():
                for line in sec.text.splitlines():
                    if line.lower().startswith("contact:"):
                        yield Finding(category="web", title="security.txt contact", value=line[8:].strip(),
                                      confidence=0.9, **{**base, "url": str(sec.url)})
        except httpx.HTTPError:
            pass


class WaybackSource(Source):
    name = "wayback"
    kinds = ("domain",)
    description = "Internet Archive history: first and latest snapshots"

    async def search(self, entity: Entity, ctx: Context):
        api = "https://web.archive.org/cdx/search/cdx"
        base = dict(source=self.name, target=entity, confidence=0.95)
        for title, limit in (("First archived", 1), ("Last archived", -1)):
            try:
                r = await ctx.get(api, params={"url": entity.value, "output": "json", "limit": limit,
                                               "fl": "timestamp,original", "filter": "statuscode:200"}, timeout=40)
                rows = r.json() if r.status_code == 200 and r.text.strip() else []
            except (httpx.HTTPError, ValueError):
                continue
            if len(rows) > 1:
                ts, original = rows[1]
                when = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                link = f"https://web.archive.org/web/{ts}/{original}"
                yield Finding(category="archive", title=title, value=when, url=link, **base)
