"""Dark web (OnionScan capabilities + onion search).

  * Ahmia index search (clearnet, no Tor needed): does a username / email / domain / wallet / name
    appear on indexed .onion sites?
  * OnionScan-style audit of a .onion service through your Tor SOCKS proxy: server banner leaks,
    exposed Apache status pages, open directories, clearnet resources that can deanonymise the
    operator, analytics/tracking IDs, emails, crypto wallets and PGP keys found on the site.
"""
from __future__ import annotations

import asyncio
import html as htmlmod
import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import USER_AGENT, Context, Source, extract_emails

BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ONION = re.compile(r"\b([a-z2-7]{56}|[a-z2-7]{16})\.onion\b")
TRACKERS = {
    "Google Analytics (UA)": re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "Google Analytics 4": re.compile(r"\bG-[A-Z0-9]{8,12}\b"),
    "Google Tag Manager": re.compile(r"\bGTM-[A-Z0-9]{5,8}\b"),
    "Google AdSense": re.compile(r"\bca-pub-\d{10,20}\b"),
    "Facebook Pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
    "Yandex Metrica": re.compile(r"ym\(\s*(\d{6,10})\s*,\s*['\"]init"),
}


def find_trackers(page: str) -> dict[str, set[str]]:
    out = {}
    for label, rx in TRACKERS.items():
        hits = set(rx.findall(page))
        if hits:
            out[label] = hits
    return out


class AhmiaSource(Source):
    name = "darkweb-index"
    kinds = ("username", "email", "domain", "name", "crypto", "company")
    description = "Searches the Ahmia .onion index (clearnet) for dark-web pages mentioning the target"
    option = "darkweb"

    async def _token(self, ctx: Context):
        try:
            r = await ctx.get("https://ahmia.fi/")
            m = re.search(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]+)"', r.text)
            return (m.group(1), m.group(2)) if m else None
        except httpx.HTTPError:
            return None

    async def search(self, entity: Entity, ctx: Context):
        if entity.kind == "username" and len(entity.value) < 5:
            return  # short handles match too much noise
        token = await ctx.once("ahmia-token", lambda: self._token(ctx))
        params = {"q": f'"{entity.value}"' if " " in entity.value else entity.value}
        if token:
            params[token[0]] = token[1]
        try:
            r = await ctx.get("https://ahmia.fi/search/", params=params, timeout=30)
        except httpx.HTTPError:
            return
        blocks = re.findall(r'<li class="result">(.*?)</li>', r.text, re.S)
        needle = entity.value.lower()
        seen = set()
        fuzzy = 0
        for b in blocks[:30]:
            link = re.search(r'href="([^"]+)"', b)
            title = re.search(r"<a[^>]*>(.*?)</a>", b, re.S)
            desc = re.search(r"<p>(.*?)</p>", b, re.S)
            cite = re.search(r"<cite>([^<]+)</cite>", b)
            target = cite.group(1).strip() if cite else ""
            if link and "redirect_url=" in link.group(1):
                target = parse_qs(urlparse(htmlmod.unescape(link.group(1))).query).get("redirect_url", [target])[0]
            if not target or target in seen:
                continue
            seen.add(target)
            text = htmlmod.unescape(re.sub(r"<[^>]+>", " ", (title.group(1) if title else "") + " " + (desc.group(1) if desc else "")))
            exact = needle in text.lower()
            if not exact:
                continue  # the index matches loosely ("gmail" alone) - only exact mentions mean anything
            yield Finding(category="darkweb", title="Mentioned on dark-web page", value=target, source=self.name,
                          target=entity, confidence=0.7 if exact else 0.45,
                          data={"page_title": re.sub(r"\s+", " ", text).strip()[:300], "exact_match": exact,
                                "note": "Open only through Tor"})


ONION_ENGINES = {
    "Torch": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P={q}",
    "Haystak": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}",
    "Ahmia (onion)": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={q}",
}


class OnionSearchSource(Source):
    """Searches dark-web search engines over Tor (Panoptes starts its own Tor if none is running)."""

    name = "darkweb-search"
    kinds = ("username", "email", "domain", "name", "crypto")
    option = "darkweb"
    description = "Searches Torch, Haystak and Ahmia's onion service through Tor for the target (built-in Tor, no setup)"

    async def search(self, entity: Entity, ctx: Context):
        if entity.kind == "username" and len(entity.value) < 5:
            return
        if ctx.report and str(entity) in ctx.report.meta.get("speculative", []):
            return
        from urllib.parse import quote_plus

        from panoptes.tor import ensure_tor
        proxy = await ensure_tor(ctx)
        if not proxy:
            return
        needle = entity.value.lower()
        seen = set()
        async with httpx.AsyncClient(proxy=proxy, timeout=60, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as tor:
            for engine, template in ONION_ENGINES.items():
                q = quote_plus(f'"{entity.value}"' if " " in entity.value else entity.value)
                try:
                    r = await asyncio.wait_for(tor.get(template.replace("{q}", q)), 90)
                except (httpx.HTTPError, asyncio.TimeoutError):
                    ctx.log(f"darkweb-search: {engine} unreachable right now", "debug")
                    continue
                finally:
                    ctx.touch()
                page = r.text
                for m in re.finditer(r'href="(https?://[a-z2-7]{56}\.onion[^"]*)"[^>]*>(.*?)</a>', page, re.S | re.I):
                    url = htmlmod.unescape(m.group(1))
                    host = urlparse(url).hostname
                    if host in seen or host in template:
                        continue
                    seen.add(host)
                    around = re.sub(r"<[^>]+>", " ", page[max(0, m.start() - 300): m.end() + 500])
                    text = htmlmod.unescape(re.sub(r"\s+", " ", around)).strip()
                    exact = needle in text.lower()
                    if not exact:
                        continue
                    yield Finding(category="darkweb", title=f"Dark-web result ({engine})", value=url, source=self.name,
                                  sources={engine}, target=entity, confidence=0.7,
                                  data={"context": text[:300], "exact_match": True, "note": "Open only through Tor"})


class OnionScanSource(Source):
    name = "onionscan"
    kinds = ("onion",)
    description = "OnionScan-style audit of a .onion site via Tor: leaks, misconfigurations, linked identities (built-in Tor)"

    async def search(self, entity: Entity, ctx: Context):
        from panoptes.tor import ensure_tor
        proxy = await ensure_tor(ctx)
        if not proxy:
            ctx.log("onionscan: Tor isn't available", "warning")
            return
        base_url = f"http://{entity.value}/"
        async with httpx.AsyncClient(proxy=proxy, timeout=60, follow_redirects=True,
                                     headers={"User-Agent": USER_AGENT}) as tor:
            try:
                r = await tor.get(base_url)
            except httpx.HTTPError as exc:
                ctx.log(f"onionscan: {entity.value} unreachable through Tor ({exc.__class__.__name__})", "warning")
                return
            S, e = self.name, entity
            out = [Finding(category="onion", title="Reachable", value=f"HTTP {r.status_code}", source=S, target=e, confidence=0.99)]
            page = r.text[:2_000_000]
            title = re.search(r"<title[^>]*>(.*?)</title>", page, re.S | re.I)
            if title:
                out.append(Finding(category="onion", title="Page title", value=htmlmod.unescape(title.group(1)).strip()[:200],
                                   source=S, target=e, confidence=0.99))
            for h in ("server", "x-powered-by", "x-generator", "via", "x-aspnet-version"):
                if r.headers.get(h):
                    out.append(Finding(category="onion", title=f"Header {h}", value=r.headers[h], source=S, target=e,
                                       confidence=0.95, data={"severity": "low", "note": "version banners narrow down the host"}))
            checks = {"/server-status": ("Apache mod_status exposed", "high", "Apache Status"),
                      "/server-info": ("Apache mod_info exposed", "high", "Apache Server Information"),
                      "/.git/HEAD": ("Exposed .git repository", "high", "ref:"),
                      "/phpinfo.php": ("phpinfo() exposed", "high", "PHP Version"),
                      "/robots.txt": ("robots.txt", "info", "isallow"),
                      "/images/": ("Open directory listing", "medium", "Index of /"),
                      "/uploads/": ("Open directory listing", "medium", "Index of /")}
            for path, (label, sev, marker) in checks.items():
                try:
                    rr = await tor.get(urljoin(base_url, path))
                except httpx.HTTPError:
                    continue
                if rr.status_code == 200 and marker in rr.text:
                    out.append(Finding(category="onion", title=label, value=urljoin(base_url, path), source=S, target=e,
                                       confidence=0.9, data={"severity": sev}))
                    if path == "/server-status":
                        ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", rr.text)) - {"127.0.0.1"}
                        for ip in sorted(ips)[:10]:
                            out.append(Finding(category="threat", title="IP leaked by server-status", value=ip, source=S,
                                               target=e, confidence=0.8, pivots=[Entity("ip", ip)], data={"severity": "high"}))
            clearnet = set()
            for src in re.findall(r'(?:src|href)=["\'](https?://[^"\']+)', page):
                host = (urlparse(src).hostname or "").lower()
                if host and not host.endswith(".onion"):
                    clearnet.add(host)
            for host in sorted(clearnet)[:20]:
                out.append(Finding(category="onion", title="Clearnet resource/link", value=host, source=S, target=e,
                                   confidence=0.8, data={"severity": "medium",
                                                         "note": "loading clearnet resources can leak visitors or the operator"}))
            for label, ids in find_trackers(page).items():
                for i in ids:
                    out.append(Finding(category="onion", title=f"Tracking ID: {label}", value=i, source=S, target=e,
                                       confidence=0.95, data={"severity": "high",
                                                              "note": "the same ID on a clearnet site identifies the operator"}))
            for em in sorted(extract_emails(page))[:20]:
                out.append(Finding(category="email", title="Email on onion site", value=em, source=S, target=e,
                                   confidence=0.85, pivots=[Entity("email", em)]))
            for rx, coin in ((BTC, "Bitcoin"), (ETH, "Ethereum"), (XMR, "Monero")):
                for w in sorted(set(rx.findall(page)))[:10]:
                    out.append(Finding(category="wallet", title=f"{coin} address on site", value=w, source=S, target=e,
                                       confidence=0.8, pivots=[Entity("crypto", w)] if coin != "Monero" else []))
            if "BEGIN PGP PUBLIC KEY" in page:
                out.append(Finding(category="key", title="PGP public key published", value="yes", source=S, target=e,
                                   confidence=0.9))
            for other in sorted(set(ONION.findall(page)) - {entity.value.removesuffix(".onion")})[:25]:
                out.append(Finding(category="onion", title="Linked onion service", value=f"{other}.onion", source=S,
                                   target=e, confidence=0.8, pivots=[Entity("onion", f"{other}.onion")]))
            for f in out:
                yield f
