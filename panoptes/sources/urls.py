"""Historical URL discovery (gau / waybackurls capabilities).

Pulls every URL ever seen for a domain from the Wayback Machine, Common Crawl and urlscan,
merges them, and surfaces the interesting ones: exposed files, backups, admin panels, API
endpoints and URLs with secrets in their parameters.
"""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source

CLASSES = [
    ("Sensitive file", 0.8, re.compile(r"\.(sql|bak|backup|old|orig|swp|env|ini|conf|config|cfg|log|db|sqlite|"
                                       r"key|pem|p12|pfx|htpasswd|DS_Store|git/config|svn/entries)(\?|$)", re.I)),
    ("Archive", 0.7, re.compile(r"\.(zip|tar|tgz|gz|7z|rar)(\?|$)", re.I)),
    ("Secret in URL", 0.75, re.compile(r"[?&](api[_-]?key|apikey|token|access_token|secret|password|passwd|pwd|"
                                       r"auth|session|sig|signature|private_key)=", re.I)),
    ("Admin / login", 0.6, re.compile(r"/(admin|administrator|wp-admin|wp-login|login|signin|dashboard|cpanel|"
                                      r"phpmyadmin|manager|console|portal)(/|\?|$|\.)", re.I)),
    ("API endpoint", 0.6, re.compile(r"/(api|graphql|rest|v[1-3]|swagger|openapi|api-docs)(/|\?|$|\.)", re.I)),
    ("Document", 0.6, re.compile(r"\.(pdf|docx?|xlsx?|pptx?|csv|odt)(\?|$)", re.I)),
]


class HistoricalURLSource(Source):
    name = "historical-urls"
    kinds = ("domain",)
    description = "Every archived URL (Wayback, Common Crawl, urlscan) classified into exposed files, secrets, admin panels, APIs"

    async def search(self, entity: Entity, ctx: Context):
        d = entity.value
        providers = {"wayback": self._wayback, "commoncrawl": self._commoncrawl, "urlscan": self._urlscan}
        urls: dict[str, set[str]] = {}
        results = await asyncio.gather(*(self._safe(n, f, d, ctx) for n, f in providers.items()))
        for pname, found in results:
            for u in found:
                urls.setdefault(u.split("#")[0], set()).add(pname)
        if not urls:
            return
        hosts: dict[str, set[str]] = {}
        for u, srcs in urls.items():
            h = (urlparse(u).hostname or "").lower()
            if h.endswith("." + d):
                hosts.setdefault(h, set()).update(srcs)
        by_src = {p: sum(1 for s in urls.values() if p in s) for p, _ in results}
        yield Finding(category="url", title="Historical URLs", value=f"{len(urls)} unique URLs",
                      source=self.name, target=entity, confidence=0.95, data={"by_source": by_src})
        shown = 0
        for u, srcs in sorted(urls.items()):
            for label, conf, rx in CLASSES:
                if rx.search(u):
                    if shown < 400:
                        yield Finding(category="url", title=label, value=u, url=u, source=self.name, target=entity,
                                      sources=srcs, confidence=conf)
                        shown += 1
                    break
        for h, srcs in hosts.items():
            yield Finding(category="subdomain", title=h, value=h, source=self.name, target=entity, sources=srcs,
                          confidence=1 - 0.4 ** len(srcs))
        ctx.log(f"historical-urls: {len(urls)} URLs for {d}, {shown} flagged as interesting")

    async def _safe(self, name, fn, d, ctx):
        try:
            return name, await fn(d, ctx)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            ctx.log(f"historical-urls/{name}: {exc.__class__.__name__}", "warning")
            return name, set()

    async def _wayback(self, d, ctx):
        r = await ctx.client.get("https://web.archive.org/cdx/search/cdx",
                                 params={"url": f"*.{d}/*", "output": "json", "fl": "original", "collapse": "urlkey",
                                         "limit": 15000}, timeout=90)
        rows = r.json() if r.text.strip() else []
        return {row[0] for row in rows[1:]}

    async def _commoncrawl(self, d, ctx):
        async def index():
            r = await ctx.get("https://index.commoncrawl.org/collinfo.json", headers=API_HEADERS, timeout=30)
            return r.json()[0]["cdx-api"]
        api = await ctx.once("cc-index", index)
        r = await ctx.client.get(api, params={"url": f"*.{d}", "output": "json", "fl": "url", "limit": 8000},
                                 headers=API_HEADERS, timeout=90)
        out = set()
        for line in r.text.splitlines():
            try:
                out.add(json.loads(line)["url"])
            except (ValueError, KeyError):
                continue
        return out

    async def _urlscan(self, d, ctx):
        r = await ctx.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{d}", "size": 1000},
                          headers=API_HEADERS)
        return {row["page"]["url"] for row in r.json().get("results", []) if row.get("page", {}).get("url")}
