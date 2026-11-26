"""Domain harvesting (theHarvester / Photon / Metagoofil capabilities).

Crawls the organisation's website collecting emails, phone numbers, people, social profiles
and internal hostnames, downloads published documents to mine their metadata for author
names and usernames, and asks PGP keyservers for every published key on the domain.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from panoptes.detect import social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source, extract_emails
from panoptes.sources.files import analyze, metadata_findings

DOC_EXT = (".pdf", ".docx", ".xlsx", ".pptx")
SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".mp4", ".mp3", ".zip",
            ".woff", ".woff2", ".ttf", ".xml", ".json", ".rss") + DOC_EXT
HREF = re.compile(r'(?:href|src)=["\']([^"\'#]+)', re.I)
TEL = re.compile(r'href=["\']tel:([+\d\s().\-]{7,25})["\']', re.I)


def _same_site(host: str, domain: str) -> bool:
    host = (host or "").lower()
    return host == domain or host.endswith("." + domain)


class HarvesterSource(Source):
    name = "harvester"
    kinds = ("domain",)
    description = ("Crawls the website for emails, phones, social profiles, hostnames and documents; mines "
                   "document metadata for author names; harvests PGP-key emails on the domain")

    async def search(self, entity: Entity, ctx: Context):
        domain = entity.value
        pgp, crawl = await asyncio.gather(self._pgp(domain, ctx), self._crawl(domain, entity, ctx))
        for f in pgp + crawl:
            yield f
        for f in await self._documents(entity, ctx):
            yield f

    async def _pgp(self, domain: str, ctx: Context) -> list[Finding]:
        entity = Entity("domain", domain)
        try:
            r = await ctx.get("https://keyserver.ubuntu.com/pks/lookup",
                              params={"search": f"@{domain}", "op": "index", "options": "mr"}, timeout=40)
        except httpx.HTTPError:
            return []
        out, seen = [], set()
        for line in r.text.splitlines() if r.status_code == 200 else []:
            if not line.startswith("uid:"):
                continue
            uid = httpx.QueryParams(f"u={line.split(':')[1]}")["u"]
            for email in extract_emails(uid):
                if email.endswith("@" + domain) and email not in seen:
                    seen.add(email)
                    name = re.sub(r"\s*[<(].*$", "", uid).strip()
                    piv = [Entity("email", email)] + ([Entity("name", name)] if name and "@" not in name else [])
                    out.append(Finding(category="email", title="Email on PGP keyserver", value=email, source=self.name,
                                       target=entity, confidence=0.85, data={"uid": uid}, pivots=piv))
        return out

    async def _crawl(self, domain: str, entity: Entity, ctx: Context) -> list[Finding]:
        limit = ctx.options.crawl_pages
        start = [f"https://{domain}/", f"https://www.{domain}/"]
        queue, seen, out = list(start), set(start), []
        emails: dict[str, str] = {}
        phones: dict[str, str] = {}
        socials: dict[str, str] = {}
        hosts: set[str] = set()
        docs: dict[str, str] = {}
        pages = 0
        ctx.progress(self.name, entity, 0, limit)
        while queue and pages < limit:
            batch, queue = queue[:8], queue[8:]

            async def get(u):
                try:
                    r = await ctx.get(u, timeout=ctx.options.timeout)
                    ct = r.headers.get("content-type", "")
                    return str(r.url), r.text[:1_500_000] if r.status_code == 200 and "html" in ct else ""
                except httpx.HTTPError:
                    return u, ""

            for url, page in await asyncio.gather(*(get(u) for u in batch)):
                pages += 1
                if not page:
                    continue
                for e in extract_emails(page):
                    emails.setdefault(e, url)
                for t in TEL.findall(page):
                    phones.setdefault(re.sub(r"\s+", " ", t.strip()), url)
                for link in HREF.findall(page):
                    absu = urljoin(url, link.strip())
                    p = urlparse(absu)
                    if p.scheme not in ("http", "https"):
                        continue
                    h = social_handle(absu)
                    if h:
                        socials.setdefault(absu.split("?")[0], h)
                        continue
                    if not _same_site(p.hostname, domain):
                        continue
                    hosts.add(p.hostname.lower())
                    path = p.path.lower()
                    if path.endswith(DOC_EXT):
                        docs.setdefault(absu, url)
                    elif not path.endswith(SKIP_EXT):
                        clean = absu.split("#")[0]
                        if clean not in seen and len(seen) < limit * 6:
                            seen.add(clean)
                            queue.append(clean)
            ctx.progress(self.name, entity, min(pages, limit), limit)

        base = dict(source=self.name, target=entity)
        for e, src in sorted(emails.items()):
            own = e.endswith("@" + domain) or e.endswith("." + domain)
            out.append(Finding(category="email", title="Email on website", value=e, url=src,
                               confidence=0.85 if own else 0.65, pivots=[Entity("email", e)], **base))
        for p, src in phones.items():
            out.append(Finding(category="phone", title="Phone on website", value=p, url=src, confidence=0.8,
                               pivots=[Entity("phone", p)], **base))
        for link, h in sorted(socials.items()):
            out.append(Finding(category="profile", title="Linked social profile", value=link, url=link, confidence=0.8,
                               pivots=[Entity("username", h)], **base))
        for h in sorted(hosts - {domain, f"www.{domain}"}):
            out.append(Finding(category="subdomain", title=h, value=h, sources={"crawl"}, confidence=0.9, **base))
        ctx.shared[f"docs:{domain}"] = docs
        ctx.log(f"harvester: crawled {pages} pages of {domain}: {len(emails)} emails, {len(phones)} phones, "
                f"{len(socials)} social links, {len(docs)} documents")
        return out

    async def _documents(self, entity: Entity, ctx: Context) -> list[Finding]:
        docs = list(ctx.shared.get(f"docs:{entity.value}", {}).items())[:15]
        out: list[Finding] = []

        async def one(url):
            try:
                r = await ctx.get(url, timeout=45)
                if r.status_code != 200 or len(r.content) > 25 * 1024 * 1024:
                    return []
            except httpx.HTTPError:
                return []
            info = await asyncio.to_thread(analyze, r.content, url)
            label = urlparse(url).path.rsplit("/", 1)[-1][:60]
            fs = metadata_findings(info, entity, self.name, url, doc_label=label)
            # keep only what identifies people or tooling - the rest is noise at domain level
            return [f for f in fs if f.category in ("person", "software", "email", "location")]

        for batch in await asyncio.gather(*(one(u) for u, _ in docs)):
            out.extend(batch)
        if docs:
            out.append(Finding(category="web", title="Published documents analysed", value=str(len(docs)),
                               source=self.name, target=entity, confidence=0.9,
                               data={"documents": [u for u, _ in docs]}))
        return out
