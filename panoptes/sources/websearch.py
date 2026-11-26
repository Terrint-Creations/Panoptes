"""Search engines, news and public records - what an investigator would google.

  * Web search (Bing): exact-phrase queries plus targeted dorks per target type - social profiles,
    documents, news, and government / public-sector sites (country-aware when the country is known).
  * News: Google News and GDELT (worldwide news, including local outlets).
  * Public records: Wikipedia, ORCID and OpenAlex (academics), Interpol red notices, FBI wanted list,
    US FEC political donations (name, city, employer).
Name results are name *matches*: they're scored lower and corroborated by the cooperative cross-check
when they mention something already known about the subject.
"""
from __future__ import annotations

import asyncio
import html as htmlmod
import re
import time
from urllib.parse import quote_plus, urlparse
from xml.etree import ElementTree as ET

import httpx

from panoptes.detect import social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, extract_emails

WIKI_HEADERS = {"User-Agent": "PanoptesOSINT/0.4 (https://github.com/panoptes-osint/panoptes) python-httpx"}
GOV_SITES = {
    "": "site:gov OR site:gov.uk OR site:gouv.fr OR site:gc.ca OR site:gov.au OR site:bund.de OR site:europa.eu",
    "IS": "site:island.is OR site:stjornarradid.is OR site:althingi.is OR site:reykjavik.is OR site:gov.is",
    "GB": "site:gov.uk OR site:parliament.uk", "US": "site:gov OR site:courts.gov OR site:state.us",
    "DE": "site:bund.de OR site:bundestag.de", "FR": "site:gouv.fr", "CA": "site:gc.ca OR site:canada.ca",
    "AU": "site:gov.au", "NO": "site:regjeringen.no OR site:stortinget.no", "SE": "site:regeringen.se OR site:riksdagen.se",
    "DK": "site:ft.dk OR site:borger.dk", "FI": "site:valtioneuvosto.fi OR site:eduskunta.fi", "NL": "site:overheid.nl",
}


async def web_search(ctx: Context, query: str) -> list[dict]:
    """Best available engine: Brave / Google Programmable Search / SerpAPI with a key, else Bing's free RSS."""
    cfg = ctx.config
    try:
        if cfg.get("brave_api_key"):
            d = await ctx.get_json("https://api.search.brave.com/res/v1/web/search", params={"q": query, "count": 20},
                                   headers={"X-Subscription-Token": cfg.get("brave_api_key"), "Accept": "application/json"})
            return [{"title": x.get("title", ""), "url": x.get("url", ""), "engine": "brave",
                     "snippet": re.sub(r"<[^>]+>", "", x.get("description", ""))} for x in (d.get("web") or {}).get("results", [])]
        if cfg.get("google_cse_key") and cfg.get("google_cse_cx"):
            d = await ctx.get_json("https://www.googleapis.com/customsearch/v1",
                                   params={"key": cfg.get("google_cse_key"), "cx": cfg.get("google_cse_cx"), "q": query})
            return [{"title": x.get("title", ""), "url": x.get("link", ""), "snippet": x.get("snippet", ""), "engine": "google"}
                    for x in d.get("items", [])]
        if cfg.get("serpapi_key"):
            d = await ctx.get_json("https://serpapi.com/search.json",
                                   params={"engine": "google", "q": query, "api_key": cfg.get("serpapi_key"), "num": 20})
            return [{"title": x.get("title", ""), "url": x.get("link", ""), "snippet": x.get("snippet", ""), "engine": "google"}
                    for x in d.get("organic_results", [])]
    except (httpx.HTTPError, ValueError) as exc:
        ctx.log(f"web-search: keyed engine failed ({exc.__class__.__name__}) - falling back to Bing", "warning")
    results = await bing(ctx, query)
    for r in results:
        r["engine"] = "bing"
    return results


async def bing(ctx: Context, query: str, count: int = 30) -> list[dict]:
    """Bing's RSS output - no key needed. Serialised and spaced to stay polite."""
    lock = ctx.lock("bing")
    while True:  # queueing behind other entities' searches isn't "idle"
        try:
            await asyncio.wait_for(lock.acquire(), 10)
            break
        except asyncio.TimeoutError:
            ctx.touch()
    try:
        last = ctx.shared.get("bing-last", 0)
        await asyncio.sleep(max(0, 1.2 - (time.monotonic() - last)))
        try:
            r = await ctx.get("https://www.bing.com/search", params={"q": query, "format": "rss", "count": count},
                              timeout=20)
        except httpx.HTTPError:
            return []
        finally:
            ctx.shared["bing-last"] = time.monotonic()
    finally:
        lock.release()
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return []
    out = []
    for item in root.iter("item"):
        out.append({"title": (item.findtext("title") or "").strip(), "url": (item.findtext("link") or "").strip(),
                    "snippet": htmlmod.unescape(re.sub(r"<[^>]+>", "", item.findtext("description") or "")).strip(),
                    "date": item.findtext("pubDate")})
    return out


COUNTRY_LANG = {"IS": "is", "NO": "no", "SE": "sv", "DK": "da", "FI": "fi", "DE": "de", "AT": "de", "FR": "fr",
                "ES": "es", "IT": "it", "PT": "pt-PT", "BR": "pt-BR", "NL": "nl", "PL": "pl", "CZ": "cs", "RU": "ru",
                "UA": "uk", "TR": "tr", "JP": "ja", "KR": "ko", "GB": "en-GB", "IE": "en-IE", "CA": "en-CA", "AU": "en-AU"}


def _ascii(s: str) -> str:
    import unicodedata
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()


def _mentions(text: str, term: str) -> bool:
    t = re.sub(r"\s+", " ", text.lower())
    return term.lower() in t


class WebSearchSource(Source):
    name = "web-search"
    kinds = ("username", "email", "name", "phone", "company")
    option = "websearch"
    description = "Search-engine queries & dorks: exact mentions, social profiles, documents, news and government sites"

    def queries(self, entity: Entity, country: str | None) -> list[tuple[str, str]]:
        v = entity.value
        q = f'"{v}"'
        if entity.kind == "username":
            return [("Web mention", q), ("Social / forum mention",
                    f'{q} (site:reddit.com OR site:x.com OR site:twitter.com OR site:instagram.com OR site:tiktok.com '
                    f'OR site:youtube.com OR site:facebook.com OR site:linkedin.com OR site:discord.com OR site:steamcommunity.com)'),
                    ("Code / paste mention", f'{q} (site:github.com OR site:gitlab.com OR site:pastebin.com OR site:gist.github.com)')]
        if entity.kind == "email":
            return [("Web mention", q), ("Document mention", f"{q} (filetype:pdf OR filetype:doc OR filetype:xls OR filetype:txt)")]
        if entity.kind == "phone":
            return [("Web mention", q)]
        gov = GOV_SITES.get(country or "", GOV_SITES[""])
        out = [("Web mention", q), ("Social profile", f"{q} (site:linkedin.com OR site:facebook.com OR site:instagram.com "
                                                      f"OR site:x.com OR site:tiktok.com)"),
               ("Government / public sector", f"{q} ({gov})"),
               ("Document", f"{q} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xlsx)")]
        if country:
            out.append(("Local web", f"{q} site:.{country.lower()}"))
        if _ascii(v) != v:
            out.append(("Web mention (no accents)", f'"{_ascii(v)}"'))
        return out

    async def search(self, entity: Entity, ctx: Context):
        if ctx.report and str(entity) in ctx.report.meta.get("speculative", []):
            return  # don't spend search-engine quota on guessed leads
        country = ctx.knowledge.country_code() if ctx.knowledge else None
        if not country and ctx.shared.get("likely-country"):
            country = ctx.shared["likely-country"]
        seen, empty = set(), 0
        queries = self.queries(entity, country)
        for label, query in queries:
            results = await web_search(ctx, query)
            ctx.touch()
            empty += not results
            if not results and label == "Web mention" and not ctx.shared.get("search-throttle-warned"):
                ctx.shared["search-throttle-warned"] = True
                ctx.log("web-search: the free search engine returned nothing (it may be throttling) - add a free "
                        "brave_api_key in Settings for reliable search-engine results", "warning")
            for res in results:
                url = res["url"]
                if not url or url in seen:
                    continue
                seen.add(url)
                text = f"{res['title']} {res['snippet']}"
                exact = _mentions(text, entity.value) or _mentions(url, entity.value.replace(" ", ""))
                if not exact:
                    continue  # engines silently drop quotes when throttled - a result without the term is noise
                handle = social_handle(url)
                piv = [Entity("username", handle)] if handle and handle.lower() != entity.value.lower() and entity.kind != "name" else []
                piv += [Entity("email", e) for e in extract_emails(text) if e != entity.value.lower()][:3]
                yield Finding(category="web", title=label, value=url, url=url, source=self.name, target=entity,
                              sources={res.get("engine", "web")},
                              confidence=(0.6 if entity.kind in ("username", "email", "phone") else 0.5) if exact else 0.35,
                              data={"page_title": res["title"], "snippet": res["snippet"][:400], "query": query,
                                    "site": urlparse(url).hostname, "date": res.get("date")},
                              pivots=piv if exact else [])


class NewsSource(Source):
    name = "news"
    kinds = ("name", "company")
    option = "websearch"
    description = "News coverage: Google News and GDELT worldwide news index"

    async def search(self, entity: Entity, ctx: Context):
        if ctx.report and str(entity) in ctx.report.meta.get("speculative", []):
            return
        q = f'"{entity.value}"'
        seen = set()
        country = (ctx.knowledge.country_code() if ctx.knowledge else None) or ctx.shared.get("likely-country")
        editions = [("en-US", "US", "US:en")]
        if country and country != "US":
            lang = COUNTRY_LANG.get(country, "en")
            editions.insert(0, (f"{lang}", country, f"{country}:{lang}"))   # local press first
        variants = list(dict.fromkeys([entity.value, _ascii(entity.value)]))
        for hl, gl, ceid in editions:
            for v in variants:
                try:
                    r = await ctx.get("https://news.google.com/rss/search", params={"q": f'"{v}"', "hl": hl, "gl": gl, "ceid": ceid})
                    root = ET.fromstring(r.text)
                except (httpx.HTTPError, ET.ParseError):
                    continue
                for item in list(root.iter("item"))[:25]:
                    link, title = item.findtext("link"), item.findtext("title") or ""
                    text = title + (item.findtext("description") or "")
                    if link and link not in seen and (_mentions(text, entity.value) or _mentions(_ascii(text), _ascii(entity.value))):
                        seen.add(link)
                        yield Finding(category="news", title=f"News: {item.findtext('source') or 'article'}", value=title[:300],
                                      url=link, source=self.name, target=entity, confidence=0.55,
                                      data={"date": item.findtext("pubDate"), "engine": f"Google News ({gl})",
                                            "note": "name match - confirm it's the same person"})
        async with ctx.lock("gdelt"):  # GDELT allows one request every 5 seconds
            try:
                r = await ctx.get("https://api.gdeltproject.org/api/v2/doc/doc", headers=API_HEADERS,
                                  params={"query": q, "mode": "artlist", "format": "json", "maxrecords": 30, "sort": "datedesc"})
                arts = r.json().get("articles", []) if r.status_code == 200 else []
            except (httpx.HTTPError, ValueError):
                arts = []
            await asyncio.sleep(5.2)
        for a in arts:
            if a.get("url") in seen:
                continue
            seen.add(a.get("url"))
            yield Finding(category="news", title=f"News: {a.get('domain')}", value=a.get("title", "")[:300], url=a.get("url"),
                          source=self.name, target=entity, confidence=0.5,
                          data={"date": a.get("seendate"), "language": a.get("language"), "country": a.get("sourcecountry"),
                                "engine": "GDELT", "note": "name match - confirm it's the same person"})


class PublicRecordsSource(Source):
    name = "public-records"
    kinds = ("name",)
    option = "websearch"
    description = "Wikipedia, ORCID, OpenAlex (academic), Interpol red notices, FBI wanted, US FEC political donations"

    async def search(self, entity: Entity, ctx: Context):
        name = entity.value
        parts = name.split()
        jobs = [self._wikipedia(name, entity, ctx), self._orcid(parts, entity, ctx), self._openalex(name, entity, ctx),
                self._interpol(parts, entity, ctx), self._fbi(name, entity, ctx), self._fec(name, entity, ctx)]
        for fut in asyncio.as_completed(jobs):
            try:
                for f in await fut:
                    yield f
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                continue

    def _f(self, entity, category, title, value, url, conf, **data):
        return Finding(category=category, title=title, value=str(value)[:600], url=url, source=self.name, target=entity,
                       confidence=conf, data={k: v for k, v in data.items() if v not in (None, "", [])})

    async def _wikipedia(self, name, e, ctx):
        r = await ctx.get("https://en.wikipedia.org/w/api.php", headers=WIKI_HEADERS, params={
            "action": "query", "list": "search", "srsearch": f'"{name}"', "format": "json", "srlimit": 5})
        out = []
        for hit in r.json().get("query", {}).get("search", []):
            exact = hit["title"].lower() == name.lower()
            snippet = htmlmod.unescape(re.sub(r"<[^>]+>", "", hit.get("snippet", "")))
            out.append(self._f(e, "record", "Wikipedia article" if exact else "Wikipedia mention", hit["title"],
                               f"https://en.wikipedia.org/wiki/{quote_plus(hit['title'].replace(' ', '_'))}",
                               0.7 if exact else 0.45, snippet=snippet))
        return out

    async def _orcid(self, parts, e, ctx):
        if len(parts) < 2:
            return []
        r = await ctx.get("https://pub.orcid.org/v3.0/expanded-search/", headers={**API_HEADERS, "Accept": "application/json"},
                          params={"q": f"given-names:{parts[0]} AND family-name:{parts[-1]}", "rows": 5})
        out = []
        for x in r.json().get("expanded-result") or []:
            inst = ", ".join(x.get("institution-name") or [])
            out.append(self._f(e, "record", "ORCID researcher", f"{x.get('given-names')} {x.get('family-names')}"
                               + (f" - {inst}" if inst else ""), f"https://orcid.org/{x['orcid-id']}", 0.5,
                               emails=x.get("email"), note="name match"))
        return out

    async def _openalex(self, name, e, ctx):
        r = await ctx.get("https://api.openalex.org/authors", params={"search": name, "per-page": 5}, headers=API_HEADERS)
        out = []
        for a in r.json().get("results", []):
            if a.get("display_name", "").lower() != name.lower():
                continue
            inst = ", ".join(i.get("display_name", "") for i in (a.get("last_known_institutions") or [])[:2])
            out.append(self._f(e, "record", "Academic author (OpenAlex)", f"{a['display_name']} - {a.get('works_count')} works"
                               + (f", {inst}" if inst else ""), a.get("id"), 0.5, note="name match"))
        return out

    async def _interpol(self, parts, e, ctx):
        if len(parts) < 2:
            return []
        r = await ctx.get("https://ws-public.interpol.int/notices/v1/red", headers=API_HEADERS,
                          params={"forename": parts[0], "name": parts[-1], "resultPerPage": 20})
        out = []
        for n in r.json().get("_embedded", {}).get("notices", []):
            full = f"{n.get('forename', '')} {n.get('name', '')}".strip()
            out.append(self._f(e, "threat", "Interpol red notice (name match)", f"{full} - born {n.get('date_of_birth')}, "
                               f"{', '.join(n.get('nationalities') or [])}", n.get("_links", {}).get("self", {}).get("href"),
                               0.6, severity="high", note="name match only - compare birth date and nationality"))
        return out

    async def _fbi(self, name, e, ctx):
        r = await ctx.get("https://api.fbi.gov/wanted/v1/list", params={"title": name, "pageSize": 10}, headers=API_HEADERS)
        out = []
        for it in r.json().get("items", []):
            if name.lower() in (it.get("title") or "").lower():
                out.append(self._f(e, "threat", "FBI wanted list (name match)", it.get("title"), it.get("url"), 0.6,
                                   severity="high", subjects=it.get("subjects")))
        return out

    async def _fec(self, name, e, ctx):
        parts = name.split()
        if len(parts) < 2:
            return []
        r = await ctx.get("https://api.open.fec.gov/v1/schedules/schedule_a/", headers=API_HEADERS, params={
            "api_key": "DEMO_KEY", "contributor_name": f"{parts[-1]}, {parts[0]}", "per_page": 10, "sort": "-contribution_receipt_date"})
        out = []
        for x in r.json().get("results", []):
            loc = ", ".join(p for p in (x.get("contributor_city"), x.get("contributor_state")) if p)
            out.append(self._f(e, "record", "US political donation (FEC)",
                               f"{x.get('contributor_name')} → {x.get('committee', {}).get('name', '?')} "
                               f"${x.get('contribution_receipt_amount')} ({(x.get('contribution_receipt_date') or '')[:10]})",
                               "https://www.fec.gov/data/receipts/individual-contributions/", 0.5,
                               location=loc, employer=x.get("contributor_employer"), occupation=x.get("contributor_occupation"),
                               note="name match - location/employer help confirm"))
        return out
