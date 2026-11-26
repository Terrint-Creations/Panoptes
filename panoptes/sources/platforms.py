"""Deep profile parsing for usernames.

Platform APIs that expose bios, real names, locations and - most valuable - links to the
person's *other* accounts (Keybase proofs, Mastodon profile fields, Dev.to GitHub/Twitter links).
Plus an enrichment pass (Blackbird / social-analyzer style) that reads the public metadata of
every account the combined search found.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import html as htmlmod
import re

import httpx

from panoptes.detect import normalize_domain, social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, extract_emails, findings_for

URL_RE = re.compile(r"https?://[^\s\"'<>)]+")


def _strip_html(s: str) -> str:
    return htmlmod.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


def _link_pivots(text: str, own: str) -> list[Entity]:
    """Usernames, emails and personal sites mentioned in free text."""
    piv: list[Entity] = []
    for e in extract_emails(text):
        piv.append(Entity("email", e))
    for url in URL_RE.findall(text or ""):
        h = social_handle(url)
        if h and h.lower() != own.lower():
            piv.append(Entity("username", h))
        elif not h:
            d = normalize_domain(url)
            if d and not any(x in d for x in ("google.", "youtube.", "facebook.", "twitter.", "x.com", "linkedin.",
                                               "instagram.", "github.com", "keybase.", "t.co", "bit.ly")):
                piv.append(Entity("domain", d))
    return list(dict.fromkeys(piv))


class PlatformProfilesSource(Source):
    name = "platform-profiles"
    kinds = ("username",)
    description = "Profile APIs: Keybase (verified proofs), Mastodon, Hacker News, GitLab, Dev.to, Chess.com"

    async def search(self, entity: Entity, ctx: Context):
        jobs = [self._keybase, self._mastodon, self._hn, self._gitlab, self._devto, self._chess]
        results = await asyncio.gather(*(self._safe(j, entity, ctx) for j in jobs))
        for batch in results:
            for f in batch:
                yield f

    async def _safe(self, fn, entity, ctx) -> list[Finding]:
        try:
            return [f async for f in fn(entity, ctx)]
        except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError):
            return []

    def _f(self, entity, title, value, url, conf=0.9, category="profile", pivots=(), **data) -> Finding:
        return Finding(category=category, title=title, value=str(value)[:600], url=url, source=self.name,
                       target=entity, confidence=conf, pivots=list(pivots), data=data)

    async def _keybase(self, entity, ctx):
        r = await ctx.get("https://keybase.io/_/api/1.0/user/lookup.json",
                          params={"usernames": entity.value, "fields": "basics,profile,proofs_summary"}, headers=API_HEADERS)
        them = (r.json().get("them") or [None])[0]
        if not them:
            return
        url = f"https://keybase.io/{them['basics']['username']}"
        yield self._f(entity, "Keybase", url, url, 0.97, "account")
        prof = them.get("profile") or {}
        if prof.get("full_name"):
            yield self._f(entity, "Keybase name", prof["full_name"], url, pivots=[Entity("name", prof["full_name"])])
        if prof.get("location"):
            yield self._f(entity, "Keybase location", prof["location"], url, category="location")
        if prof.get("bio"):
            yield self._f(entity, "Keybase bio", prof["bio"], url, pivots=_link_pivots(prof["bio"], entity.value))
        for proof in (them.get("proofs_summary") or {}).get("all", []):
            ptype, tag = proof.get("proof_type"), proof.get("nametag")
            purl = proof.get("service_url") or proof.get("proof_url")
            piv = []
            if ptype in ("dns", "generic_web_site"):
                piv = [Entity("domain", normalize_domain(tag))]
            elif tag and tag.lower() != entity.value.lower():
                piv = [Entity("username", tag)]
            yield self._f(entity, f"Verified {ptype} (Keybase proof)", tag, purl, 0.97, "account", piv,
                          note="cryptographically proven by the account owner")

    async def _mastodon(self, entity, ctx):
        r = await ctx.get("https://mastodon.social/api/v2/search",
                          params={"q": entity.value, "type": "accounts", "limit": 10, "resolve": "false"}, headers=API_HEADERS)
        for acct in r.json().get("accounts", []):
            if acct.get("username", "").lower() != entity.value.lower():
                continue
            url = acct.get("url")
            yield self._f(entity, f"Mastodon ({acct.get('acct')})", url, url, 0.9, "account",
                          created=acct.get("created_at"), followers=acct.get("followers_count"))
            if acct.get("display_name"):
                yield self._f(entity, "Mastodon display name", acct["display_name"], url, 0.8)
            note = _strip_html(acct.get("note", ""))
            if note:
                yield self._f(entity, "Mastodon bio", note, url, 0.8, pivots=_link_pivots(acct.get("note", ""), entity.value))
            for field in acct.get("fields") or []:
                val = _strip_html(field.get("value", ""))
                yield self._f(entity, f"Mastodon field: {field.get('name')}", val, url,
                              0.9 if field.get("verified_at") else 0.75,
                              pivots=_link_pivots(field.get("value", "") + " " + val, entity.value),
                              verified=bool(field.get("verified_at")))

    async def _hn(self, entity, ctx):
        r = await ctx.get(f"https://hacker-news.firebaseio.com/v0/user/{entity.value}.json", headers=API_HEADERS)
        d = r.json()
        if not d:
            return
        url = f"https://news.ycombinator.com/user?id={d['id']}"
        created = dt.datetime.fromtimestamp(d.get("created", 0), dt.timezone.utc).date().isoformat()
        yield self._f(entity, "Hacker News", url, url, 0.95, "account", karma=d.get("karma"), created=created)
        about = d.get("about")
        if about:
            yield self._f(entity, "Hacker News about", _strip_html(about), url, 0.85,
                          pivots=_link_pivots(htmlmod.unescape(about), entity.value))

    async def _gitlab(self, entity, ctx):
        r = await ctx.get("https://gitlab.com/api/v4/users", params={"username": entity.value}, headers=API_HEADERS)
        users = r.json()
        if not users:
            return
        u = (await ctx.get(f"https://gitlab.com/api/v4/users/{users[0]['id']}", headers=API_HEADERS)).json()
        url = u.get("web_url")
        yield self._f(entity, "GitLab", url, url, 0.97, "account", created=u.get("created_at"))
        if u.get("name"):
            yield self._f(entity, "GitLab name", u["name"], url, 0.85, pivots=[Entity("name", u["name"])])
        for key, label, kind in (("location", "GitLab location", None), ("bio", "GitLab bio", None),
                                 ("public_email", "GitLab public email", "email"), ("website_url", "GitLab website", "site"),
                                 ("twitter", "GitLab Twitter", "username"), ("organization", "GitLab organisation", None),
                                 ("job_title", "GitLab job title", None)):
            v = u.get(key)
            if not v:
                continue
            piv = []
            if kind == "email":
                piv = [Entity("email", v)]
            elif kind == "username":
                piv = [Entity("username", v)]
            elif kind == "site":
                piv = _link_pivots(v if "://" in v else f"https://{v}", entity.value)
            yield self._f(entity, label, v, url, 0.9, "location" if key == "location" else "profile", piv)

    async def _devto(self, entity, ctx):
        r = await ctx.get("https://dev.to/api/users/by_username", params={"url": entity.value}, headers=API_HEADERS)
        if r.status_code != 200:
            return
        u = r.json()
        url = f"https://dev.to/{u['username']}"
        yield self._f(entity, "DEV Community", url, url, 0.97, "account", joined=u.get("joined_at"))
        if u.get("name"):
            yield self._f(entity, "DEV name", u["name"], url, 0.85, pivots=[Entity("name", u["name"])])
        for key, label in (("twitter_username", "DEV linked Twitter"), ("github_username", "DEV linked GitHub")):
            if u.get(key):
                piv = [Entity("username", u[key])] if u[key].lower() != entity.value.lower() else []
                yield self._f(entity, label, u[key], url, 0.95, "account", piv)
        if u.get("location"):
            yield self._f(entity, "DEV location", u["location"], url, 0.85, "location")
        if u.get("summary"):
            yield self._f(entity, "DEV bio", u["summary"], url, 0.8, pivots=_link_pivots(u["summary"], entity.value))
        if u.get("website_url"):
            yield self._f(entity, "DEV website", u["website_url"], u["website_url"], 0.9,
                          pivots=_link_pivots(u["website_url"], entity.value))

    async def _chess(self, entity, ctx):
        r = await ctx.get(f"https://api.chess.com/pub/player/{entity.value.lower()}", headers=API_HEADERS)
        if r.status_code != 200:
            return
        u = r.json()
        url = u.get("url")
        joined = dt.datetime.fromtimestamp(u.get("joined", 0), dt.timezone.utc).date().isoformat()
        last = dt.datetime.fromtimestamp(u.get("last_online", 0), dt.timezone.utc).date().isoformat()
        yield self._f(entity, "Chess.com", url, url, 0.97, "account", joined=joined, last_online=last)
        if u.get("name"):
            yield self._f(entity, "Chess.com name", u["name"], url, 0.8, pivots=[Entity("name", u["name"])])
        if u.get("location"):
            yield self._f(entity, "Chess.com location", u["location"], url, 0.8, "location")
        if u.get("country"):
            yield self._f(entity, "Chess.com country", u["country"].rsplit("/", 1)[-1], url, 0.8, "location")


META_RE = {
    "og:title": re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']{1,300})', re.I),
    "og:description": re.compile(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']{1,800})', re.I),
    "description": re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,800})', re.I),
    "og:image": re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']{1,500})', re.I),
}


class ProfileMetadataSource(Source):
    """Reads public page metadata of every discovered account (runs after account discovery)."""

    name = "profile-metadata"
    kinds = ("username",)
    stage = "enrich"
    description = "Extracts bio, display name, avatar, emails and cross-links from each found account page"
    max_pages = 40

    async def search(self, entity: Entity, ctx: Context):
        accounts = sorted((f for f in findings_for(ctx, entity, "account") if f.url and f.confidence >= 0.6
                           and f.source == "accounts"), key=lambda f: -f.confidence)[: self.max_pages]
        if not accounts:
            return
        ctx.progress(self.name, entity, 0, len(accounts))
        done = 0

        async def fetch(f: Finding):
            try:
                r = await ctx.get(f.url, timeout=ctx.options.timeout)
                return f, r.text[:600_000] if r.status_code == 200 else ""
            except httpx.HTTPError:
                return f, ""

        for fut in asyncio.as_completed([fetch(f) for f in accounts]):
            acct, page = await fut
            done += 1
            ctx.progress(self.name, entity, done, len(accounts))
            if not page:
                continue
            meta = {k: htmlmod.unescape(m.group(1)).strip() for k, rx in META_RE.items() if (m := rx.search(page))}
            desc = meta.get("og:description") or meta.get("description") or ""
            title = meta.get("og:title", "")
            u = entity.value.lower()
            # Remember outbound links that carry the username: site discovery learns new sites from them.
            host = (acct.url.split("/")[2] if "//" in acct.url else "").lower()
            out_links = {h for h in re.findall(r'href=["\'](https?://[^"\'\s]+)', page)
                         if u in h.lower() and host not in h.lower()}
            ctx.shared.setdefault("outlinks", {}).setdefault(str(entity), set()).update(list(out_links)[:40])
            # Annotate the account itself so cross-checks and image matching can use the page's identity.
            if u in (title + desc).lower() or meta.get("og:image"):
                acct.data.setdefault("page_title", title[:200])
                acct.data.setdefault("page_desc", desc[:300])
                disp = re.split(r"\s[|\-–·•(]\s?|\s\(@", title)[0].strip() if title else ""
                # Only short titles that aren't templates around the handle ("x's profile on Site") are names.
                if disp and u not in disp.lower() and len(disp) <= 40 and len(disp.split()) <= 4:
                    acct.data.setdefault("display_name", disp)
                if meta.get("og:image", "").startswith("http"):
                    from panoptes.sources.deep import site_default_image
                    if meta["og:image"] != await site_default_image(ctx, acct.url):
                        acct.data.setdefault("avatar", meta["og:image"])
            # Only trust metadata that is actually about this profile, not the site's generic blurb.
            if u not in (title + desc).lower():
                continue
            base = dict(source=self.name, target=entity, url=acct.url)
            residue = re.sub(re.escape(u), "", desc.lower()).strip(" .,'|-")
            if title and u in title.lower() and title.lower().strip() != u:
                yield Finding(category="profile", title=f"{acct.title} display title", value=title[:300],
                              confidence=0.6, **base)
            if desc and u in desc.lower() and len(residue) >= 25:
                yield Finding(category="profile", title=f"{acct.title} bio", value=desc[:600], confidence=0.6,
                              pivots=_link_pivots(desc, entity.value), **base)
            if meta.get("og:image", "").startswith("http"):
                yield Finding(category="image", title=f"{acct.title} avatar", value=meta["og:image"],
                              confidence=0.7, data={"profile": acct.url},
                              **{**base, "url": meta["og:image"]})
