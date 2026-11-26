"""GitHub deep lookups: profile details, commit-email leaks, email -> account."""
from __future__ import annotations

import asyncio
import html as htmlmod
import re

import httpx

from panoptes.detect import normalize_domain, social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source

API = "https://api.github.com"


def _headers(ctx: Context) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.config.get("github_token")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _real_email(email: str | None) -> bool:
    return bool(email) and "noreply" not in email.lower() and "@" in email


async def _scrape_profile(user: str, ctx: Context) -> dict | None:
    """Profile fields from the public github.com page, shaped like the API response."""
    try:
        r = await ctx.get(f"https://github.com/{user}")
    except httpx.HTTPError:
        return None
    if r.status_code != 200 or 'itemprop="additionalName"' not in r.text and "p-nickname" not in r.text:
        return None
    page = r.text

    def grab(pattern):
        m = re.search(pattern, page, re.S)
        return htmlmod.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else None
    login = grab(r'itemprop="additionalName"[^>]*>(.*?)</span>') or user
    blog = re.search(r'itemprop="url"[^>]*>.*?href="([^"]+)"', page, re.S)
    twitter = re.search(r'href="https://(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})"', page)
    avatar = re.search(r'<img[^>]+class="[^"]*avatar-user[^"]*"[^>]+src="([^"]+)"', page)
    return {"_scraped": True, "login": login, "html_url": f"https://github.com/{login}",
            "name": grab(r'itemprop="name"[^>]*>(.*?)</span>'),
            "bio": grab(r'class="p-note[^"]*"[^>]*>(.*?)</div>'),
            "location": grab(r'itemprop="homeLocation"[^>]*>.*?<span[^>]*>(.*?)</span>'),
            "company": grab(r'itemprop="worksFor"[^>]*>.*?<span[^>]*>(.*?)</span>'),
            "blog": blog.group(1) if blog else None, "twitter_username": twitter.group(1) if twitter else None,
            "avatar_url": htmlmod.unescape(avatar.group(1)).split("?")[0] if avatar else None}


class GitHubProfileSource(Source):
    name = "github"
    kinds = ("username",)
    description = "GitHub profile details plus emails leaked in public commit metadata"

    async def search(self, entity: Entity, ctx: Context):
        user = entity.value
        try:
            r = await ctx.get(f"{API}/users/{user}", headers=_headers(ctx))
        except httpx.HTTPError as exc:
            ctx.log(f"github: {exc.__class__.__name__}", "warning")
            return
        if r.status_code == 404:
            return
        if r.status_code in (403, 429):
            ctx.log("github: API rate limit hit - using the public website instead (a github_token avoids this)", "warning")
            p = await _scrape_profile(user, ctx)
            if not p:
                return
        elif r.status_code != 200:
            return
        else:
            p = r.json()
        login = p.get("login", user)
        url = p.get("html_url")
        base = dict(source=self.name, target=entity, url=url)

        def add(title, value, conf=0.95, pivots=(), category="profile"):
            if value in (None, "", []):
                return None
            return Finding(category=category, title=title, value=str(value), confidence=conf,
                           pivots=list(pivots), **base)

        out = [
            Finding(category="image", title="GitHub avatar", value=p["avatar_url"], url=p["avatar_url"], source=self.name,
                    target=entity, confidence=0.9, data={"profile": url}) if p.get("avatar_url") else None,
            add("GitHub name", p.get("name"), pivots=[Entity("name", p["name"])] if p.get("name") else ()),
            add("GitHub bio", p.get("bio")),
            add("GitHub location", p.get("location")),
            add("GitHub company", p.get("company")),
            add("GitHub created", p.get("created_at")),
            None if p.get("_scraped") else
            add("GitHub followers", f"{p.get('followers', 0)} followers / {p.get('public_repos', 0)} public repos"),
        ]
        if p.get("blog"):
            blog = p["blog"]
            handle = social_handle(blog)
            piv = [Entity("username", handle)] if handle else [Entity("domain", normalize_domain(blog))]
            out.append(add("GitHub website", blog, pivots=piv))
        if p.get("twitter_username"):
            out.append(add("Twitter/X handle", p["twitter_username"], pivots=[Entity("username", p["twitter_username"])]))
        if _real_email(p.get("email")):
            out.append(add("Public email", p["email"], category="email", pivots=[Entity("email", p["email"])]))
        for f in out:
            if f:
                yield f

        if p.get("_scraped"):
            async for f in self._patch_emails(login, entity, ctx, p.get("name")):
                yield f
        else:
            async for f in self._commit_emails(login, entity, ctx):
                yield f

    async def _patch_emails(self, login: str, entity: Entity, ctx: Context, display: str | None = None):
        """No-API commit emails: recent commits from each repo's Atom feed, author line from the public .patch."""
        try:
            r = await ctx.get(f"https://github.com/{login}?tab=repositories")
            repos = list(dict.fromkeys(re.findall(rf'href="/{re.escape(login)}/([A-Za-z0-9_.\-]+)"[^>]*itemprop="name codeRepository"',
                                                  r.text)))[:4]
        except httpx.HTTPError:
            return
        seen: dict[str, set[str]] = {}
        for repo in repos:
            try:
                feed = await ctx.get(f"https://github.com/{login}/{repo}/commits.atom")
            except httpx.HTTPError:
                continue
            # Only commits this person authored - big repos are mostly other people's work.
            shas = []
            for entry in re.findall(r"<entry>(.*?)</entry>", feed.text, re.S):
                author = re.search(r"<author>\s*<name>([^<]+)</name>", entry)
                sha = re.search(r"Commit/([0-9a-f]{40})", entry)
                if sha and author and author.group(1).strip().lower() == login.lower():
                    shas.append(sha.group(1))
            shas = shas[:10]  # huge commits can't be rendered as .patch - keep trying until one works
            got = 0
            for sha in shas:
                if got >= 2:
                    break
                try:
                    pr = await ctx.get(f"https://github.com/{login}/{repo}/commit/{sha}.patch")
                except httpx.HTTPError:
                    continue
                if pr.status_code != 200:
                    continue
                got += 1
                m = re.search(r"^From: (.*?) <([^>]+)>", pr.text[:4000], re.M)
                # The patch author must be this person (their name or login) - maintainers commit others' patches.
                ident = {login.lower()} | ({display.lower()} if display else set())
                if m and _real_email(m.group(2)) and (m.group(1).strip().strip('"').lower() in ident
                                                      or login.lower() in m.group(2).lower()):
                    seen.setdefault(m.group(2).lower(), set()).add(m.group(1).strip())
        for email, names in seen.items():
            yield Finding(category="email", title="Commit author email", value=email, source=self.name,
                          target=entity, confidence=0.9, url=f"https://github.com/{login}",
                          data={"author_names": sorted(n for n in names if n), "via": "public commit patches"},
                          pivots=[Entity("email", email)])

    async def _commit_emails(self, login: str, entity: Entity, ctx: Context):
        """Emails in commit author metadata of the user's own recent repositories."""
        try:
            r = await ctx.get(f"{API}/users/{login}/repos", headers=_headers(ctx),
                              params={"sort": "pushed", "per_page": 10, "type": "owner"})
            repos = [x for x in (r.json() if r.status_code == 200 else []) if not x.get("fork")][:5]
        except (httpx.HTTPError, ValueError):
            return

        async def commits(repo):
            try:
                rr = await ctx.get(f"{API}/repos/{login}/{repo['name']}/commits", headers=_headers(ctx),
                                   params={"author": login, "per_page": 20})
                return rr.json() if rr.status_code == 200 else []
            except (httpx.HTTPError, ValueError):
                return []

        seen: dict[str, set[str]] = {}
        for batch in await asyncio.gather(*(commits(r) for r in repos)):
            for c in batch if isinstance(batch, list) else []:
                author = (c.get("commit") or {}).get("author") or {}
                email = author.get("email")
                if _real_email(email):
                    seen.setdefault(email.lower(), set()).add(author.get("name") or "")
        for email, names in seen.items():
            yield Finding(category="email", title="Commit author email", value=email, source=self.name,
                          target=entity, confidence=0.9, url=f"https://github.com/{login}",
                          data={"author_names": sorted(n for n in names if n)},
                          pivots=[Entity("email", email)])


class GitHubEmailSource(Source):
    name = "github-email"
    kinds = ("email",)
    description = "Finds GitHub accounts tied to an email (profile search + commit authorship)"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value
        logins: dict[str, str] = {}
        try:
            r = await ctx.get(f"{API}/search/users", headers=_headers(ctx), params={"q": f"{email} in:email"})
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    logins[item["login"]] = "profile email"
            r = await ctx.get(f"{API}/search/commits", headers=_headers(ctx),
                              params={"q": f"author-email:{email}", "per_page": 20})
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    if item.get("author") and item["author"].get("login"):
                        logins.setdefault(item["author"]["login"], "commit author")
        except (httpx.HTTPError, ValueError) as exc:
            ctx.log(f"github-email: {exc.__class__.__name__}", "warning")
            return
        for login, how in logins.items():
            yield Finding(category="account", title="GitHub", value=f"https://github.com/{login}",
                          url=f"https://github.com/{login}", source=self.name, target=entity,
                          confidence=0.95, data={"matched_by": how, "username": login},
                          pivots=[Entity("username", login)])
