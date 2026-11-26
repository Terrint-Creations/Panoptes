"""Deep-search username capabilities.

  * Site discovery - profile pages link to the person's accounts on sites no database knows about.
    Any such link containing the username becomes a URL template, is validated (real username
    exists, a random username doesn't), is checked for every username in the investigation, and is
    saved so all future searches check that site too.
  * Alt-account finder - variations of the username on the platforms where the main account lives,
    reported only when the candidate shares hard evidence with the main account: the same profile
    picture, a mention of the other account, the same personal link, or the same real display name.
  * Username domains (Namechk) - registered domains named after the username.
"""
from __future__ import annotations

import asyncio
import html as htmlmod
import re
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source, findings_for
from panoptes.sources.sitedb import OK_2XX, U, Probe, Rule, Site, load_discovered, save_discovered, site_key

GENERIC_HOSTS = ("google.", "youtube.com/watch", "bit.ly", "t.co", "goo.gl", "apple.com", "microsoft.com", "amazon.",
                 "wikipedia.org", "w3.org", "schema.org", "gravatar.com/avatar", "cloudflare", "akamai", "cdn.")
NOT_DISPLAY = {"home", "profile", "user", "account", "login", "sign in", "page not found", "404"}


def _accounts_source():
    from panoptes.sources.accounts import AccountsSource
    return AccountsSource()


def template_for(url: str, username: str) -> str | None:
    """Turn a profile URL containing the username into a reusable template, or None."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname or p.query or any(g in url for g in GENERIC_HOSTS):
        return None
    u = username.lower()
    host = p.hostname.lower()
    labels = host.split(".")
    if labels[0] == u and len(labels) >= 3:
        return f"{p.scheme}://{U}.{'.'.join(labels[1:])}{p.path.rstrip('/')}"
    segs = p.path.split("/")
    for i, seg in enumerate(segs):
        if seg.lower() in (u, f"@{u}", f"~{u}"):
            prefix = seg[: len(seg) - len(username)]
            segs[i] = prefix + U
            path = "/".join(segs[: i + 1])  # cut anything after the username segment
            return f"{p.scheme}://{host}{path}"
    return None


class SiteDiscoverySource(Source):
    name = "site-discovery"
    kinds = ("username",)
    stage = "late"
    option = "discover_sites"
    description = "Learns new sites from links on found profiles, validates them, checks them for every username, saves them"

    async def search(self, entity: Entity, ctx: Context):
        catalog = ctx.shared.get("account-catalog") or []
        known = {site_key(s.profile_url).split("/")[0] for s in catalog}
        urls: set[str] = set(ctx.shared.get("outlinks", {}).get(str(entity), set()))
        for f in findings_for(ctx, entity):
            if f.confidence >= 0.7:
                urls.update(x for x in (f.url, f.value) if x and x.startswith("http"))
        templates: dict[str, str] = {}
        for url in urls:
            t = template_for(url, entity.value)
            if t and site_key(t).split("/")[0] not in known and t not in templates:
                templates[t] = url
        if not templates:
            return
        acc = _accounts_source()
        usernames = [e.value for e, _, _ in ctx.report.entities.values() if e.kind == "username"]
        saved = load_discovered()
        new = 0
        for template in list(templates)[:25]:
            host = urlparse(template.replace(U, "x")).hostname.removeprefix("www.")
            rule = Rule(db="discovered", probe=Probe(template, follow=False), exists_codes=OK_2XX, no_redirect=True)
            site = Site(name=host, profile_url=template, key=site_key(template), tags={"discovered"}, rules=[rule])
            verify_was = ctx.options.verify
            ctx.options.verify = True  # never trust a learned site without the random-username check
            try:
                _, finding, _ = await acc._check_site(ctx, site, [rule], entity.value)
                if not finding:
                    continue
                finding.source, finding.sources = self.name, {"discovered"}
                finding.data["learned_from"] = templates[template]
                yield finding
                if template not in saved:
                    saved[template] = {"name": host, "seen": 0}
                    new += 1
                saved[template]["seen"] = saved[template].get("seen", 0) + 1
                for other in usernames:
                    if other.lower() == entity.value.lower():
                        continue
                    _, f2, _ = await acc._check_site(ctx, site, [rule], other)
                    if f2:
                        f2.source, f2.sources = self.name, {"discovered"}
                        yield f2
            finally:
                ctx.options.verify = verify_was
        if new:
            async with ctx.lock("discovered-save"):
                merged = load_discovered()
                merged.update(saved)
                save_discovered(merged)
            ctx.log(f"site-discovery: learned {new} new site(s) from {entity.value}'s profiles - future searches check them too")


# ----------------------------------------------------------------------------- alt accounts

def username_variants(u: str, name: str | None, aliases: list[str] | None = None) -> list[str]:
    """Plausible alternate handles: separators, numbers, prefixes/suffixes, leetspeak, aliases, name-based."""
    base = re.sub(r"\d+$", "", u)
    leet = u.translate(str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4"}))
    out = [base, f"{u}_", f"_{u}", f"{u}1", f"{u}2", f"{u}3", f"{u}0", f"{u}01", f"{u}_1", f"{u}alt", f"{u}_alt",
           f"{u}2nd", f"{u}backup", f"{u}priv", f"{u}x", f"x{u}", f"real{u}", f"the{u}", f"its{u}", f"iam{u}",
           f"not{u}", f"{u}official", f"{u}tv", f"{u}yt", f"{u}gaming", leet,
           u.replace("_", "."), u.replace(".", "_"), u.replace("_", ""), u.replace("-", "_"), u.replace(".", "")]
    for a in aliases or []:
        out.append(a)
        out.append(a.replace(" ", ""))
    if name:
        from panoptes.sources.phone import username_candidates
        out += username_candidates(name)[:5]
    seen, res = {u.lower()}, []
    for v in out:
        v = v.strip("._-")
        if len(v) >= 3 and v.lower() not in seen and re.fullmatch(r"[A-Za-z0-9_.\-]+", v):
            seen.add(v.lower())
            res.append(v)
    return res[:30]

META = {k: re.compile(rf'<meta[^>]+(?:property|name)=["\']{k}["\'][^>]+content=["\']([^"\']{{1,600}})', re.I)
        for k in ("og:title", "og:description", "og:image", "description")}


URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>)]+|(?<![@\w])(?:[a-z0-9-]+\.)+(?:com|net|org|io|me|dev|co|tv|gg|xyz)/?[^\s\"'<>)]*", re.I)


async def _site_defaults(ctx: Context, url: str) -> dict:
    """og:image / description of the site's home page - generic profiles fall back to these."""
    p = urlparse(url)
    host = f"{p.scheme}://{p.hostname}/"
    cache = ctx.shared.setdefault("site-defaults", {})
    if host not in cache:
        try:
            r = await ctx.get(host, timeout=12)
            page = r.text[:400_000]
            img, desc = META["og:image"].search(page), META["og:description"].search(page) or META["description"].search(page)
            cache[host] = {"image": htmlmod.unescape(img.group(1)) if img else "",
                           "desc": htmlmod.unescape(desc.group(1)).strip().lower() if desc else ""}
        except httpx.HTTPError:
            cache[host] = {"image": "", "desc": ""}
    return cache[host]


async def site_default_image(ctx: Context, url: str) -> str:
    return (await _site_defaults(ctx, url))["image"]


async def page_signals(ctx: Context, url: str) -> dict:
    cache = ctx.shared.setdefault("page-signals", {})
    if url in cache:
        return cache[url]
    sig = {"title": "", "desc": "", "image": "", "image_hash": None, "links": set(), "text": ""}
    try:
        r = await ctx.get(url, timeout=15)
        page = r.text[:800_000] if r.status_code == 200 else ""
    except httpx.HTTPError:
        page = ""
    if page:
        for k, rx in META.items():
            m = rx.search(page)
            if m:
                sig["title" if k == "og:title" else "image" if k == "og:image" else "desc"] = htmlmod.unescape(m.group(1))
        host = (urlparse(url).hostname or "").removeprefix("www.")
        # Only links the owner wrote in their bio count - page-wide hrefs are site navigation shared by everyone.
        for link in URL_IN_TEXT.findall(sig["title"] + " " + sig["desc"]):
            link = link.rstrip(".,;").lower()
            if host not in link and not any(g in link for g in GENERIC_HOSTS):
                sig["links"].add(re.sub(r"^https?://(www\.)?", "", link).rstrip("/"))
        sig["text"] = (sig["title"] + " " + sig["desc"]).lower()
        if sig.get("image", "").startswith("http") and sig["image"] != await site_default_image(ctx, url):
            try:
                from panoptes.sources.images import dhash, load_image
                ir = await ctx.get(sig["image"], timeout=15)
                img, _ = load_image(ir.content) if ir.status_code == 200 else (None, "")
                sig["image_hash"] = dhash(img) if img else None
            except httpx.HTTPError:
                pass
    cache[url] = sig
    return sig


def _mentions(text: str, who: str, own: str) -> bool:
    """Does `text` refer to @who - ignoring the page's own handle, which may contain `who` as a substring?"""
    # Only explicit references count: "@who" or a link ".../who". A bare word is too often just a fan's
    # display name ("Linus Torvalds" on a 'linus-torvalds' account says nothing about @torvalds).
    t = text.lower().replace(own.lower(), " ")
    return re.search(rf"(?:@|/){re.escape(who.lower())}(?![a-z0-9_.\-])", t) is not None


def _display(title: str, username: str) -> str:
    t = re.split(r"\s[|\-–·•(]\s?|\s\(@", title)[0].strip()
    return "" if t.lower() in NOT_DISPLAY or t.lower().strip("@") == username.lower() else t


def norm_text_simple(s: str) -> str:
    import unicodedata
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower().strip()


def norm_words(text: str) -> list[str]:
    import unicodedata
    t = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return re.findall(r"[a-z0-9]+", t)


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{3,}", text.lower()) if w not in {"the", "and", "for", "with", "you", "profile",
                                                                              "user", "page", "account", "follow"}}


class AltAccountSource(Source):
    name = "alt-accounts"
    kinds = ("username",)
    stage = "late"
    option = "alt_accounts"
    heavy = True
    description = ("Finds alternate accounts: handle variants, aliases and name-based handles on the platforms the person "
                   "uses, graded by shared picture, cross-mentions, bio links, bio similarity, display name and known facts")

    async def search(self, entity: Entity, ctx: Context):
        from panoptes.sources.images import hamming

        if ctx.report and str(entity) in ctx.report.meta.get("speculative", []):
            return  # alt-hunting for an unverified lead only multiplies guesses
        catalog = {s.name: s for s in ctx.shared.get("account-catalog") or []}
        mains = [f for f in findings_for(ctx, entity, "account")
                 if f.source == "accounts" and f.confidence >= 0.7 and f.title in catalog
                 and not f.data.get("conflicts_with")]
        if not mains:
            return
        mains = sorted(mains, key=lambda f: (-len(catalog[f.title].dbs), -f.confidence))[:15]
        kb = ctx.knowledge
        name = kb.best_name() if kb else None
        from panoptes.knowledge import ambiguous_handles, owned
        ambiguous = ambiguous_handles(ctx.report) if ctx.report else set()
        aliases = sorted({str(f.data["display_name"]) for f in findings_for(ctx, entity)
                          if f.data.get("display_name") and f.confidence >= 0.7 and owned(ctx.report, f, ambiguous)
                          and re.fullmatch(r"[A-Za-z0-9_. ]{3,30}", str(f.data["display_name"]))})[:4]
        name_tokens = kb.name_tokens() if kb else set()
        aliases = [a for a in aliases if norm_text_simple(a) not in name_tokens and len(a) >= 6]
        variants = username_variants(entity.value, name, aliases)
        acc = _accounts_source()
        jobs = [(m, v) for m in mains for v in variants]
        ctx.progress(self.name, entity, 0, len(jobs))
        done = 0

        async def probe(main: Finding, variant: str):
            site = catalog[main.title]
            rules = [r for r in site.rules if r.applies_to(variant)]
            if not rules:
                return None
            if site.key in ctx.shared.get("catch-all", set()):
                return None
            _, hit, _ = await acc._check_site(ctx, site, rules, variant, ctx.options.fast_timeout)
            # only verified hits: a site that 'finds' a random name too proves nothing
            return (main, variant, hit) if hit and hit.confidence >= 0.6 and hit.data.get("verified") else None

        hits = []
        for fut in asyncio.as_completed([probe(m, v) for m, v in jobs]):
            res = await fut
            done += 1
            if done % 25 == 0 or done == len(jobs):
                ctx.progress(self.name, entity, done, len(jobs))
            if res:
                hits.append(res)

        known_alias = {a.lower() for a in aliases} | ({name.lower()} if name else set())
        for main, variant, hit in hits:
            a, b = await asyncio.gather(page_signals(ctx, main.url), page_signals(ctx, hit.url))
            strong, medium = [], []
            if (a["image_hash"] is not None and b["image_hash"] is not None and a["image"] != b["image"]
                    and hamming(a["image_hash"], b["image_hash"]) <= 6):
                strong.append("same profile picture")
            if _mentions(b["text"], entity.value, variant):
                strong.append(f"mentions @{entity.value}")
            if _mentions(a["text"], variant, entity.value):
                strong.append(f"main account mentions @{variant}")
            shared = a["links"] & b["links"]
            if shared:
                strong.append(f"same link in bio: {sorted(shared)[0]}")
            handle = re.sub(r"[^a-z0-9]", "", variant.lower())
            if kb:
                for ev in kb.evidence_in(b["text"], exclude_username=variant):
                    if ev.startswith("name ") and all(t in handle for t in norm_words(ev[6:-1])):
                        continue  # the handle was built from the name, so the name being there proves nothing
                    strong.append(f"alt page names known {ev}")
            site_words = {w for w in re.findall(r"[a-z0-9]+", (main.title + " " + (urlparse(hit.url).hostname or "")).lower())}
            da, db = _display(a["title"], entity.value), _display(b["title"], variant)
            if (da and db and da.lower() == db.lower() and (" " in da or len(da) >= 4)
                    and not set(re.findall(r"[a-z0-9]+", da.lower())) <= site_words):
                (strong if da.lower() in known_alias else medium).append(f"same display name '{da}'")
            ta = a["desc"].lower().replace(entity.value.lower(), "{u}")
            tb = b["desc"].lower().replace(variant.lower(), "{u}")
            site_desc = (await _site_defaults(ctx, hit.url))["desc"]
            if ta and ta == tb and ("{u}" in ta or ta == site_desc or len(_words(ta)) < 4):
                pass  # identical site template / the site's default description - not evidence
            elif ta and ta == tb:
                strong.append("identical bio")
            else:
                wa, wb = _words(a["desc"]) - _words(a["title"]), _words(b["desc"]) - _words(b["title"])
                if len(wa) >= 4 and len(wb) >= 4 and len(wa & wb) / len(wa | wb) >= 0.4:
                    medium.append(f"similar bio ({len(wa & wb)} shared words)")
            if variant.lower() in known_alias:
                medium.append("handle matches an alias the person uses")
            if not strong and not medium:
                continue  # existence alone proves nothing - lots of people share similar handles
            if strong or len(medium) >= 2:
                conf = min(0.93, 0.6 + 0.12 * len(strong) + 0.08 * len(medium))
                title = f"Likely alt on {main.title}"
            else:
                conf, title = 0.5, f"Possible alt on {main.title}"
            yield Finding(category="alt-account", title=title, value=hit.url, url=hit.url,
                          source=self.name, target=entity, confidence=conf,
                          data={"alt_username": variant, "main_account": main.url, "evidence": strong + medium},
                          pivots=[Entity("username", variant)] if conf >= 0.7 else [])


class UsernameDomainsSource(Source):
    name = "username-domains"
    kinds = ("username",)
    description = "Namechk-style: registered domains named after the username (.com .net .io .dev …) with their site titles"

    async def search(self, entity: Entity, ctx: Context):
        label = entity.value.lower().replace("_", "-").replace(".", "-").strip("-")
        if not re.fullmatch(r"[a-z0-9][a-z0-9\-]{2,62}", label):
            return
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6

        async def check(tld):
            d = f"{label}.{tld}"
            try:
                await resolver.resolve(d, "NS")
                return d
            except (dns.exception.DNSException, OSError):
                return None
        found = [d for d in await asyncio.gather(*(check(t) for t in ("com", "net", "org", "io", "me", "dev", "co",
                                                                         "xyz", "app", "info", "tv", "gg"))) if d]
        for d in found:
            title = ""
            try:
                r = await ctx.get(f"https://{d}", timeout=10)
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:200_000], re.S | re.I)
                title = htmlmod.unescape(m.group(1)).strip()[:200] if m else ""
            except httpx.HTTPError:
                pass
            if re.search(r"for sale|parked|buy this domain|domain (is )?available|hugedomains|sedo|dan\.com", title, re.I):
                continue
            yield Finding(category="related-domain", title="Domain named after username", value=d, url=f"https://{d}",
                          source=self.name, target=entity, confidence=0.4, pivots=[Entity("domain", d)],
                          data={"page_title": title, "note": "may belong to someone else - boosted only if it "
                                                            "independently mentions a confirmed name/link"})
