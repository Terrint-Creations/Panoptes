"""Social platform intelligence.

  * X / Twitter (twint-fork / birdwatcher capabilities): profile, recent tweets, who they mention,
    linked sites, activity hours -> timezone estimate. Works without login via the syndication
    timeline; uses your auth_token/ct0 cookies when provided.
  * Instagram (Toutatis + Instaloader capabilities): profile, business contact info, recent posts
    with locations/mentions/tagged users; with a sessionid also the hidden contact fields and
    obfuscated email/phone from the account-recovery lookup.
  * TikTok, Telegram: public profile parsing.
  * Reddit (with an app id/secret): account age, karma, top communities, activity-hour timezone.
  * Link pages (Linktree & co.): every link the owner declared, as accounts and pivots.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import html as htmlmod
import json
import re
import urllib.parse
from collections import Counter
from urllib.parse import urljoin, urlparse

import httpx

from panoptes.detect import normalize_domain, social_handle
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, extract_emails, findings_for

NEXT_DATA = re.compile(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)
MENTION = re.compile(r"(?<![\w@])@([A-Za-z0-9_.]{2,30})")
HASHTAG = re.compile(r"(?<![\w#])#(\w{2,40})")


def activity_timezone(times: list[dt.datetime]) -> tuple[str, str] | None:
    """Estimate a UTC offset from posting hours: the quietest 6-hour window is assumed to be ~01:00-07:00 local."""
    if len(times) < 25:
        return None
    hist = Counter(t.astimezone(dt.timezone.utc).hour for t in times)
    counts = [hist.get(h, 0) for h in range(24)]
    quiet = min(range(24), key=lambda s: sum(counts[(s + i) % 24] for i in range(6)))
    center = (quiet + 3) % 24
    offset = (4 - center + 12) % 24 - 12
    peak = max(range(24), key=lambda h: counts[h])
    return (f"Quietest {quiet:02d}:00-{(quiet + 6) % 24:02d}:00 UTC, busiest {peak:02d}:00 UTC",
            f"UTC{offset:+d} (±2h)")


def _f(source, entity, category, title, value, url=None, conf=0.85, pivots=(), **data) -> Finding:
    return Finding(category=category, title=title, value=str(value)[:800], url=url, source=source, target=entity,
                   confidence=conf, pivots=list(pivots), data={k: v for k, v in data.items() if v not in (None, "", [])})


def _link_pivots(text: str, own: str) -> list[Entity]:
    from panoptes.sources.platforms import _link_pivots as lp
    return lp(text, own)


# ----------------------------------------------------------------------------- X / Twitter

class XSource(Source):
    name = "x-twitter"
    kinds = ("username",)
    description = "X/Twitter profile + recent tweets: mentions, links, activity hours (no login; cookies optional)"

    async def search(self, entity: Entity, ctx: Context):
        user = entity.value
        if not re.fullmatch(r"[A-Za-z0-9_]{1,15}", user):
            return
        headers = {}
        if ctx.config.get("x_auth_token"):
            headers["Cookie"] = f"auth_token={ctx.config.get('x_auth_token')}; ct0={ctx.config.get('x_ct0') or ''}"
        try:
            r = await ctx.get(f"https://syndication.twitter.com/srv/timeline-profile/screen-name/{user}", headers=headers)
            m = NEXT_DATA.search(r.text)
            entries = json.loads(m.group(1))["props"]["pageProps"]["timeline"]["entries"] if m else []
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return
        tweets = [e["content"]["tweet"] for e in entries if e.get("type") == "tweet" and e.get("content", {}).get("tweet")]
        own = [t for t in tweets if t.get("user", {}).get("screen_name", "").lower() == user.lower()]
        if not own:
            return
        u = own[0]["user"]
        url = f"https://x.com/{u['screen_name']}"
        S, e = self.name, entity
        yield _f(S, e, "account", "X (Twitter)", url, url, 0.97, followers=u.get("followers_count"),
                 following=u.get("friends_count"), tweets=u.get("statuses_count"), verified=u.get("verified"))
        if u.get("name"):
            yield _f(S, e, "profile", "X display name", u["name"], url, 0.85, display_name=u["name"])
        if u.get("description"):
            yield _f(S, e, "profile", "X bio", u["description"], url, 0.85, pivots=_link_pivots(u["description"], user))
        if u.get("location"):
            yield _f(S, e, "location", "X location", u["location"], url, 0.75, pivots=[Entity("location", u["location"])])
        if u.get("created_at"):
            yield _f(S, e, "profile", "X account created", u["created_at"], url, 0.95)
        for link in (u.get("entities", {}).get("url", {}).get("urls") or []):
            target = link.get("expanded_url") or link.get("url")
            if target:
                yield _f(S, e, "profile", "X profile link", target, target, 0.9, pivots=_link_pivots(target, user))
        pic = (u.get("profile_image_url_https") or "").replace("_normal.", "_400x400.")
        if pic:
            yield _f(S, e, "image", "X avatar", pic, pic, 0.9, profile=url)

        times, mentions, tags, domains = [], Counter(), Counter(), Counter()
        for t in own:
            try:
                times.append(dt.datetime.strptime(t["created_at"], "%a %b %d %H:%M:%S %z %Y"))
            except (KeyError, ValueError):
                pass
            ents = t.get("entities") or {}
            mentions.update(m["screen_name"] for m in ents.get("user_mentions", []) if m.get("screen_name"))
            tags.update(h["text"].lower() for h in ents.get("hashtags", []) if h.get("text"))
            for link in ents.get("urls", []):
                d = normalize_domain(link.get("expanded_url") or "")
                if d and d not in ("x.com", "twitter.com"):
                    domains[d] += 1
        if times:
            yield _f(S, e, "activity", "X recent tweets", f"{len(own)} tweets, {min(times).date()} → {max(times).date()}",
                     url, 0.9)
        for handle, n in mentions.most_common(8):
            yield _f(S, e, "associate", "Frequently mentions on X", f"@{handle} ({n}x)", f"https://x.com/{handle}", 0.55,
                     pivots=[Entity("username", handle)])
        if tags:
            yield _f(S, e, "activity", "X hashtags", ", ".join(f"#{t}" for t, _ in tags.most_common(12)), url, 0.8)
        for d, n in domains.most_common(6):
            yield _f(S, e, "activity", "Links shared on X", f"{d} ({n}x)", f"https://{d}", 0.7)
        tz = activity_timezone(times)
        if tz:
            yield _f(S, e, "activity", "X posting hours", tz[0], url, 0.6)
            yield _f(S, e, "location", "Timezone (from X activity)", tz[1], url, 0.5)


# ----------------------------------------------------------------------------- Instagram

IG_APP_ID = "936619743392459"
IG_SIG_KEY = "e6358aeede676184b9fe702b30f4fd35e71744605e39d2181a34cede076b3c33"


def _ig_signed(data: dict) -> str:
    body = json.dumps(data)
    sig = hmac.new(IG_SIG_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"ig_sig_key_version=4&signed_body={sig}.{urllib.parse.quote_plus(body)}"


class InstagramSource(Source):
    name = "instagram"
    kinds = ("username",)
    description = ("Instagram profile, business contacts, recent posts (locations, mentions, tagged users); "
                   "with instagram_sessionid also hidden contact info and obfuscated email/phone (Toutatis)")

    async def search(self, entity: Entity, ctx: Context):
        user = entity.value.lower()
        if not re.fullmatch(r"[a-z0-9_.]{1,30}", user):
            return
        session = ctx.config.get("instagram_sessionid")
        headers = {"x-ig-app-id": IG_APP_ID, "Referer": "https://www.instagram.com/"}
        if session:
            headers["Cookie"] = f"sessionid={session}"
        try:
            r = await ctx.get("https://i.instagram.com/api/v1/users/web_profile_info/", params={"username": user},
                              headers=headers)
        except httpx.HTTPError:
            return
        if r.status_code in (401, 429) or (r.status_code == 200 and not r.text.strip()):
            ctx.log("instagram: rate-limited without login - add instagram_sessionid in Settings for reliable results",
                    "warning")
            return
        try:
            u = r.json()["data"]["user"]
        except (ValueError, KeyError, TypeError):
            return
        if not u:
            return
        S, e = self.name, entity
        url = f"https://www.instagram.com/{u['username']}/"
        yield _f(S, e, "account", "Instagram", url, url, 0.98, user_id=u.get("id"), private=u.get("is_private"),
                 verified=u.get("is_verified"), followers=(u.get("edge_followed_by") or {}).get("count"),
                 following=(u.get("edge_follow") or {}).get("count"))
        if u.get("full_name"):
            yield _f(S, e, "profile", "Instagram name", u["full_name"], url, 0.85, display_name=u["full_name"])
        if u.get("biography"):
            yield _f(S, e, "profile", "Instagram bio", u["biography"], url, 0.85, pivots=_link_pivots(u["biography"], user))
        links = [u.get("external_url")] + [b.get("url") for b in u.get("bio_links") or []]
        for link in dict.fromkeys(l for l in links if l):
            yield _f(S, e, "profile", "Instagram link", link, link, 0.9, pivots=_link_pivots(link, user))
        if u.get("business_email"):
            yield _f(S, e, "email", "Instagram business email", u["business_email"], url, 0.95,
                     pivots=[Entity("email", u["business_email"])])
        if u.get("business_phone_number"):
            yield _f(S, e, "phone", "Instagram business phone", u["business_phone_number"], url, 0.95,
                     pivots=[Entity("phone", u["business_phone_number"])])
        if u.get("category_name"):
            yield _f(S, e, "profile", "Instagram category", u["category_name"], url, 0.9)
        pic = u.get("profile_pic_url_hd") or u.get("profile_pic_url")
        if pic:
            yield _f(S, e, "image", "Instagram avatar", pic, pic, 0.9, profile=url)

        posts = [x["node"] for x in (u.get("edge_owner_to_timeline_media") or {}).get("edges", [])]
        places, mentions, tagged, tags = Counter(), Counter(), Counter(), Counter()
        times = []
        for p in posts:
            if p.get("location") and p["location"].get("name"):
                places[p["location"]["name"]] += 1
            cap = " ".join(c["node"].get("text", "") for c in (p.get("edge_media_to_caption") or {}).get("edges", []))
            mentions.update(m.lower() for m in MENTION.findall(cap))
            tags.update(t.lower() for t in HASHTAG.findall(cap))
            for t in (p.get("edge_media_to_tagged_user") or {}).get("edges", []):
                tagged[t["node"]["user"]["username"]] += 1
            if p.get("taken_at_timestamp"):
                times.append(dt.datetime.fromtimestamp(p["taken_at_timestamp"], dt.timezone.utc))
        if posts:
            span = f", {min(times).date()} → {max(times).date()}" if times else ""
            yield _f(S, e, "activity", "Instagram recent posts", f"{len(posts)} posts{span}", url, 0.9)
        for place, n in places.most_common(10):
            yield _f(S, e, "location", "Instagram post location", f"{place} ({n} posts)", url, 0.8,
                     pivots=[Entity("location", place)])
        for who, n in (tagged + mentions).most_common(8):
            if who != user:
                yield _f(S, e, "associate", "Tagged / mentioned on Instagram", f"@{who} ({n}x)",
                         f"https://www.instagram.com/{who}/", 0.55, pivots=[Entity("username", who)])
        if tags:
            yield _f(S, e, "activity", "Instagram hashtags", ", ".join(f"#{t}" for t, _ in tags.most_common(12)), url, 0.8)

        if session and u.get("id"):
            async for f in self._private_fields(u["id"], user, session, entity, ctx, url):
                yield f

    async def _private_fields(self, uid, user, session, entity, ctx, url):
        """Toutatis: the mobile API exposes contact fields and account-recovery hints to logged-in clients."""
        S, e = self.name, entity
        mobile = {"User-Agent": "Instagram 292.0.0.31.110 Android (30/11; 420dpi; 1080x2129; samsung; SM-G973F; "
                                "beyond1; exynos9820; en_US; 500160575)", "Cookie": f"sessionid={session}",
                  "x-ig-app-id": "567067343352427"}
        try:
            r = await ctx.get(f"https://i.instagram.com/api/v1/users/{uid}/info/", headers=mobile)
            info = r.json().get("user", {}) if r.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            info = {}
        for key, title, kind in (("public_email", "Instagram public email", "email"),
                                 ("public_phone_number", "Instagram public phone", "phone"),
                                 ("contact_phone_number", "Instagram contact phone", "phone"),
                                 ("city_name", "Instagram city", None), ("address_street", "Instagram address", None),
                                 ("whatsapp_number", "Instagram WhatsApp", "phone")):
            v = info.get(key)
            if v:
                cat = "location" if kind is None else kind
                yield _f(S, e, cat, title, v, url, 0.95, pivots=[Entity(kind, str(v))] if kind else [])
        if info.get("latitude") and info.get("longitude"):
            loc = f"{info['latitude']}, {info['longitude']}"
            yield _f(S, e, "location", "Instagram business coordinates", loc, url, 0.95, pivots=[Entity("location", loc)])
        try:
            r = await ctx.post("https://i.instagram.com/api/v1/users/lookup/", content=_ig_signed(
                {"q": user, "skip_recovery": "1"}), headers={**mobile, "Content-Type": "application/x-www-form-urlencoded"})
            lk = r.json() if r.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            lk = {}
        if lk.get("obfuscated_email"):
            yield _f(S, e, "email", "Instagram recovery email (obfuscated)", lk["obfuscated_email"], url, 0.9)
        if lk.get("obfuscated_phone"):
            yield _f(S, e, "phone", "Instagram recovery phone (obfuscated)", lk["obfuscated_phone"], url, 0.9)


# ----------------------------------------------------------------------------- TikTok / Telegram

class TikTokSource(Source):
    name = "tiktok"
    kinds = ("username",)
    description = "TikTok public profile: nickname, bio, bio link, language/region, creation date, stats"

    async def search(self, entity: Entity, ctx: Context):
        user = entity.value.lower()
        if not re.fullmatch(r"[a-z0-9_.]{2,24}", user):
            return
        try:
            r = await ctx.get(f"https://www.tiktok.com/@{user}")
            m = re.search(r'id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', r.text, re.S)
            ui = json.loads(m.group(1))["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"] if m else None
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return
        if not ui or not ui.get("user", {}).get("uniqueId"):
            return
        u, stats = ui["user"], ui.get("stats", {})
        S, e = self.name, entity
        url = f"https://www.tiktok.com/@{u['uniqueId']}"
        created = dt.datetime.fromtimestamp(u.get("createTime", 0), dt.timezone.utc).date().isoformat() if u.get("createTime") else None
        yield _f(S, e, "account", "TikTok", url, url, 0.97, user_id=u.get("id"), created=created,
                 followers=stats.get("followerCount"), videos=stats.get("videoCount"), private=u.get("privateAccount"))
        if u.get("nickname"):
            yield _f(S, e, "profile", "TikTok nickname", u["nickname"], url, 0.8, display_name=u["nickname"])
        if u.get("signature"):
            yield _f(S, e, "profile", "TikTok bio", u["signature"], url, 0.85, pivots=_link_pivots(u["signature"], user))
        link = (u.get("bioLink") or {}).get("link")
        if link:
            yield _f(S, e, "profile", "TikTok bio link", link, link, 0.9, pivots=_link_pivots(link, user))
        if u.get("region"):
            yield _f(S, e, "location", "TikTok region", u["region"], url, 0.8)
        if u.get("language"):
            yield _f(S, e, "profile", "TikTok language", u["language"], url, 0.7)
        pic = u.get("avatarLarger") or u.get("avatarMedium")
        if pic:
            yield _f(S, e, "image", "TikTok avatar", pic, pic, 0.9, profile=url)


class TelegramSource(Source):
    name = "telegram"
    kinds = ("username",)
    description = "Telegram public user/channel page: display name, bio, members, photo"

    async def search(self, entity: Entity, ctx: Context):
        user = entity.value
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", user):
            return
        try:
            r = await ctx.get(f"https://t.me/{user}")
        except httpx.HTTPError:
            return
        page = r.text
        if "tgme_page_title" not in page:
            return
        title = re.search(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', page, re.S)
        desc = re.search(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', page, re.S)
        extra = re.search(r'<div class="tgme_page_extra">(.*?)</div>', page, re.S)
        img = re.search(r'<img class="tgme_page_photo_image"[^>]+src="([^"]+)"', page)
        S, e = self.name, entity
        url = f"https://t.me/{user}"
        kind = "channel/group" if extra and ("subscriber" in extra.group(1) or "member" in extra.group(1)) else "user"
        yield _f(S, e, "account", f"Telegram ({kind})", url, url, 0.95,
                 members=htmlmod.unescape(extra.group(1)).strip() if extra else None)
        if title:
            name = htmlmod.unescape(re.sub(r"<[^>]+>", "", title.group(1))).strip()
            yield _f(S, e, "profile", "Telegram display name", name, url, 0.8, display_name=name)
        if desc:
            text = htmlmod.unescape(re.sub(r"<br\s*/?>", "\n", desc.group(1)))
            text = re.sub(r"<[^>]+>", "", text).strip()
            if text:
                yield _f(S, e, "profile", "Telegram bio", text, url, 0.85, pivots=_link_pivots(desc.group(1) + " " + text, user))
        if img:
            yield _f(S, e, "image", "Telegram photo", img.group(1), img.group(1), 0.85, profile=url)


# ----------------------------------------------------------------------------- Reddit (login)

class RedditSource(Source):
    name = "reddit"
    kinds = ("username",)
    description = "Reddit account age, karma, bio, top communities and activity-hour timezone (needs Reddit app id/secret)"
    requires = ("reddit_client_id", "reddit_client_secret")

    async def _token(self, ctx: Context) -> str | None:
        auth = base64.b64encode(f"{ctx.config.get('reddit_client_id')}:{ctx.config.get('reddit_client_secret')}".encode()).decode()
        try:
            r = await ctx.post("https://www.reddit.com/api/v1/access_token", data={"grant_type": "client_credentials"},
                               headers={"Authorization": f"Basic {auth}", "User-Agent": "panoptes-osint/0.3"})
            return r.json().get("access_token")
        except (httpx.HTTPError, ValueError):
            return None

    async def search(self, entity: Entity, ctx: Context):
        token = await ctx.once("reddit-token", lambda: self._token(ctx))
        if not token:
            ctx.log("reddit: could not authenticate - check reddit_client_id / reddit_client_secret", "error")
            return
        h = {"Authorization": f"bearer {token}", "User-Agent": "panoptes-osint/0.3"}
        user = entity.value
        try:
            r = await ctx.get(f"https://oauth.reddit.com/user/{user}/about", headers=h)
            if r.status_code != 200:
                return
            d = r.json().get("data", {})
        except (httpx.HTTPError, ValueError):
            return
        if d.get("is_suspended") is None and not d.get("name"):
            return
        S, e = self.name, entity
        url = f"https://www.reddit.com/user/{d.get('name', user)}"
        created = dt.datetime.fromtimestamp(d.get("created_utc", 0), dt.timezone.utc).date().isoformat()
        yield _f(S, e, "account", "Reddit", url, url, 0.98, created=created, karma=d.get("total_karma"),
                 suspended=d.get("is_suspended"))
        bio = (d.get("subreddit") or {}).get("public_description")
        if bio:
            yield _f(S, e, "profile", "Reddit bio", bio, url, 0.85, pivots=_link_pivots(bio, user))
        title = (d.get("subreddit") or {}).get("title")
        if title:
            yield _f(S, e, "profile", "Reddit display name", title, url, 0.7, display_name=title)
        subs, times = Counter(), []
        for kind in ("comments", "submitted"):
            try:
                rr = await ctx.get(f"https://oauth.reddit.com/user/{user}/{kind}", params={"limit": 100}, headers=h)
                for c in rr.json().get("data", {}).get("children", []):
                    cd = c.get("data", {})
                    subs[cd.get("subreddit", "")] += 1
                    if cd.get("created_utc"):
                        times.append(dt.datetime.fromtimestamp(cd["created_utc"], dt.timezone.utc))
            except (httpx.HTTPError, ValueError):
                continue
        if subs:
            yield _f(S, e, "activity", "Reddit top communities",
                     ", ".join(f"r/{s} ({n})" for s, n in subs.most_common(12) if s), url, 0.85)
        tz = activity_timezone(times)
        if tz:
            yield _f(S, e, "activity", "Reddit posting hours", tz[0], url, 0.6)
            yield _f(S, e, "location", "Timezone (from Reddit activity)", tz[1], url, 0.5)


# ----------------------------------------------------------------------------- link pages

LINK_PAGE_HOSTS = {"linktr.ee", "beacons.ai", "bio.link", "solo.to", "about.me", "carrd.co", "lnk.bio", "taplink.cc",
                   "campsite.bio", "msha.ke", "allmylinks.com", "hoo.be", "linkin.bio", "bio.site", "withkoji.com",
                   "linkfly.to", "contactinbio.com", "lnkfi.re", "snipfeed.co", "stan.store", "koji.to", "flow.page"}
SKIP_LINK_HOSTS = ("linktr.ee", "linktree", "beacons.ai", "cloudflare", "googletagmanager", "google-analytics",
                   "gstatic", "facebook.net", "apple.com/app", "play.google.com", "w3.org", "schema.org", "jsdelivr",
                   "cdn.", "fonts.", "static.", "sentry")


def is_link_page(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    return host in LINK_PAGE_HOSTS or host.endswith(".carrd.co")


class LinkPagesSource(Source):
    """Every link the owner put on their Linktree-style page is a self-declared account or site."""

    name = "link-pages"
    kinds = ("username",)
    stage = "late"
    description = "Parses Linktree, Beacons, bio.link, about.me, carrd and similar pages for owner-declared accounts"

    async def search(self, entity: Entity, ctx: Context):
        urls = set()
        for f in findings_for(ctx, entity):
            for candidate in (f.url, f.value, *re.findall(r"https?://\S+", f.value)):
                if candidate and is_link_page(candidate) and f.confidence >= 0.6:
                    urls.add(candidate.split("?")[0].rstrip("/"))
        for page_url in list(urls)[:5]:
            try:
                r = await ctx.get(page_url)
                if r.status_code != 200:
                    continue
            except httpx.HTTPError:
                continue
            page_host = urlparse(page_url).hostname
            links = set()
            for href in re.findall(r'href="([^"]+)"', r.text):
                full = urljoin(page_url, htmlmod.unescape(href))
                host = (urlparse(full).hostname or "").lower()
                if full.startswith("mailto:"):
                    links.add(full)
                elif full.startswith("http") and host and host != page_host and not any(s in full for s in SKIP_LINK_HOSTS):
                    links.add(full.split("#")[0])
            for link in sorted(links)[:60]:
                if link.startswith("mailto:"):
                    email = link[7:].split("?")[0].lower()
                    yield _f(self.name, entity, "email", "Email on link page", email, page_url, 0.92,
                             pivots=[Entity("email", email)])
                    continue
                handle = social_handle(link)
                if handle:
                    piv = [Entity("username", handle)] if handle.lower() != entity.value.lower() else []
                    yield _f(self.name, entity, "account", f"{urlparse(link).hostname.removeprefix('www.')} (link page)",
                             link, link, 0.93, pivots=piv, declared_on=page_url)
                else:
                    yield _f(self.name, entity, "profile", "Link on link page", link, link, 0.85,
                             pivots=_link_pivots(link, entity.value), declared_on=page_url)
            ctx.shared.setdefault("outlinks", {}).setdefault(str(entity), set()).update(links)
