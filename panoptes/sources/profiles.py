"""Platform profile APIs - real names, locations, emails, avatars and linked accounts.

Account-existence checks only say *that* a profile exists. These parsers read what the profile says:
Duolingo, Codewars, LeetCode, Codeforces, Lichess, Twitch, Docker Hub, Minecraft, Roblox, Bluesky,
YouTube, Steam, npm (publisher emails), Gravatar, and GitHub's public GPG/SSH keys (key e-mails).
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import html as htmlmod
import json
import re

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, USER_AGENT, Context, Source, extract_emails

YT_CONSENT = {"Cookie": "SOCS=CAI; CONSENT=YES+cb", "Accept-Language": "en-US,en;q=0.9"}


def _ts(v) -> str | None:
    try:
        if isinstance(v, (int, float)):
            return dt.datetime.fromtimestamp(v / 1000 if v > 1e11 else v, dt.timezone.utc).date().isoformat()
        return str(v)[:10] if v else None
    except (ValueError, OSError):
        return None


class _Out:
    """Collects findings for one platform with consistent shapes."""

    def __init__(self, source: str, entity: Entity, platform: str, url: str):
        self.s, self.e, self.p, self.url = source, entity, platform, url
        self.items: list[Finding] = []

    def account(self, conf=0.97, **data):
        self.items.append(Finding(category="account", title=self.p, value=self.url, url=self.url, source=self.s,
                                  target=self.e, confidence=conf, data={k: v for k, v in data.items() if v not in (None, "", [], 0)}))

    def field(self, title, value, cat="profile", conf=0.85, pivots=(), url=None, **data):
        if value in (None, "", [], "null"):
            return
        v = str(value).strip()
        if not v:
            return
        self.items.append(Finding(category=cat, title=f"{self.p} {title}", value=v[:800], url=url or self.url, source=self.s,
                                  target=self.e, confidence=conf, pivots=list(pivots),
                                  data={k: x for k, x in data.items() if x not in (None, "", [])}))

    def name(self, value, conf=0.85):
        if value and str(value).strip().lower() != self.e.value.lower():
            v = str(value).strip()
            self.field("name", v, conf=conf, pivots=[Entity("name", v)] if len(v.split()) >= 2 else [], display_name=v)

    def display(self, value):
        if value and str(value).strip().lower() != self.e.value.lower():
            self.field("display name", value, conf=0.75, display_name=str(value).strip())

    def location(self, value, conf=0.8):
        if value and str(value).strip():
            self.field("location", value, cat="location", conf=conf, pivots=[Entity("location", str(value).strip())])

    def avatar(self, url):
        if url and str(url).startswith("http") and not re.search(r"default|no-?title|no-?avatar|placeholder|blank", url, re.I):
            self.items.append(Finding(category="image", title=f"{self.p} avatar", value=url, url=url, source=self.s,
                                      target=self.e, confidence=0.9, data={"profile": self.url}))

    def email(self, value, conf=0.9, how=""):
        if value and "@" in value and "noreply" not in value:
            self.field("email", value.lower(), cat="email", conf=conf, pivots=[Entity("email", value.lower())], via=how)

    def bio(self, value):
        if value and str(value).strip():
            from panoptes.sources.platforms import _link_pivots
            self.field("bio", value, conf=0.8, pivots=_link_pivots(str(value), self.e.value))


class PlatformIntelSource(Source):
    name = "platform-intel"
    kinds = ("username",)
    description = ("Reads profile data (real name, location, email, avatar, links) from Duolingo, Codewars, LeetCode, "
                   "Codeforces, Lichess, Twitch, Docker Hub, Minecraft, Roblox, Bluesky, YouTube, Steam, npm, Gravatar, "
                   "GitHub GPG/SSH keys")

    async def search(self, entity: Entity, ctx: Context):
        u = entity.value
        parsers = [self._pinterest, self._spotify, self._duolingo, self._codewars, self._leetcode, self._codeforces, self._lichess, self._twitch,
                   self._dockerhub, self._minecraft, self._roblox, self._bluesky, self._youtube, self._steam, self._npm,
                   self._gravatar, self._github_keys]

        async def safe(fn):
            try:
                return await fn(u, entity, ctx)
            except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
                ctx.log(f"platform-intel/{fn.__name__.strip('_')}: {exc.__class__.__name__}", "debug")
                return []
        for fut in asyncio.as_completed([safe(p) for p in parsers]):
            for f in await fut or []:
                yield f

    # ------------------------------------------------------------------ parsers
    async def _pinterest(self, u, e, ctx):
        r = await ctx.get(f"https://www.pinterest.com/{u}/", headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US"})
        if r.status_code != 200:
            return []
        page = r.text
        # the profile's user object sits in the embedded JSON; find the one whose username is ours
        m = re.search(r'\{[^{}]*"username":"%s"[^{}]*\}' % re.escape(u), page, re.I)
        blob = m.group(0) if m else ""
        full = re.search(r'"full_name":"([^"]{1,80})"', blob)
        if not full:
            return []
        dec = lambda x: json.loads(f'"{x}"') if x else x
        o = _Out(self.name, e, "Pinterest", f"https://www.pinterest.com/{u}/")
        followers = re.search(r'"follower_count":(\d+)', blob)
        o.account(followers=int(followers.group(1)) if followers else None)
        o.name(dec(full.group(1)))
        about = re.search(r'"about":"([^"]{1,500})"', blob)
        if about:
            o.bio(dec(about.group(1)))
        loc = re.search(r'"location":"([^"]{1,100})"', blob)
        if loc:
            o.location(dec(loc.group(1)))
        img = re.search(r'"image_xlarge_url":"([^"]+)"', blob) or re.search(r'"image_large_url":"([^"]+)"', blob)
        if img:
            o.avatar(dec(img.group(1)))
        site = re.search(r'"website_url":"([^"]+)"', blob)
        if site:
            o.field("website", dec(site.group(1)), conf=0.9)
        return o.items

    async def _spotify(self, u, e, ctx):
        cid, secret = ctx.config.get("spotify_client_id"), ctx.config.get("spotify_client_secret")
        if not (cid and secret):
            return []

        async def token():
            r = await ctx.post("https://accounts.spotify.com/api/token", data={"grant_type": "client_credentials"},
                               auth=(cid, secret))
            return r.json().get("access_token") if r.status_code == 200 else None
        tok = await ctx.once("spotify-token", token)
        if not tok:
            ctx.log("platform-intel: Spotify client id/secret rejected", "warning")
            return []
        r = await ctx.get(f"https://api.spotify.com/v1/users/{u}", headers={"Authorization": f"Bearer {tok}"})
        if r.status_code != 200:
            return []
        d = r.json()
        o = _Out(self.name, e, "Spotify", (d.get("external_urls") or {}).get("spotify") or f"https://open.spotify.com/user/{u}")
        o.account(followers=(d.get("followers") or {}).get("total"))
        dn = d.get("display_name")
        if dn and len(dn.split()) >= 2:
            o.name(dn)
        else:
            o.display(dn)
        imgs = d.get("images") or []
        if imgs:
            o.avatar(imgs[0].get("url"))
        return o.items

    async def _duolingo(self, u, e, ctx):
        r = await ctx.get("https://www.duolingo.com/2017-06-30/users", params={"username": u}, headers=API_HEADERS)
        users = r.json().get("users", []) if r.status_code == 200 else []
        d = next((x for x in users if x.get("username", "").lower() == u.lower()), None)
        if not d:
            return []
        o = _Out(self.name, e, "Duolingo", f"https://www.duolingo.com/profile/{d['username']}")
        langs = sorted({c.get("title") for c in d.get("courses", []) if c.get("title")})
        o.account(created=_ts(d.get("creationDate")), streak=d.get("streak"), learning=langs,
                  interface_language=d.get("fromLanguage"))
        o.name(d.get("name"))
        o.bio(d.get("bio"))
        if d.get("picture"):
            o.avatar("https:" + d["picture"] + "/xlarge" if d["picture"].startswith("//") else d["picture"])
        if d.get("fromLanguage"):
            o.field("interface language", d["fromLanguage"], conf=0.6)
        if langs:
            o.field("learning", ", ".join(langs), cat="activity", conf=0.8)
        return o.items

    async def _codewars(self, u, e, ctx):
        r = await ctx.get(f"https://www.codewars.com/api/v1/users/{u}", headers=API_HEADERS)
        if r.status_code != 200:
            return []
        d = r.json()
        o = _Out(self.name, e, "Codewars", f"https://www.codewars.com/users/{d.get('username', u)}")
        o.account(honor=d.get("honor"), rank=(d.get("ranks") or {}).get("overall", {}).get("name"))
        o.name(d.get("name"), 0.88)
        o.field("clan / organisation", d.get("clan"), conf=0.8, pivots=[Entity("company", d["clan"])] if d.get("clan") else [])
        if d.get("skills"):
            o.field("skills", ", ".join(d["skills"][:12]), cat="activity", conf=0.7)
        return o.items

    async def _leetcode(self, u, e, ctx):
        q = {"query": "query($u:String!){matchedUser(username:$u){username profile{realName countryName aboutMe userAvatar "
                      "websites school company}}}", "variables": {"u": u}}
        r = await ctx.post("https://leetcode.com/graphql", json=q,
                           headers={"User-Agent": USER_AGENT, "Referer": "https://leetcode.com", "Content-Type": "application/json"})
        m = (r.json().get("data") or {}).get("matchedUser") if r.status_code == 200 else None
        if not m:
            return []
        p = m.get("profile") or {}
        o = _Out(self.name, e, "LeetCode", f"https://leetcode.com/u/{m['username']}/")
        o.account()
        o.name(p.get("realName"))
        o.location(p.get("countryName"))
        o.bio(p.get("aboutMe"))
        o.field("school", p.get("school"), conf=0.8)
        o.field("company", p.get("company"), conf=0.8)
        for w in p.get("websites") or []:
            o.field("website", w, conf=0.85, url=w)
        if p.get("userAvatar") and "default_avatar" not in p["userAvatar"]:
            o.avatar(p["userAvatar"])
        return o.items

    async def _codeforces(self, u, e, ctx):
        r = await ctx.get("https://codeforces.com/api/user.info", params={"handles": u}, headers=API_HEADERS)
        d = r.json()
        if d.get("status") != "OK":
            return []
        x = d["result"][0]
        o = _Out(self.name, e, "Codeforces", f"https://codeforces.com/profile/{x['handle']}")
        o.account(rating=x.get("rating"), registered=_ts(x.get("registrationTimeSeconds")))
        o.name(" ".join(p for p in (x.get("firstName"), x.get("lastName")) if p))
        o.location(", ".join(p for p in (x.get("city"), x.get("country")) if p))
        o.field("organisation", x.get("organization"), conf=0.8)
        if x.get("titlePhoto") and "no-avatar" not in x["titlePhoto"]:
            o.avatar(x["titlePhoto"])
        return o.items

    async def _lichess(self, u, e, ctx):
        r = await ctx.get(f"https://lichess.org/api/user/{u}", headers=API_HEADERS)
        if r.status_code != 200:
            return []
        d = r.json()
        p = d.get("profile") or {}
        o = _Out(self.name, e, "Lichess", d.get("url") or f"https://lichess.org/@/{u}")
        o.account(created=_ts(d.get("createdAt")), seen=_ts(d.get("seenAt")))
        o.name(" ".join(x for x in (p.get("firstName"), p.get("lastName"), p.get("realName")) if x))
        o.location(p.get("location"))
        o.field("country", p.get("flag") or p.get("country"), cat="location", conf=0.8)
        o.bio(p.get("bio"))
        for link in (p.get("links") or "").split():
            o.field("link", link, conf=0.85, url=link if link.startswith("http") else None)
        return o.items

    async def _twitch(self, u, e, ctx):
        q = {"query": 'query{user(login:"%s"){login displayName description createdAt profileImageURL(width:300) '
                      'channel{socialMedias{title url}}}}' % u.lower()}
        r = await ctx.post("https://gql.twitch.tv/gql", json=q, headers={**API_HEADERS, "Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko"})
        d = (r.json().get("data") or {}).get("user") if r.status_code == 200 else None
        if not d:
            return []
        o = _Out(self.name, e, "Twitch", f"https://www.twitch.tv/{d['login']}")
        o.account(created=_ts(d.get("createdAt")))
        o.display(d.get("displayName") if d.get("displayName", "").lower() != d["login"] else None)
        o.bio(d.get("description"))
        if d.get("profileImageURL") and "user-default" not in d["profileImageURL"]:
            o.avatar(d["profileImageURL"])
        for sm in ((d.get("channel") or {}).get("socialMedias") or []):
            from panoptes.sources.platforms import _link_pivots
            o.field(f"linked {sm.get('title') or 'site'}", sm.get("url"), conf=0.92, url=sm.get("url"),
                    pivots=_link_pivots(sm.get("url", ""), u))
        return o.items

    async def _dockerhub(self, u, e, ctx):
        r = await ctx.get(f"https://hub.docker.com/v2/users/{u}", headers=API_HEADERS)
        if r.status_code != 200:
            return []
        d = r.json()
        o = _Out(self.name, e, "Docker Hub", f"https://hub.docker.com/u/{d.get('username', u)}")
        o.account(joined=_ts(d.get("date_joined")))
        o.name(d.get("full_name"))
        o.location(d.get("location"))
        o.field("company", d.get("company"), conf=0.8)
        o.field("website", d.get("profile_url"), conf=0.85)
        return o.items

    async def _minecraft(self, u, e, ctx):
        r = await ctx.get(f"https://api.mojang.com/users/profiles/minecraft/{u}", headers=API_HEADERS)
        if r.status_code != 200 or not r.text.strip():
            return []
        d = r.json()
        o = _Out(self.name, e, "Minecraft", f"https://namemc.com/profile/{d['id']}")
        o.account(uuid=d["id"], exact_name=d.get("name"))
        o.avatar(f"https://mc-heads.net/avatar/{d['id']}/256")
        return o.items

    async def _roblox(self, u, e, ctx):
        r = await ctx.post("https://users.roblox.com/v1/usernames/users", json={"usernames": [u], "excludeBannedUsers": False},
                           headers=API_HEADERS)
        data = r.json().get("data") or []
        if not data:
            return []
        uid = data[0]["id"]
        d = (await ctx.get(f"https://users.roblox.com/v1/users/{uid}", headers=API_HEADERS)).json()
        o = _Out(self.name, e, "Roblox", f"https://www.roblox.com/users/{uid}/profile")
        o.account(created=_ts(d.get("created")), banned=d.get("isBanned"))
        o.display(d.get("displayName") if d.get("displayName", "").lower() != u.lower() else None)
        o.bio(d.get("description"))
        return o.items

    async def _bluesky(self, u, e, ctx):
        actor = u if "." in u else f"{u}.bsky.social"
        r = await ctx.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile", params={"actor": actor},
                          headers=API_HEADERS)
        if r.status_code != 200:
            return []
        d = r.json()
        o = _Out(self.name, e, "Bluesky", f"https://bsky.app/profile/{d['handle']}")
        o.account(followers=d.get("followersCount"), created=_ts(d.get("createdAt")), did=d.get("did"))
        o.display(d.get("displayName"))
        o.bio(d.get("description"))
        o.avatar(d.get("avatar"))
        return o.items

    async def _youtube(self, u, e, ctx):
        r = await ctx.get(f"https://www.youtube.com/@{u}", headers={"User-Agent": USER_AGENT, **YT_CONSENT})
        if r.status_code != 200:
            return []
        m = re.search(r"var ytInitialData = (\{.*?\});</script>", r.text, re.S)
        if not m:
            return []
        data = json.loads(m.group(1))
        md = (data.get("metadata") or {}).get("channelMetadataRenderer") or {}
        if not md.get("title"):
            return []
        o = _Out(self.name, e, "YouTube", md.get("vanityChannelUrl") or f"https://www.youtube.com/@{u}")
        o.account(channel_id=md.get("externalId"), keywords=md.get("keywords"))
        o.display(md.get("title"))
        o.bio(md.get("description"))
        thumbs = (md.get("avatar") or {}).get("thumbnails") or []
        if thumbs:
            o.avatar(thumbs[-1]["url"])
        from urllib.parse import unquote
        for q in sorted(set(re.findall(r'youtube\.com/redirect\?[^"]*?q=([^"&\\]+)', m.group(1))))[:10]:
            link = unquote(q)
            from panoptes.sources.platforms import _link_pivots
            o.field("linked site", link, conf=0.85, url=link, pivots=_link_pivots(link, u))
        return o.items

    async def _steam(self, u, e, ctx):
        r = await ctx.get(f"https://steamcommunity.com/id/{u}", params={"xml": 1})
        if r.status_code != 200 or "<steamID64>" not in r.text:
            return []
        x = lambda tag: (lambda m: htmlmod.unescape(m.group(1)).strip() if m else None)(
            re.search(rf"<{tag}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{tag}>", r.text, re.S))
        sid = x("steamID64")
        o = _Out(self.name, e, "Steam", f"https://steamcommunity.com/profiles/{sid}")
        o.account(steam_id=sid, member_since=x("memberSince"), privacy=x("privacyState"), vac=x("vacBanned"))
        o.display(x("steamID"))
        o.name(x("realname"))
        o.location(x("location"))
        o.bio(re.sub(r"<[^>]+>", " ", x("summary") or ""))
        o.avatar(x("avatarFull"))
        return o.items

    async def _npm(self, u, e, ctx):
        r = await ctx.get("https://registry.npmjs.org/-/v1/search", params={"text": f"maintainer:{u}", "size": 20},
                          headers=API_HEADERS)
        objs = r.json().get("objects", []) if r.status_code == 200 else []
        emails = set()
        for ob in objs:
            for m in ob.get("package", {}).get("maintainers", []) + [ob.get("package", {}).get("publisher") or {}]:
                if m.get("username", "").lower() == u.lower() and m.get("email"):
                    emails.add(m["email"].lower())
        if not objs:
            return []
        o = _Out(self.name, e, "npm", f"https://www.npmjs.com/~{u}")
        o.account(packages=len(objs))
        for em in sorted(emails):
            o.email(em, 0.92, "npm package publisher record")
        return o.items

    async def _gravatar(self, u, e, ctx):
        r = await ctx.get(f"https://api.gravatar.com/v3/profiles/{u}", headers=API_HEADERS)
        if r.status_code != 200:
            return []
        d = r.json()
        o = _Out(self.name, e, "Gravatar", d.get("profile_url") or f"https://gravatar.com/{u}")
        o.account()
        o.name(d.get("display_name"))
        o.location(d.get("location"))
        o.bio(d.get("description"))
        o.avatar(d.get("avatar_url"))
        for acct in d.get("verified_accounts") or []:
            o.field(f"verified {acct.get('service_label', 'account')}", acct.get("url"), conf=0.95, url=acct.get("url"))
        return o.items

    async def _github_keys(self, u, e, ctx):
        out = []
        r = await ctx.get(f"https://github.com/{u}.gpg")
        if r.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in r.text and "hasn't uploaded" not in r.text:
            for uid in pgp_uids(r.text):
                o = _Out(self.name, e, "GitHub GPG key", f"https://github.com/{u}.gpg")
                for em in extract_emails(uid):
                    o.email(em, 0.95, "GPG key uploaded to GitHub")
                name = re.sub(r"\s*[<(].*$", "", uid).strip()
                if name and "@" not in name:
                    o.name(name, 0.9)
                out += o.items
        r = await ctx.get(f"https://github.com/{u}.keys")
        keys = [k for k in r.text.splitlines() if k.strip()] if r.status_code == 200 else []
        if keys:
            import hashlib
            fps = []
            for k in keys:
                try:
                    fps.append("SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(k.split()[1])).digest()).decode().rstrip("="))
                except (IndexError, ValueError):
                    continue
            out.append(Finding(category="key", title="GitHub SSH keys", value=f"{len(keys)} public key(s)", source=self.name,
                               target=e, url=f"https://github.com/{u}.keys", confidence=0.9,
                               data={"fingerprints": fps, "note": "the same key on another server/platform = same owner"}))
        return out


def pgp_uids(armored: str) -> list[str]:
    """Extract User ID strings from an ASCII-armored OpenPGP public key block (minimal packet parser)."""
    body = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----", armored, re.S)
    if not body:
        return []
    lines = [ln for ln in body.group(1).strip().splitlines() if ln and ":" not in ln[:20] and not ln.startswith("=")]
    try:
        data = base64.b64decode("".join(lines))
    except ValueError:
        return []
    uids, i = [], 0
    while i < len(data):
        tag = data[i]
        if not tag & 0x80:
            break
        if tag & 0x40:  # new format
            ptype = tag & 0x3F
            l1 = data[i + 1]
            if l1 < 192:
                length, hdr = l1, 2
            elif l1 < 224:
                length, hdr = ((l1 - 192) << 8) + data[i + 2] + 192, 3
            elif l1 == 255:
                length, hdr = int.from_bytes(data[i + 2:i + 6], "big"), 6
            else:
                break
        else:  # old format
            ptype = (tag >> 2) & 0x0F
            lt = tag & 3
            if lt == 0:
                length, hdr = data[i + 1], 2
            elif lt == 1:
                length, hdr = int.from_bytes(data[i + 1:i + 3], "big"), 3
            elif lt == 2:
                length, hdr = int.from_bytes(data[i + 1:i + 5], "big"), 5
            else:
                break
        if ptype == 13:
            uids.append(data[i + hdr:i + hdr + length].decode("utf-8", "replace"))
        i += hdr + length
    return uids
