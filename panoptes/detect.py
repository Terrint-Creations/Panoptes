"""Figure out what kind of thing the user typed."""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

from panoptes.models import KINDS, Entity

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
BTC_RE = re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
FILE_EXTS = (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic", ".webp", ".gif", ".pdf", ".docx", ".xlsx",
             ".pptx", ".doc", ".xls", ".odt", ".mp4", ".mov", ".mp3", ".wav")
PHONE_RE = re.compile(r"^\+?[\d\s().\-]{7,20}$")
COORD_RE = re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*[, ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$")
ONION_RE = re.compile(r"^(?:https?://)?([a-z2-7]{16}|[a-z2-7]{56})\.onion(?:[/:].*)?$", re.I)
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}$")
COMPANY_RE = re.compile(r"\b(inc|inc\.|llc|l\.l\.c\.|ltd|ltd\.|limited|gmbh|corp|corp\.|corporation|plc|s\.a\.|"
                        r"sa|ag|bv|b\.v\.|nv|srl|s\.r\.l\.|oy|ab|as|pty|co\.|company|holdings|group)$", re.I)

# host -> regex capturing the handle from the URL path
SOCIAL_PROFILE_PATTERNS: dict[str, re.Pattern] = {
    "github.com": re.compile(r"^/([A-Za-z0-9\-]{1,39})/?$"),
    "twitter.com": re.compile(r"^/([A-Za-z0-9_]{1,15})/?$"),
    "x.com": re.compile(r"^/([A-Za-z0-9_]{1,15})/?$"),
    "instagram.com": re.compile(r"^/([A-Za-z0-9_.]{1,30})/?$"),
    "tiktok.com": re.compile(r"^/@([A-Za-z0-9_.]{1,30})/?$"),
    "reddit.com": re.compile(r"^/(?:u|user)/([A-Za-z0-9_\-]{3,20})/?$"),
    "youtube.com": re.compile(r"^/@([A-Za-z0-9_.\-]{3,30})/?$"),
    "twitch.tv": re.compile(r"^/([A-Za-z0-9_]{3,25})/?$"),
    "gitlab.com": re.compile(r"^/([A-Za-z0-9_.\-]{2,255})/?$"),
    "medium.com": re.compile(r"^/@([A-Za-z0-9_.]{1,30})/?$"),
    "keybase.io": re.compile(r"^/([A-Za-z0-9_]{2,16})/?$"),
    "facebook.com": re.compile(r"^/([A-Za-z0-9.]{5,50})/?$"),
    "linkedin.com": re.compile(r"^/in/([A-Za-z0-9\-_%]{3,100})/?$"),
    "t.me": re.compile(r"^/([A-Za-z0-9_]{5,32})/?$"),
    "revolut.me": re.compile(r"^/([A-Za-z0-9_.\-]{2,40})/?$"),
    "paypal.me": re.compile(r"^/([A-Za-z0-9_.\-]{2,40})/?$"),
    "cash.app": re.compile(r"^/\$([A-Za-z0-9_.\-]{1,30})/?$"),
    "venmo.com": re.compile(r"^/(?:u/)?([A-Za-z0-9_.\-]{2,40})/?$"),
    "ko-fi.com": re.compile(r"^/([A-Za-z0-9_]{2,40})/?$"),
    "buymeacoffee.com": re.compile(r"^/([A-Za-z0-9_]{2,40})/?$"),
    "pinterest.com": re.compile(r"^/([A-Za-z0-9_]{3,30})/?$"),
    "open.spotify.com": re.compile(r"^/user/([A-Za-z0-9_.\-]{2,40})/?$"),
    "steamcommunity.com": re.compile(r"^/id/([A-Za-z0-9_\-]{2,32})/?$"),
    "soundcloud.com": re.compile(r"^/([A-Za-z0-9_\-]{3,30})/?$"),
    "linktr.ee": re.compile(r"^/([A-Za-z0-9_.]{2,40})/?$"),
    "threads.com": re.compile(r"^/@([A-Za-z0-9_.]{1,30})/?$"),
    "threads.net": re.compile(r"^/@([A-Za-z0-9_.]{1,30})/?$"),
    "bsky.app": re.compile(r"^/profile/([A-Za-z0-9_.\-]{3,60})/?$"),
    "kick.com": re.compile(r"^/([A-Za-z0-9_]{3,25})/?$"),
    "snapchat.com": re.compile(r"^/(?:add/|@)([A-Za-z0-9_.\-]{3,15})/?$"),
}
RESERVED_PATHS = {"login", "signup", "about", "home", "explore", "search", "settings", "help",
                  "share", "intent", "i", "hashtag", "watch", "p", "sharer", "dialog", "privacy",
                  "terms", "pages", "groups", "events", "orgs", "features", "pricing"}


def social_handle(url: str) -> str | None:
    """Return the username if `url` is a profile link on a known social platform."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    pattern = SOCIAL_PROFILE_PATTERNS.get(host)
    if not pattern:
        return None
    m = pattern.match(parsed.path or "/")
    if m and m.group(1).lower() not in RESERVED_PATHS:
        return m.group(1)
    return None


def detect_kind(value: str) -> str:
    v = value.strip().strip('"')
    if os.path.isfile(v) and ("/" in v or "\\" in v or v.lower().endswith(FILE_EXTS)):
        return "file"
    if ONION_RE.match(v):
        return "onion"
    if MAC_RE.match(v):
        return "bssid"
    m = COORD_RE.match(v)
    if m and abs(float(m.group(1))) <= 90 and abs(float(m.group(2))) <= 180 and "." in v:
        return "location"
    if EMAIL_RE.match(v):
        return "email"
    if BTC_RE.match(v) or ETH_RE.match(v):
        return "crypto"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if PHONE_RE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return "phone"
    if v.lower().startswith(("http://", "https://")):
        if urlparse(v).path.lower().endswith(FILE_EXTS):
            return "file"
        return "url"
    if DOMAIN_RE.match(v):
        return "domain"
    if " " in v:
        return "company" if COMPANY_RE.search(v) else "name"
    return "username"


def parse_target(value: str, kind: str | None = None) -> Entity:
    """Turn raw user input into an Entity, auto-detecting the kind if not given."""
    v = value.strip().strip('"')
    if kind and kind != "auto":
        if kind not in KINDS:
            raise ValueError(f"Unknown target type '{kind}'. Choose from: {', '.join(KINDS)}")
        if kind == "domain":
            v = normalize_domain(v)
        return Entity(kind, v.lstrip("@") if kind == "username" else v)
    detected = detect_kind(v)
    if detected == "onion":
        return Entity("onion", ONION_RE.match(v).group(1).lower() + ".onion")
    if detected == "bssid":
        return Entity("bssid", v.replace("-", ":").upper())
    if detected == "url":
        handle = social_handle(v)
        if handle:
            return Entity("username", handle)
        return Entity("domain", normalize_domain(v))
    if detected == "domain":
        return Entity("domain", normalize_domain(v))
    if detected == "username":
        return Entity("username", v.lstrip("@"))
    return Entity(detected, v)


def normalize_domain(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        v = urlparse(v).hostname or v
    v = v.split("/")[0].split(":")[0].rstrip(".")
    return v.removeprefix("www.")


def parse_all(value: str) -> list[Entity]:
    """Target type 'all': every plausible reading of the input (a handle, a person's name, the detected type…)."""
    v = value.strip().strip('"')
    out: list[Entity] = []
    try:
        out.append(parse_target(v))
    except ValueError:
        pass
    kind = detect_kind(v)
    if " " in v:
        out.append(Entity("name", " ".join(w if w[:1].isupper() else w.capitalize() for w in v.split())))
        handle = re.sub(r"[^A-Za-z0-9_.]", "", v)
        if 3 <= len(handle) <= 30:
            out.append(Entity("username", handle))
        out.append(Entity("company", v))
    elif kind == "email":
        out.append(Entity("username", v.split("@")[0]))
        out.append(Entity("domain", v.split("@")[1].lower()))
    elif kind == "username" and re.fullmatch(r"[A-Za-z0-9_.\-]{2,40}", v):
        out.append(Entity("username", v.lstrip("@")))
    seen, res = set(), []
    for e in out:
        if e.key() not in seen:
            seen.add(e.key())
            res.append(e)
    return res
