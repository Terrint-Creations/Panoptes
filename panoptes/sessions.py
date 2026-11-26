"""Site logins: browser sessions for sites that block anonymous lookups (Facebook, LinkedIn, …).

Log in to the site in your browser (use a separate burner account), copy the request's Cookie header from
DevTools → Network, and save it here per site. Panoptes then sends that cookie - only to that site and its
subdomains - on every check, so the site answers as it would for a logged-in user.
Stored locally in ~/.panoptes/sessions.json.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from panoptes.config import DATA_DIR

FILE = DATA_DIR / "sessions.json"
_cache: dict[str, str] | None = None


def load() -> dict[str, str]:
    global _cache
    if _cache is None:
        try:
            _cache = {k.lower().removeprefix("www."): v for k, v in json.loads(FILE.read_text(encoding="utf-8")).items()}
        except (OSError, ValueError):
            _cache = {}
    return _cache


def save(sessions: dict[str, str]) -> None:
    global _cache
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    clean = {k.strip().lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").split("/")[0]: v.strip()
             for k, v in sessions.items() if k.strip() and v.strip()}
    FILE.write_text(json.dumps(clean, indent=1), encoding="utf-8")
    _cache = clean


def cookie_for(url: str) -> str | None:
    """The saved cookie for this URL's site (exact host or a parent domain), if any."""
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    sessions = load()
    while host:
        if host in sessions:
            return sessions[host]
        host = host.partition(".")[2] if host.count(".") >= 1 else ""
    return None


def to_text(sessions: dict[str, str]) -> str:
    return "\n".join(f"{k} = {v}" for k, v in sorted(sessions.items()))


def from_text(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out
