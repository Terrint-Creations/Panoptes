"""Unified username site catalog.

Pulls the site databases maintained by Sherlock, WhatsMyName and Maigret, translates
every entry into one common rule format, and merges entries that point at the same
profile URL. A site known to several projects carries one detection rule per project;
the checker runs them all against the same response and takes a vote.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

import httpx

from panoptes.config import CACHE_DIR

DATABASES = {
    "sherlock": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    "whatsmyname": "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
    "maigret": "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
    "social-analyzer": "https://raw.githubusercontent.com/qeeqbox/social-analyzer/main/data/sites.json",
}
DB_PRIORITY = ("whatsmyname", "sherlock", "maigret", "social-analyzer", "discovered", "panoptes")  # whose display name/profile URL wins
MAX_AGE = 7 * 24 * 3600
U = "{U}"  # internal username placeholder

OK_2XX = frozenset(range(200, 300))
BELOW_400 = frozenset(range(200, 400))
NSFW_TAGS = {"porn", "nsfw", "adult", "xxx", "dating", "erotic"}


@dataclass(frozen=True)
class Probe:
    """One HTTP request. Rules sharing a Probe share the response."""
    url: str
    method: str = "GET"
    body: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    follow: bool = True


@dataclass
class Rule:
    db: str
    probe: Probe
    exists_codes: frozenset | None = None          # status must be in here to count as found
    exists_strings: tuple[str, ...] = ()           # at least one must appear (if any given)
    missing: tuple[tuple[frozenset | None, str | None], ...] = ()  # (codes, text) -> not found
    error_strings: tuple[str, ...] = ()            # text meaning "blocked / can't tell"
    no_redirect: bool = False                      # a redirect means not found
    allow_403: bool = False
    regex: str | None = None
    strip_chars: str = ""
    require_all: bool = False                      # every exists_string must appear (social-analyzer style)

    def applies_to(self, username: str) -> bool:
        if not self.regex:
            return True
        try:
            return re.search(self.regex, username) is not None
        except re.error:
            return True

    def evaluate(self, status: int, body: str, redirected: bool, username: str = "") -> bool | None:
        """True = account exists, False = doesn't, None = can't tell (blocked, error)."""
        sub = (lambda s: s.replace(U, username)) if username else (lambda s: s)
        if any(e in body for e in self.error_strings):
            return None
        explicit = set(self.exists_codes or ()) | {c for codes, _ in self.missing if codes for c in codes}
        if status in (401, 403, 429, 503) and status not in explicit and not (status == 403 and self.allow_403):
            return None
        if status >= 500 and status not in explicit:
            return None
        lowered_challenge = body[:4000].lower()
        if status in (403, 503) and ("cf-chl" in lowered_challenge or "just a moment" in lowered_challenge
                                     or "captcha" in lowered_challenge):
            return None
        for codes, text in self.missing:
            if (codes is None or status in codes) and (text is None or sub(text) in body):
                return False
        if self.no_redirect and (redirected or 300 <= status < 400):
            return False
        if self.exists_codes is not None and status not in self.exists_codes:
            return False
        if self.exists_strings:
            check = all if self.require_all else any
            if not check(sub(s) in body for s in self.exists_strings):
                return False
        return True


@dataclass
class Site:
    name: str
    profile_url: str
    key: str
    tags: set[str] = field(default_factory=set)
    nsfw: bool = False
    rank: int | None = None
    rules: list[Rule] = field(default_factory=list)

    @property
    def dbs(self) -> set[str]:
        return {r.db for r in self.rules}


# ----------------------------------------------------------------------------- cache

def cache_file(db: str):
    return CACHE_DIR / "sitedb" / f"{db}.json"


def cache_age(db: str) -> float | None:
    f = cache_file(db)
    return time.time() - f.stat().st_mtime if f.exists() else None


async def update_databases(client: httpx.AsyncClient, force: bool = False, log=print) -> dict[str, int]:
    """Download site databases that are missing or stale. Returns db -> site count."""
    counts = {}
    for db, url in DATABASES.items():
        age = cache_age(db)
        if force or age is None or age > MAX_AGE:
            try:
                r = await client.get(url, timeout=60)
                r.raise_for_status()
                data = r.json()
                f = cache_file(db)
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(json.dumps(data), encoding="utf-8")
                log(f"Updated {db} site database")
            except Exception as exc:  # network trouble: fall back to the cached copy
                log(f"Could not update {db} database ({exc.__class__.__name__}); using cached copy" if age is not None
                    else f"Could not download {db} database: {exc}")
        raw = load_raw(db)
        counts[db] = _raw_count(db, raw) if raw else 0
    counts["discovered"] = len(load_discovered())
    return counts


def load_raw(db: str) -> dict | None:
    f = cache_file(db)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _raw_count(db: str, raw: dict) -> int:
    if db == "sherlock":
        return sum(1 for v in raw.values() if isinstance(v, dict))
    if db == "social-analyzer":
        return len(raw.get("websites_entries", []))
    return len(raw.get("sites", []))


# ----------------------------------------------------------------------------- sites learned during searches

def discovered_file():
    return CACHE_DIR / "sitedb" / "discovered.json"


def load_discovered() -> dict:
    try:
        return json.loads(discovered_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_discovered(entries: dict) -> None:
    """entries: profile_url_template -> {"name": str, "seen": int}"""
    f = discovered_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(entries, indent=1), encoding="utf-8")


# ----------------------------------------------------------------------------- parsing helpers

def _codes(value) -> frozenset | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return frozenset(int(v) for v in value)
    return frozenset({int(value)})


def _strs(value) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value if v)


def _subst(obj, token: str):
    """Recursively replace a username token inside a JSON-ish payload."""
    if isinstance(obj, str):
        return obj.replace(token, U)
    if isinstance(obj, dict):
        return {k: _subst(v, token) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, token) for v in obj]
    return obj


def _headers(h) -> tuple[tuple[str, str], ...]:
    if not isinstance(h, dict):
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in h.items()))


def site_key(url: str) -> str:
    u = url.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    u = u.replace("/#!/", "/").rstrip("/")
    return u


# ----------------------------------------------------------------------------- per-database translators

def _from_sherlock(raw: dict):
    for name, s in raw.items():
        if not isinstance(s, dict) or "url" not in s:
            continue
        profile = s["url"].replace("{}", U)
        check_url = (s.get("urlProbe") or s["url"]).replace("{}", U)
        method = (s.get("request_method") or "GET").upper()
        body = None
        headers = dict(s.get("headers") or {})
        if s.get("request_payload") is not None:
            body = json.dumps(_subst(s["request_payload"], "{}"))
            headers.setdefault("Content-Type", "application/json")
        etype = s.get("errorType")
        if isinstance(etype, list):
            etype = etype[0] if etype else "status_code"
        follow = etype != "response_url"
        rule = Rule(db="sherlock", probe=Probe(check_url, method, body, _headers(headers), follow),
                    regex=s.get("regexCheck"))
        if etype == "message":
            rule.exists_codes = BELOW_400
            rule.missing = tuple((None, m) for m in _strs(s.get("errorMsg")))
        elif etype == "response_url":
            rule.exists_codes = OK_2XX
            rule.no_redirect = True
        else:
            rule.exists_codes = OK_2XX
            if s.get("errorCode") is not None:
                rule.missing = ((_codes(s["errorCode"]), None),)
        yield Site(name=name, profile_url=profile, key=site_key(profile),
                   nsfw=bool(s.get("isNSFW")), rules=[rule])


def _from_wmn(raw: dict):
    for s in raw.get("sites", []):
        if s.get("valid") is False or "uri_check" not in s:
            continue
        check_url = s["uri_check"].replace("{account}", U)
        profile = (s.get("uri_pretty") or s["uri_check"]).replace("{account}", U)
        body = s.get("post_body")
        if body:
            body = body.replace("{account}", U)
        rule = Rule(
            db="whatsmyname",
            probe=Probe(check_url, "POST" if body else "GET", body, _headers(s.get("headers")), True),
            exists_codes=_codes(s.get("e_code")),
            exists_strings=_strs(s.get("e_string")),
            missing=((_codes(s.get("m_code")), s.get("m_string") or None),)
            if (s.get("m_code") is not None or s.get("m_string")) else (),
            strip_chars=s.get("strip_bad_char") or "",
        )
        cat = (s.get("cat") or "").lower()
        yield Site(name=s["name"], profile_url=profile, key=site_key(profile),
                   tags={cat} if cat else set(), nsfw=cat in ("xx nsfw xx", "nsfw") or cat in NSFW_TAGS,
                   rules=[rule])


def _from_maigret(raw: dict):
    engines = raw.get("engines", {})
    for name, site in raw.get("sites", {}).items():
        s = dict(site)
        if s.get("engine") in engines:
            s = {**engines[s["engine"]].get("site", {}), **site}
        if s.get("disabled") or s.get("type") or "url" not in s:
            continue
        url_main = (s.get("urlMain") or "").rstrip("/")
        sub = s.get("urlSubpath") or ""

        def fill(t: str) -> str:
            return t.replace("{urlMain}", url_main).replace("{urlSubpath}", sub).replace("{username}", U)

        profile = fill(s["url"])
        if not profile.startswith("http"):
            continue
        check_url = fill(s.get("urlProbe") or s["url"])
        method = (s.get("requestMethod") or ("HEAD" if s.get("requestHeadOnly") else "GET")).upper()
        body = None
        headers = dict(s.get("headers") or {})
        if s.get("requestPayload") is not None:
            body = json.dumps(_subst(s["requestPayload"], "{username}"))
            headers.setdefault("Content-Type", "application/json")
        ctype = s.get("checkType", "status_code")
        rule = Rule(db="maigret", probe=Probe(check_url, method, body, _headers(headers), ctype != "response_url"),
                    regex=s.get("regexCheck"), allow_403=bool(s.get("ignore403")),
                    error_strings=tuple((s.get("errors") or {}).keys()))
        if ctype == "message":
            rule.exists_strings = _strs(s.get("presenseStrs"))
            rule.missing = tuple((None, m) for m in _strs(s.get("absenceStrs")))
            if not rule.exists_strings and not rule.missing:
                rule.exists_codes = OK_2XX
        elif ctype == "response_url":
            rule.exists_codes = OK_2XX
            rule.no_redirect = True
        else:
            rule.exists_codes = OK_2XX
        tags = set(s.get("tags") or [])
        yield Site(name=name, profile_url=profile, key=site_key(profile), tags=tags,
                   nsfw=bool(tags & NSFW_TAGS), rank=s.get("alexaRank"), rules=[rule])


def _from_social_analyzer(raw: dict):
    shared = {d["name"]: d.get("detections", []) for d in raw.get("shared_detections", [])}
    for s in raw.get("websites_entries", []):
        url = s.get("url", "")
        if "{username}" not in url or not url.startswith("http"):
            continue
        dets = []
        for d in s.get("detections", []):
            if d.get("type") == "shared":
                dets.extend(shared.get(d.get("name"), []))
            elif d.get("type") in ("normal", "advanced"):
                dets.append(d)
            elif d.get("type") == "special":
                dets = None
                break
        if not dets:
            continue
        exists, missing = [], []
        for d in dets:
            text = (d.get("string") or "").replace("{username}", U)
            if not text or "temp_fix" in text:
                continue
            (exists if d.get("return") == "true" else missing).append(text)
        exists, missing = list(dict.fromkeys(exists)), list(dict.fromkeys(missing))
        if not exists and not missing:
            continue
        profile = url.replace("{username}", U)
        rule = Rule(db="social-analyzer", probe=Probe(profile), exists_codes=BELOW_400,
                    exists_strings=tuple(exists), missing=tuple((None, m) for m in missing), require_all=True)
        name = re.sub(r"^www\.", "", profile.split("/")[2])
        cat = (s.get("type") or "").lower()
        yield Site(name=name, profile_url=profile, key=site_key(profile), tags={cat.split(" > ")[0]} if cat else set(),
                   nsfw=str(s.get("nsfw")).lower() == "true" or "adult" in cat, rank=s.get("global_rank") or None,
                   rules=[rule])


def _from_discovered(raw: dict):
    """Sites Panoptes learned from links on profiles it found. Checked by status + redirect, and every
    hit still goes through the random-username false-positive check."""
    for template, meta in raw.items():
        if U not in template:
            continue
        rule = Rule(db="discovered", probe=Probe(template, follow=False), exists_codes=OK_2XX, no_redirect=True)
        yield Site(name=meta.get("name") or template.split("/")[2], profile_url=template, key=site_key(template),
                   tags={"discovered"}, rules=[rule])


def _broken(rule: Rule) -> bool:
    """Rules whose marker text was mis-encoded can never match - they'd make every name 'exist'."""
    texts = list(rule.exists_strings) + [t for _, t in rule.missing if t]
    return any("�" in t for t in texts)


def _from_extra(_raw):
    from panoptes.sources.extra_sites import EXTRA_SITES
    for name, template, nsfw, tags in EXTRA_SITES:
        url = template.replace("{u}", U)
        rule = Rule(db="panoptes", probe=Probe(url, follow=False), exists_codes=OK_2XX, no_redirect=True,
                    exists_strings=(U,))
        yield Site(name=name, profile_url=url, key=site_key(url), tags=set(tags), nsfw=nsfw, rules=[rule])


TRANSLATORS = {"sherlock": _from_sherlock, "whatsmyname": _from_wmn, "maigret": _from_maigret,
               "social-analyzer": _from_social_analyzer}


# ----------------------------------------------------------------------------- merge

def build_catalog(scope: str = "standard", nsfw: bool = False) -> list[Site]:
    """Merge all cached databases into one deduplicated list of sites.

    scope:
      quick    - sites at least two projects agree on, plus Maigret's top 100
      standard - all Sherlock + WhatsMyName sites, plus ranked Maigret sites
      full     - everything not disabled (~10k+ sites)
    """
    merged: dict[str, Site] = {}
    sources = [(db, load_raw(db), TRANSLATORS[db]) for db in sorted(DATABASES, key=DB_PRIORITY.index)]
    sources.append(("discovered", load_discovered(), _from_discovered))
    sources.append(("panoptes", True, _from_extra))
    for db, raw, translate in sources:
        if not raw:
            continue
        for site in translate(raw):
            site.rules = [r for r in site.rules if not _broken(r)]
            if not site.rules:
                continue
            existing = merged.get(site.key)
            if existing is None:
                merged[site.key] = site
                continue
            known_probes = {(r.db, r.probe) for r in existing.rules}
            existing.rules.extend(r for r in site.rules if (r.db, r.probe) not in known_probes)
            existing.tags |= site.tags
            existing.nsfw = existing.nsfw or site.nsfw
            if site.rank and (existing.rank is None or site.rank < existing.rank):
                existing.rank = site.rank

    sites = list(merged.values())
    if not nsfw:
        sites = [s for s in sites if not s.nsfw]
    if scope == "quick":
        sites = [s for s in sites if len(s.dbs) >= 2 or (s.rank is not None and s.rank <= 100)]
    elif scope == "standard":
        sites = [s for s in sites if s.dbs & {"sherlock", "whatsmyname", "discovered", "panoptes"}
                 or (s.rank is not None and (s.dbs != {"social-analyzer"} or s.rank <= 20000))]
    sites.sort(key=lambda s: (-len(s.dbs), s.rank or 10**9, s.name.lower()))
    return sites


def catalog_stats(nsfw: bool = False) -> dict:
    stats = {}
    for scope in ("quick", "standard", "full"):
        sites = build_catalog(scope, nsfw)
        stats[scope] = {
            "sites": len(sites),
            "multi_source": sum(1 for s in sites if len(s.dbs) >= 2),
            "rules": sum(len(s.rules) for s in sites),
        }
    return stats
