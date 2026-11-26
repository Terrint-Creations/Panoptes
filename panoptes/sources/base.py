"""Base class and runtime context shared by every source module."""
from __future__ import annotations

import asyncio
import contextvars
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, AsyncIterator
from urllib.parse import urlparse

import httpx

from panoptes.config import Config

if TYPE_CHECKING:
    from panoptes.engine import Events
    from panoptes.knowledge import Knowledge
    from panoptes.models import Entity, Finding

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
# For JSON APIs: some (rdap.org behind Cloudflare) reject a browser UA without a browser TLS fingerprint.
API_HEADERS = {"User-Agent": "panoptes-osint/0.3 (+https://github.com/)", "Accept": "application/json, application/rdap+json"}

# Which source run the current coroutine belongs to - lets the watchdog see per-source network activity.
current_run: contextvars.ContextVar[tuple | None] = contextvars.ContextVar("panoptes_run", default=None)


@dataclass
class SearchOptions:
    depth: int = 1                      # pivot hops to follow after the initial target
    scope: str = "standard"             # username site scope: quick | standard | full
    nsfw: bool = False
    verify: bool = True                 # re-check username hits with a random name to drop false positives
    include_disputed: bool = False      # keep account hits where databases split 50/50
    timeout: float = 15.0               # per request (also enforced as a hard wall-clock deadline)
    fast_timeout: float = 7.0           # pass 1 of bulk checks: quick answers first
    two_pass: bool = True               # re-check slow/blocked sites with the full timeout after pass 1
    concurrency: int = 96               # parallel requests for bulk sources (account discovery etc.)
    light_concurrency: int = 16         # parallel requests for every other source - each gets its own pool
    per_host: int = 4                   # politeness: parallel requests to any single host
    profile: str = "balanced"           # resource profile: light | balanced | heavy (see apply_profile)
    image_workers: int = 6              # images downloaded/analysed in parallel
    include: set[str] | None = None     # only run these sources
    exclude: set[str] = field(default_factory=set)
    pivot_kinds: set[str] = field(default_factory=lambda: {"username", "email", "domain", "ip", "phone", "name"})
    pivot_min_confidence: float = 0.6
    max_entities_per_level: int = 25
    max_subdomains: int = 2000
    name_permutations: bool = False     # turn a full name into candidate usernames and search them
    active_dns: bool = True             # DNS brute force / zone transfer / lookalike resolution
    crawl_pages: int = 30               # pages the domain harvester may crawl
    correlate: bool = True              # run correlation rules + identity summary at the end
    cooperative: bool = True            # let sources share high-confidence facts and cross-verify each other
    hint_min_confidence: float = 0.85   # how sure a fact must be before other sources may use it
    faces: bool = True                  # local face detection / matching across collected images
    reverse_image: bool = True          # automated reverse image search
    alt_accounts: bool = True           # look for alternate accounts on the same platforms
    discover_sites: bool = True         # learn new sites from links on found profiles and check them too
    darkweb: bool = True                # dark-web index mentions (Ahmia) and onion scanning (with Tor)
    ai_vision: bool = True              # describe/geolocate images with Claude (needs anthropic_api_key)
    geoai: bool = True                  # visual geolocation (Picarta online, or GeoCLIP if installed)
    ocr: bool = True                    # read text in images (coordinates, street signs, usernames)
    websearch: bool = True              # run search-engine, news and public-record queries
    idle_timeout: float = 240.0         # a source with no network activity or results this long is stopped
    source_timeout: float = 1800.0      # absolute cap per source run


PROFILES = {
    # name: (bulk pool, per-source pool, per-host, parallel image jobs, watchdog multiplier, process priority)
    "light":    (24, 6, 2, 2, 3.0, "below_normal"),
    "balanced": (96, 16, 4, 6, 1.0, "normal"),
    "heavy":    (192, 32, 6, 12, 1.0, "normal"),
}


def apply_profile(options: "SearchOptions", name: str) -> "SearchOptions":
    """Resource profiles change only how much runs at once - never which checks run or their timeouts -
    so a Light scan finds exactly what a Heavy one does, just more slowly."""
    bulk, light, host, images, wd, _prio = PROFILES.get(name, PROFILES["balanced"])
    options.profile = name
    options.concurrency, options.light_concurrency, options.per_host, options.image_workers = bulk, light, host, images
    options.idle_timeout = 240.0 * wd
    options.source_timeout = 1800.0 * wd
    return options


def set_process_priority(name: str) -> None:
    """Light profile: run below normal priority so the PC stays responsive while scanning."""
    import os
    import sys
    level = PROFILES.get(name, PROFILES["balanced"])[5]
    if sys.platform != "win32":
        # POSIX niceness can only be raised (lowered priority) without root, so only Light changes it.
        if level == "below_normal":
            try:
                os.nice(10)
            except (AttributeError, OSError):
                pass
        return
    import ctypes
    cls = {"below_normal": 0x4000, "normal": 0x20}[level]
    try:
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), cls)
    except Exception:
        pass


class Context:
    """Everything a source needs while running: HTTP client, config, options, event sink."""

    def __init__(self, client: httpx.AsyncClient, config: Config, options: SearchOptions, events: "Events"):
        self.client = client
        self.config = config
        self.options = options
        self.events = events
        self.heavy: set[str] = set()     # source names that get the big pool
        self._pools: dict[tuple, asyncio.Semaphore] = {}
        self._bulk = asyncio.Semaphore(options.concurrency + 32)  # total in-flight for all bulk sources combined
        self.shared: dict = {}
        self.report = None              # the live Report; enrichers read earlier findings from it
        self.knowledge: "Knowledge | None" = None
        self.activity: dict[tuple, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._hosts: dict[str, asyncio.Semaphore] = {}

    async def once(self, key: str, factory):
        """Run `factory()` once per search session and share its result across sources."""
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self.shared:
                self.shared[key] = await factory()
            return self.shared[key]

    def lock(self, key: str) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())

    def touch(self) -> None:
        run = current_run.get()
        if run is not None:
            self.activity[run] = time.monotonic()

    def progress(self, source: str, entity: "Entity", done: int, total: int) -> None:
        self.touch()
        self.events.on_progress(source, entity, done, total)

    def log(self, message: str, level: str = "info") -> None:
        self.events.on_log(level, message)

    def _host_sem(self, url: str) -> asyncio.Semaphore:
        host = (urlparse(url).hostname or "").lower()
        sem = self._hosts.get(host)
        if sem is None:
            sem = self._hosts[host] = asyncio.Semaphore(self.options.per_host)
        return sem

    def _pool(self) -> asyncio.Semaphore:
        """Each source run gets its own connection budget, so a bulk source checking 11,000 sites can
        never starve GitHub, breach lookups etc. (that starvation used to get them killed as 'idle')."""
        run = current_run.get() or ("_", "_")
        pool = self._pools.get(run)
        if pool is None:
            size = self.options.concurrency if run[0] in self.heavy else self.options.light_concurrency
            pool = self._pools[run] = asyncio.Semaphore(size)
        return pool

    async def request(self, method: str, url: str, *, deadline: float | None = None, **kw) -> httpx.Response:
        """HTTP request with a per-source cap, a per-host cap and a hard wall-clock deadline.

        httpx's own timeout applies per network operation, so a server trickling bytes can hold a
        request open indefinitely; the deadline guarantees every request ends."""
        timeout = kw.get("timeout", self.options.timeout)
        if isinstance(timeout, httpx.Timeout):
            timeout = timeout.read or self.options.timeout
        limit = deadline or (float(timeout) * 1.6 + 3)
        from panoptes.sessions import cookie_for
        cookie = cookie_for(url)
        if cookie:  # a saved site login: only ever sent to that site
            headers = dict(kw.get("headers") or {})
            if not any(h.lower() == "cookie" for h in headers):
                headers["Cookie"] = cookie
                kw["headers"] = headers
        run = current_run.get()
        bulk = self._bulk if run and run[0] in self.heavy else _NULL
        async with self._pool(), bulk, self._host_sem(url):
            try:
                return await asyncio.wait_for(self.client.request(method, url, **kw), limit)
            except asyncio.TimeoutError:
                raise httpx.ReadTimeout(f"hard deadline of {limit:.0f}s exceeded for {url}") from None
            finally:
                self.touch()

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def get_json(self, url: str, **kw):
        r = await self.get(url, **kw)
        r.raise_for_status()
        return r.json()


class _Null:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


_NULL = _Null()


def findings_for(ctx: "Context", entity: "Entity", category: str | None = None) -> list:
    if ctx.report is None:
        return []
    return [f for f in list(ctx.report.findings.values())
            if f.target.key() == entity.key() and (category is None or f.category == category)]


class Source:
    """A data source. Subclasses yield Findings for entities of the kinds they support.

    stage: "primary" sources run first and in parallel; "enrich" sources run after them and read
    their findings; "late" sources run after enrichment (cross-checks, alt accounts, images)."""

    name: str = ""
    kinds: tuple[str, ...] = ()
    stage: str = "primary"
    description: str = ""
    requires: tuple[str, ...] = ()      # config keys that must ALL be set for this source to run
    option: str | None = None           # SearchOptions flag that must be true for this source to run
    heavy: bool = False                 # bulk source (thousands of requests) - gets the large connection pool

    def available(self, config: Config) -> tuple[bool, str]:
        missing = [k for k in self.requires if not config.get(k)]
        if missing:
            return False, f"needs config key: {', '.join(missing)}"
        return True, ""

    async def search(self, entity: "Entity", ctx: Context) -> AsyncIterator["Finding"]:
        raise NotImplementedError
        yield  # pragma: no cover


EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
IGNORED_EMAIL_PARTS = ("example.", "@sentry", "noreply", "no-reply", "@email.com", "wixpress",
                       ".png", ".jpg", ".gif", ".svg", ".webp", "@2x", "u003e", "users.noreply.github.com")


def extract_emails(text: str) -> set[str]:
    out = set()
    for m in EMAIL_IN_TEXT.findall(text or ""):
        low = m.lower().strip(".")
        if not any(bad in low for bad in IGNORED_EMAIL_PARTS):
            out.add(low)
    return out
