"""Combined account discovery.

One engine, one deduplicated site catalog (Sherlock + WhatsMyName + Maigret + social-analyzer +
sites Panoptes learned), every database's detection rule applied to each response, majority vote,
then a false-positive check that re-runs every hit with a random username.

Speed without losing coverage:
  * sites are checked most-likely-first (sites that produced verified hits in past searches, then
    sites several databases agree on, then by popularity), so the first hits arrive in seconds;
  * pass 1 uses a short timeout; pass 2 re-checks only the slow/blocked sites with the full timeout;
  * catch-all sites (that "find" any random name) are remembered and skipped from then on.
"""
from __future__ import annotations

import asyncio
import re
import json
import random
import string
import time
from urllib.parse import quote, urlparse

import httpx

from panoptes.config import CACHE_DIR
from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source
from panoptes.sources.sitedb import U, Probe, Rule, Site, build_catalog, site_key, update_databases

_catalog_cache: dict[tuple, list[Site]] = {}
STATS_FILE = CACHE_DIR / "site_stats.json"


def _random_username() -> str:
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=11))


def _effective(username: str, rule: Rule) -> str:
    for ch in rule.strip_chars:
        username = username.replace(ch, "")
    return username


# ----------------------------------------------------------------------------- learned site statistics

def load_stats() -> dict:
    try:
        return json.loads(STATS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_stats(stats: dict) -> None:
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(json.dumps(stats), encoding="utf-8")


def likelihood(site: Site, stats: dict) -> tuple:
    """Sort key: most likely to produce a real hit first."""
    st = stats.get(site.key, {})
    hit_rate = st.get("hits", 0) / max(1, st.get("checks", 0))
    return (-hit_rate, -len(site.dbs), site.rank or 10 ** 9, site.name.lower())


# ----------------------------------------------------------------------------- fetching

LOGIN_WALL = re.compile(r"/(?:login|signin|sign-in|log-in|authwall|checkpoint|accounts/login|uas/login|auth/)|"
                        r"[?&](?:next|redirect_uri|return_to)=")


async def _fetch(ctx: Context, probe: Probe, username: str, timeout: float) -> tuple[int, str, bool] | None:
    url = probe.url.replace(U, quote(username, safe="@._-+~"))
    body = None
    if probe.body is not None:
        body = probe.body.replace(U, json.dumps(username)[1:-1])
    headers = dict(probe.headers)
    try:
        r = await ctx.request(probe.method, url, content=body, headers=headers or None,
                              follow_redirects=probe.follow, timeout=timeout)
        if not probe.follow and 300 <= r.status_code < 400:
            # Redirects that only normalise the URL (https, trailing slash, www) aren't "not found".
            loc = r.headers.get("location", "")
            if loc and site_key(str(r.url.join(loc))) == site_key(url):
                r = await ctx.request(probe.method, url, content=body, headers=headers or None,
                                      follow_redirects=True, timeout=timeout)
                return r.status_code, _text(r, probe), False
        redirected = bool(r.history) and site_key(str(r.url)) != site_key(url)
        final = str(r.url).lower() + " " + r.headers.get("location", "").lower()
        if r.status_code in (401, 999) or LOGIN_WALL.search(final):
            from panoptes.sessions import cookie_for
            if not cookie_for(url):
                ctx.shared.setdefault("login-walled", set()).add(urlparse(url).hostname or url)
        return r.status_code, _text(r, probe), redirected or (not probe.follow and 300 <= r.status_code < 400)
    except (httpx.HTTPError, ValueError, UnicodeError):
        return None


def _text(r: httpx.Response, probe: Probe) -> str:
    if probe.method == "HEAD":
        return ""
    try:
        return r.text
    except Exception:
        return r.content.decode("utf-8", "replace")


async def _run_rules(ctx: Context, rules: list[Rule], username: str,
                     timeout: float | None = None) -> list[tuple[Rule, bool | None, int | None]]:
    """Evaluate each rule, issuing one request per distinct (probe, username)."""
    timeout = timeout or ctx.options.timeout
    responses: dict[tuple, asyncio.Task] = {}
    for rule in rules:
        key = (rule.probe, _effective(username, rule))
        if key not in responses:
            responses[key] = asyncio.ensure_future(_fetch(ctx, rule.probe, key[1], timeout))
    await asyncio.gather(*responses.values())
    out = []
    for rule in rules:
        resp = responses[(rule.probe, _effective(username, rule))].result()
        if resp is None:
            out.append((rule, None, None))
        else:
            status, body, redirected = resp
            out.append((rule, rule.evaluate(status, body, redirected, _effective(username, rule)), status))
    return out


def _tally(results) -> tuple[int, int]:
    votes = [v for _, v, _ in results if v is not None]
    yes = sum(1 for v in votes if v)
    return yes, len(votes)


class AccountsSource(Source):
    name = "accounts"
    kinds = ("username",)
    heavy = True
    description = ("Combined account search across the Sherlock, WhatsMyName, Maigret and social-analyzer site "
                   "databases plus learned sites: cross-database voting, false-positive checks, likely-first ordering "
                   "and a fast pass followed by a thorough pass")

    async def _catalog(self, ctx: Context) -> list[Site]:
        async def prepare():
            await update_databases(ctx.client, log=lambda m: ctx.log(m))
            from panoptes.sources.sitedb import discovered_file
            mtime = discovered_file().stat().st_mtime if discovered_file().exists() else 0
            key = (ctx.options.scope, ctx.options.nsfw, mtime)
            if key not in _catalog_cache:
                _catalog_cache.clear()
                _catalog_cache[key] = await asyncio.to_thread(build_catalog, *key[:2])
            return _catalog_cache[key]
        return await ctx.once("account-catalog", prepare)

    async def _check_site(self, ctx: Context, site: Site, rules: list[Rule], username: str,
                          timeout: float | None = None):
        """Returns (site, finding | None, inconclusive: bool)."""
        results = await _run_rules(ctx, rules, username, timeout)
        yes, total = _tally(results)
        # Case-insensitivity: many sites only know the lowercase handle.
        if yes == 0 and username != username.lower():
            lower = await _run_rules(ctx, rules, username.lower(), timeout)
            if _tally(lower)[0]:
                results, username = lower, username.lower()
                yes, total = _tally(results)
        if yes == 0:
            return site, None, total == 0

        verified = None
        if ctx.options.verify:
            positive = [r for r, v, _ in results if v]
            checkable = [r for r in positive if r.applies_to(_random_username())]
            if checkable:
                decoy_results = []
                for _ in range(2):  # an unreachable decoy check is retried once rather than trusted
                    decoy_results = await _run_rules(ctx, checkable, _random_username(), timeout)
                    if any(v is not None for _, v, _ in decoy_results):
                        break
                unreliable = {id(r) for r, v, _ in decoy_results if v}
                if unreliable:
                    # One database's rule being fooled doesn't make the whole site catch-all: only that rule is
                    # remembered as weak. The site is a catch-all only when *every* checkable rule was fooled.
                    weak = ctx.shared.setdefault("weak-rules", {}).setdefault(site.key, set())
                    weak.update(r.db for r in checkable if id(r) in unreliable)
                    if len(unreliable) == len(rules):
                        ctx.shared.setdefault("catch-all", set()).add(site.key)
                results = [(r, None if id(r) in unreliable else v, s) for r, v, s in results]
                yes, total = _tally(results)
                verified = any(v is not None for _, v, _ in decoy_results)
                if yes == 0:
                    return site, None, False

        no = total - yes
        if yes < no or (yes == no and not ctx.options.include_disputed):
            return site, None, False
        confidence = (1 - 0.35 ** yes) * (yes / total)
        if verified is False:
            confidence *= 0.6   # couldn't confirm a random name is rejected - treat as unverified
        elif verified is None:
            confidence *= 0.85
        profile = site.profile_url.replace(U, quote(username, safe="@._-+~"))
        statuses = sorted({s for _, _, s in results if s is not None})
        finding = Finding(
            category="account", title=site.name, value=profile, url=profile,
            source="accounts", target=Entity("username", username), confidence=confidence,
            sources={r.db for r, v, _ in results if v},
            data={"votes": f"{yes}/{total}", "databases": sorted(site.dbs), "tags": sorted(site.tags),
                  "verified": bool(verified), "disputed": yes == no, "http_status": statuses},
        )
        return site, finding, False

    async def search(self, entity: Entity, ctx: Context):
        sites = await self._catalog(ctx)
        if not sites:
            ctx.log("No site databases available - run `panoptes update` with internet access", "error")
            return
        username = entity.value
        stats = load_stats()
        skipped_catchall = 0
        jobs = []
        for site in sorted(sites, key=lambda s: likelihood(s, stats)):
            st = stats.get(site.key, {})
            if st.get("catch_all_strikes", 0) >= 2:
                skipped_catchall += 1
                continue
            weak = set(st.get("weak_dbs", ()))
            rules = [r for r in site.rules if (r.applies_to(_effective(username, r))
                     or r.applies_to(_effective(username.lower(), r)))]
            rules = [r for r in rules if r.db not in weak] or rules   # never drop a site's last rules
            if rules:
                jobs.append((site, rules))
        rules_by_key = {s.key: r for s, r in jobs}
        two_pass = ctx.options.two_pass and ctx.options.fast_timeout < ctx.options.timeout
        first_timeout = ctx.options.fast_timeout if two_pass else ctx.options.timeout
        total, done, found = len(jobs), 0, 0
        ctx.log(f"accounts: checking '{username}' on {total} sites, most likely first "
                f"({sum(len(r) for _, r in jobs)} rules from {len({r.db for _, rs in jobs for r in rs})} databases"
                + (f"; {skipped_catchall} known catch-all sites skipped" if skipped_catchall else "") + ")")
        ctx.progress(self.name, entity, 0, total)
        hits: set[str] = set()
        retry: list[tuple[Site, list[Rule]]] = []
        started = time.monotonic()

        async def run_pass(batch, timeout, label):
            nonlocal done, found
            tasks = {asyncio.ensure_future(self._check_site(ctx, s, r, username, timeout)): (s, r) for s, r in batch}
            try:
                for fut in asyncio.as_completed(tasks):
                    site, finding, inconclusive = await fut
                    done += 1
                    if done % 25 == 0 or done == total:
                        ctx.progress(self.name, entity, done, total)
                    if finding:
                        found += 1
                        hits.add(site.key)
                        finding.data["pass"] = label
                        yield finding
                    elif inconclusive and label == "fast":
                        retry.append((site, rules_by_key[site.key]))
            finally:
                for t in tasks:
                    t.cancel()

        async for f in run_pass(jobs, first_timeout, "fast" if two_pass else "full"):
            yield f
        ctx.log(f"accounts: pass 1 done in {time.monotonic() - started:.0f}s - {found} accounts; "
                f"{len(retry)} slow/blocked sites" + (" will be re-checked with a longer timeout" if two_pass else ""))
        if two_pass and retry:
            total += len(retry)
            async for f in run_pass(retry, ctx.options.timeout, "thorough"):
                yield f
            ctx.log(f"accounts: pass 2 done - {found} accounts total for '{username}'")

        walled = sorted(ctx.shared.get("login-walled", set()))
        if walled and not ctx.shared.get("login-walled-reported"):
            ctx.shared["login-walled-reported"] = True
            yield Finding(category="lead", title="Sites that hid profiles behind a login", value=", ".join(walled[:30])
                          + (f" (+{len(walled) - 30} more)" if len(walled) > 30 else ""), source=self.name,
                          target=entity, confidence=0.9,
                          data={"sites": walled, "how_to_fix": "Settings > Logins & sessions: paste a burner account's "
                                "browser cookie for these sites (or `panoptes login add <site> <cookie>`) and search again"})

        # Learn: which sites produce hits, and which ones "find" everybody.
        catch_all = ctx.shared.get("catch-all", set())
        weak_rules = ctx.shared.get("weak-rules", {})
        async with ctx.lock("site-stats"):
            stats = load_stats()
            for site, _ in jobs:
                st = stats.setdefault(site.key, {"hits": 0, "checks": 0})
                st["checks"] += 1
                st["hits"] += site.key in hits
                if site.key in catch_all:   # needs two separate searches before the site is skipped
                    st["catch_all_strikes"] = st.get("catch_all_strikes", 0) + 1
                elif site.key in hits:
                    st["catch_all_strikes"] = 0   # a clean, verified hit clears earlier strikes
                if weak_rules.get(site.key):
                    st["weak_dbs"] = sorted(set(st.get("weak_dbs", ())) | weak_rules[site.key])
            save_stats(stats)
        if catch_all:
            ctx.log(f"accounts: {len(catch_all)} site(s) accepted a random username on every rule (e.g. "
                    f"{sorted(catch_all)[0]}) - skipped from now on if it happens again")
