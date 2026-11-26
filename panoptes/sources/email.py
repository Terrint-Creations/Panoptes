"""Email intelligence: mail infrastructure, account registrations, avatars, keys, breaches."""
from __future__ import annotations

import asyncio
import hashlib
import re
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import httpx

from panoptes.config import CACHE_DIR
from panoptes.models import Entity, Finding
from panoptes.sources.base import USER_AGENT, Context, Source

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "pm.me", "gmx.com", "gmx.de", "gmx.net", "web.de", "mail.com", "yandex.ru", "yandex.com", "mail.ru",
    "zoho.com", "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "qq.com", "163.com", "126.com",
}
GENERIC_LOCALPARTS = {"info", "admin", "contact", "support", "sales", "hello", "office", "mail", "team",
                      "help", "billing", "noreply", "no-reply", "webmaster", "security", "abuse", "hr", "jobs"}
DISPOSABLE_URL = ("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/"
                  "main/disposable_email_blocklist.conf")


async def _disposable_domains(ctx: Context) -> set[str]:
    f = CACHE_DIR / "disposable_domains.txt"
    if not f.exists():
        try:
            r = await ctx.get(DISPOSABLE_URL, timeout=30)
            r.raise_for_status()
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(r.text, encoding="utf-8")
        except httpx.HTTPError:
            return set()
    return {ln.strip().lower() for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()}


class EmailBasicsSource(Source):
    name = "email-infra"
    kinds = ("email",)
    description = "Mail server records, provider type, disposable-address check, username/domain pivots"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value.lower()
        local, _, domain = email.partition("@")
        base = dict(source=self.name, target=entity)

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.options.timeout
        try:
            answers = await resolver.resolve(domain, "MX")
            mx = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
            yield Finding(category="email", title="Mail servers (MX)",
                          value=", ".join(h for _, h in mx), confidence=0.99,
                          data={"mx": [h for _, h in mx], "provider": _mail_provider([h for _, h in mx])}, **base)
            provider = _mail_provider([h for _, h in mx])
            if provider:
                yield Finding(category="email", title="Mail hosted by", value=provider, confidence=0.9, **base)
        except dns.resolver.NXDOMAIN:
            yield Finding(category="email", title="Domain status", value="Domain does not exist (NXDOMAIN)",
                          confidence=0.99, **base)
        except (dns.exception.DNSException, OSError):
            yield Finding(category="email", title="Mail servers (MX)", value="No MX records - domain can't receive mail",
                          confidence=0.8, **base)

        if domain in FREE_PROVIDERS:
            yield Finding(category="email", title="Provider type", value=f"Free webmail ({domain})", confidence=0.99, **base)
        else:
            yield Finding(category="email", title="Provider type", value=f"Custom/organisational domain ({domain})",
                          confidence=0.9, pivots=[Entity("domain", domain)], **base)

        disposable = await ctx.once("disposable", lambda: _disposable_domains(ctx))
        if domain in disposable:
            yield Finding(category="email", title="Disposable address",
                          value="Domain is a known throwaway email service", confidence=0.95, **base)

        handle = re.sub(r"\+.*$", "", local)
        if len(handle) >= 4 and handle not in GENERIC_LOCALPARTS:
            yield Finding(category="lead", title="Possible username (from local part)", value=handle,
                          confidence=0.6, pivots=[Entity("username", handle)], **base)


def _mail_provider(mx_hosts: list[str]) -> str | None:
    joined = " ".join(mx_hosts).lower()
    for needle, name in (("google.com", "Google Workspace / Gmail"), ("googlemail.com", "Google Workspace / Gmail"),
                         ("outlook.com", "Microsoft 365 / Outlook"), ("protection.outlook", "Microsoft 365"),
                         ("protonmail", "Proton Mail"), ("zoho", "Zoho Mail"), ("yahoodns", "Yahoo Mail"),
                         ("icloud.com", "iCloud Mail"), ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"),
                         ("messagingengine", "Fastmail"), ("mailgun", "Mailgun"), ("secureserver", "GoDaddy"),
                         ("yandex", "Yandex Mail"), ("mail.ru", "Mail.ru"), ("barracuda", "Barracuda")):
        if needle in joined:
            return name
    return None


class GravatarSource(Source):
    name = "gravatar"
    kinds = ("email",)
    description = "Gravatar avatar and public profile (name, location, linked accounts)"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value.strip().lower()
        md5 = hashlib.md5(email.encode()).hexdigest()
        sha = hashlib.sha256(email.encode()).hexdigest()
        base = dict(source=self.name, target=entity)
        try:
            r = await ctx.get(f"https://api.gravatar.com/v3/profiles/{sha}")
            if r.status_code == 200:
                p = r.json()
                url = p.get("profile_url")
                yield Finding(category="account", title="Gravatar", value=url or f"https://gravatar.com/{md5}",
                              url=url, confidence=0.99, data={"avatar": p.get("avatar_url")}, **base)
                slug = (url or "").rstrip("/").rsplit("/", 1)[-1]
                fields = [("Display name", p.get("display_name"), "name"), ("Location", p.get("location"), None),
                          ("Job title", p.get("job_title"), None), ("Company", p.get("company"), None),
                          ("About", p.get("description"), None), ("Pronouns", p.get("pronouns"), None)]
                for title, value, pivot_kind in fields:
                    if value:
                        yield Finding(category="profile", title=f"Gravatar {title.lower()}", value=str(value),
                                      url=url, confidence=0.9,
                                      pivots=[Entity(pivot_kind, value)] if pivot_kind else [], **base)
                if slug and slug != sha and slug != md5:
                    yield Finding(category="lead", title="Gravatar username", value=slug, url=url, confidence=0.75,
                                  pivots=[Entity("username", slug)], **base)
                for acct in p.get("verified_accounts") or []:
                    if acct.get("url"):
                        yield Finding(category="account", title=acct.get("service_label") or acct.get("service_type", "Linked"),
                                      value=acct["url"], url=acct["url"], confidence=0.95,
                                      data={"via": "gravatar verified account"}, **base)
                return
            r = await ctx.get(f"https://www.gravatar.com/avatar/{md5}", params={"d": "404"})
            if r.status_code == 200:
                yield Finding(category="account", title="Gravatar avatar", value=f"https://www.gravatar.com/avatar/{md5}?s=400",
                              url=f"https://www.gravatar.com/avatar/{md5}?s=400", confidence=0.95,
                              data={"note": "avatar exists but profile is private"}, **base)
        except (httpx.HTTPError, ValueError) as exc:
            ctx.log(f"gravatar: {exc.__class__.__name__}", "warning")


class PGPKeySource(Source):
    name = "pgp-keys"
    kinds = ("email",)
    description = "PGP public keys on keys.openpgp.org and keyserver.ubuntu.com (often reveal real names)"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value.strip()
        base = dict(source=self.name, target=entity)
        try:
            r = await ctx.get(f"https://keys.openpgp.org/vks/v1/by-email/{quote(email)}")
            if r.status_code == 200 and "BEGIN PGP PUBLIC KEY" in r.text:
                yield Finding(category="key", title="PGP key (keys.openpgp.org)", value="Verified public key published",
                              url=f"https://keys.openpgp.org/search?q={quote(email)}", confidence=0.95, **base)
        except httpx.HTTPError:
            pass
        try:
            r = await ctx.get("https://keyserver.ubuntu.com/pks/lookup",
                              params={"search": email, "op": "index", "options": "mr", "exact": "on"})
            if r.status_code == 200:
                keys: list[tuple[str, str, list[str]]] = []
                for line in r.text.splitlines():
                    parts = line.split(":")
                    if parts[0] == "pub" and len(parts) > 1:
                        keys.append((parts[1], parts[4] if len(parts) > 4 else "", []))
                    elif parts[0] == "uid" and len(parts) > 1 and keys:
                        keys[-1][2].append(httpx.QueryParams(f"u={parts[1]}")["u"])
                needle = email.lower()
                names = set()
                for key_id, created, uids in keys:
                    if not any(f"<{needle}>" in u.lower() or u.lower() == needle for u in uids):
                        continue
                    yield Finding(category="key", title="PGP key (keyserver.ubuntu.com)", value=key_id,
                                  url=f"https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=0x{key_id}",
                                  data={"created_unix": created, "uids": uids}, confidence=0.9, **base)
                    for uid in uids:
                        name = re.sub(r"\s*[<(].*$", "", uid).strip()
                        if name and "@" not in name:
                            names.add(name)
                for name in sorted(names):
                    yield Finding(category="profile", title="Name on PGP key", value=name, confidence=0.85,
                                  pivots=[Entity("name", name)], **base)
        except httpx.HTTPError:
            pass


class RegistrationSource(Source):
    """Runs the holehe module collection natively inside Panoptes' async engine."""

    name = "registrations"
    kinds = ("email",)
    description = "Checks 120+ sites for accounts registered to the email (holehe module set)"

    def available(self, config):
        try:
            import holehe.core  # noqa: F401
        except ImportError:
            return False, "pip install holehe"
        return True, ""

    async def search(self, entity: Entity, ctx: Context):
        import logging

        from holehe.core import get_functions, import_submodules

        logging.getLogger("bs4").setLevel(logging.ERROR)  # holehe's HTML parsing is noisy

        funcs = get_functions(import_submodules("holehe.modules"))
        total, done, limited = len(funcs), 0, 0
        ctx.progress(self.name, entity, 0, total)
        sem = asyncio.Semaphore(min(ctx.options.concurrency, 30))
        # holehe modules expect their own client semantics (no auto-redirects).
        async with httpx.AsyncClient(timeout=ctx.options.timeout, headers={"User-Agent": USER_AGENT},
                                     proxy=ctx.config.get("proxy") or None) as client:
            async def run(fn):
                out: list[dict] = []
                async with sem:
                    try:
                        await asyncio.wait_for(fn(entity.value, client, out), ctx.options.timeout * 2)
                    except Exception:
                        out.append({"name": fn.__name__, "rateLimit": True, "exists": False})
                return out

            tasks = [asyncio.ensure_future(run(f)) for f in funcs]
            try:
                for fut in asyncio.as_completed(tasks):
                    results = await fut
                    done += 1
                    if done % 10 == 0 or done == total:
                        ctx.progress(self.name, entity, done, total)
                    for res in results:
                        if res.get("rateLimit"):
                            limited += 1
                        if not res.get("exists"):
                            continue
                        domain = res.get("domain") or res.get("name")
                        parts = str(domain).split(".")
                        domain = ".".join(parts[-3:] if len(parts) > 2 and len(parts[-2]) <= 3 else parts[-2:])
                        data = {k: res[k] for k in ("emailrecovery", "phoneNumber", "others") if res.get(k)}
                        yield Finding(category="account", title=res.get("name", domain).capitalize(),
                                      value=domain, url=f"https://{domain}", source=self.name, target=entity,
                                      confidence=0.85, data={"method": res.get("method"), **data})
            finally:
                for t in tasks:
                    t.cancel()
        if limited:
            ctx.log(f"registrations: {limited}/{total} sites rate-limited or errored", "warning")


BLACKBIRD_EMAIL_URL = "https://raw.githubusercontent.com/p1ngul1n0/blackbird/main/data/email-data.json"


async def _blackbird_sites(ctx: Context) -> list[dict]:
    import json
    import time

    f = CACHE_DIR / "sitedb" / "blackbird_email.json"
    if not f.exists() or time.time() - f.stat().st_mtime > 7 * 24 * 3600:
        try:
            r = await ctx.get(BLACKBIRD_EMAIL_URL, timeout=30)
            r.raise_for_status()
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(r.text, encoding="utf-8")
        except httpx.HTTPError:
            pass
    try:
        return json.loads(f.read_text(encoding="utf-8")).get("sites", [])
    except (OSError, ValueError):
        return []


def _json_path(obj, path):
    for p in path:
        try:
            obj = obj[p]
        except (KeyError, IndexError, TypeError):
            return None
    return obj


class EmailSitesSource(Source):
    """Blackbird's email-account checks, with its JSON metadata extraction (names, avatars, linked accounts)."""

    name = "email-sites"
    kinds = ("email",)
    description = "Blackbird email checks: account existence plus profile metadata extraction"

    async def search(self, entity: Entity, ctx: Context):
        sites = await ctx.once("blackbird-email", lambda: _blackbird_sites(ctx))
        email = entity.value.strip().lower()

        async def check(site: dict):
            if site.get("pre_check"):
                return None
            op = site.get("input_operation") or ""
            account = email
            if op == "hash-sha256":
                account = hashlib.sha256(email.encode()).hexdigest()
            elif op == "hash-md5":
                account = hashlib.md5(email.encode()).hexdigest()
            url = site["uri_check"].replace("{account}", quote(account, safe="@"))
            body = site.get("data")
            if isinstance(body, (dict, list)):
                import json
                body = json.dumps(body)
            if body:
                body = body.replace("{account}", account)
            try:
                r = await ctx.client.request(site.get("method") or "GET", url, content=body,
                                             headers=site.get("headers") or None, timeout=ctx.options.timeout)
            except httpx.HTTPError:
                return None
            text = r.text
            if r.status_code == site.get("e_code") and site.get("e_string", "") in text:
                return site, r
            return None

        results = await asyncio.gather(*(check(s) for s in sites))
        for res in results:
            if not res:
                continue
            site, r = res
            host = urlparse_host(site["uri_check"])
            yield Finding(category="account", title=site["name"], value=host, url=f"https://{host}",
                          source=self.name, target=entity, confidence=0.88, data={"category": site.get("cat")})
            try:
                data = r.json()
            except ValueError:
                continue
            for meta in site.get("metadata") or []:
                if meta.get("schema") != "JSON":
                    continue
                val = _json_path(data, meta.get("path", []))
                if val in (None, "", []):
                    continue
                if meta.get("type") == "Array" and isinstance(val, list):
                    vals = [_json_path(v, meta.get("item-path", [])) for v in val]
                    val = ", ".join(str(v) for v in vals if v)
                    if not val:
                        continue
                label = meta.get("name", "field")
                pivots = []
                if label.lower() == "name":
                    pivots = [Entity("name", str(val))]
                elif label.lower() == "username":
                    pivots = [Entity("username", str(val))]
                yield Finding(category="profile", title=f"{site['name']} {label.lower()}", value=str(val)[:500],
                              source=self.name, target=entity, confidence=0.85, pivots=pivots,
                              url=str(val) if meta.get("type") == "Image" else None)


def urlparse_host(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(url).hostname or url).removeprefix("www.")


class GoogleAccountSource(Source):
    """GHunt-style checks that need no login: public Google Calendar and the Google profile photo."""

    name = "google"
    kinds = ("email",)
    description = "Google account traces without login: public Google Calendar events and calendar owner name"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value.strip().lower()
        url = f"https://calendar.google.com/calendar/ical/{quote(email)}/public/basic.ics"
        try:
            r = await ctx.get(url)
        except httpx.HTTPError:
            return
        if r.status_code != 200 or "BEGIN:VCALENDAR" not in r.text:
            return
        text = r.text
        name = re.search(r"^X-WR-CALNAME:(.+)$", text, re.M)
        tz = re.search(r"^X-WR-TIMEZONE:(.+)$", text, re.M)
        events = re.findall(r"^SUMMARY:(.+)$", text, re.M)
        locations = sorted({l.strip() for l in re.findall(r"^LOCATION:(.+)$", text, re.M) if l.strip()})
        base = dict(source=self.name, target=entity, url=f"https://calendar.google.com/calendar/embed?src={quote(email)}")
        yield Finding(category="account", title="Google Calendar (public)", value=f"{len(events)} public events",
                      confidence=0.97, **base)
        if name and name.group(1).strip() != email:
            yield Finding(category="profile", title="Google Calendar name", value=name.group(1).strip(), confidence=0.85,
                          pivots=[Entity("name", name.group(1).strip())], **base)
        if tz:
            yield Finding(category="profile", title="Calendar time zone", value=tz.group(1).strip(), confidence=0.85, **base)
        for loc in locations[:15]:
            yield Finding(category="location", title="Calendar event location", value=loc.replace("\\,", ","),
                          confidence=0.7, **base)
        for ev in events[:15]:
            yield Finding(category="lead", title="Calendar event", value=ev.strip().replace("\\,", ","),
                          confidence=0.7, **base)
