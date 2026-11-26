"""Phone number intelligence (offline numbering-plan analysis + search leads)."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import quote_plus

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import NumberParseException, PhoneNumberType

from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source

TYPE_NAMES = {v: k.replace("_", " ").title() for k, v in vars(PhoneNumberType).items() if k.isupper()}


def parse(value: str, region: str | None):
    try:
        return phonenumbers.parse(value, None if value.strip().startswith("+") else (region or "US"))
    except NumberParseException:
        return None


class PhoneInfoSource(Source):
    name = "phone-info"
    kinds = ("phone",)
    description = "Validity, country, region, carrier, line type and time zones from numbering-plan data"

    async def search(self, entity: Entity, ctx: Context):
        region = ctx.config.get("default_region") or (ctx.knowledge.country_code() if ctx.knowledge else None)
        num = parse(entity.value, region)
        base = dict(source=self.name, target=entity)
        if num is None:
            yield Finding(category="phone", title="Parse", value="Could not parse as a phone number", confidence=0.9, **base)
            return
        valid = phonenumbers.is_valid_number(num)
        rows = [
            ("Valid", "yes" if valid else "no (possible: %s)" % ("yes" if phonenumbers.is_possible_number(num) else "no")),
            ("E.164", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)),
            ("International", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
            ("National", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)),
            ("Country", f"{phonenumbers.region_code_for_number(num)} (+{num.country_code})"),
            ("Location", geocoder.description_for_number(num, "en")),
            ("Carrier (original)", carrier.name_for_number(num, "en")),
            ("Line type", TYPE_NAMES.get(phonenumbers.number_type(num), "Unknown")),
            ("Time zones", ", ".join(timezone.time_zones_for_number(num))),
        ]
        for title, value in rows:
            if value:
                yield Finding(category="phone", title=title, value=value, confidence=0.95 if valid else 0.6, **base)


class PhoneLeadsSource(Source):
    name = "phone-leads"
    kinds = ("phone",)
    description = "Ready-made search engine and reverse-lookup links for every format of the number"

    async def search(self, entity: Entity, ctx: Context):
        num = parse(entity.value, ctx.config.get("default_region"))
        if num is None:
            return
        fmts = {phonenumbers.format_number(num, f) for f in (
            phonenumbers.PhoneNumberFormat.E164, phonenumbers.PhoneNumberFormat.INTERNATIONAL,
            phonenumbers.PhoneNumberFormat.NATIONAL)}
        fmts.add(str(num.national_number))
        quoted = " OR ".join(f'"{f}"' for f in sorted(fmts))
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        leads = {
            "Web mentions": quoted,
            "Social media": f"({quoted}) (site:facebook.com OR site:twitter.com OR site:x.com OR site:instagram.com OR site:linkedin.com OR site:vk.com)",
            "Classifieds & listings": f"({quoted}) (site:craigslist.org OR site:ebay.com OR site:olx.com OR site:gumtree.com)",
            "Documents": f"({quoted}) (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:csv)",
            "Spam / caller reports": f"({quoted}) (site:800notes.com OR site:whocalledme.com OR site:tellows.com OR site:shouldianswer.com)",
        }
        for title, q in leads.items():
            url = f"https://www.google.com/search?q={quote_plus(q)}"
            yield Finding(category="lead", title=title, value=url, url=url, source=self.name, target=entity,
                          confidence=0.5)
        for title, url in (("WhatsApp", f"https://wa.me/{e164.lstrip('+')}"),
                           ("Telegram", f"https://t.me/{e164}"),
                           ("Sync.me", f"https://sync.me/search/?number={quote_plus(e164)}")):
            yield Finding(category="lead", title=f"{title} check", value=url, url=url, source=self.name,
                          target=entity, confidence=0.5)


class PhoneRegistrationSource(Source):
    """Ignorant's checks (is this number registered on Instagram / Snapchat / Amazon?) run natively."""

    name = "phone-registrations"
    kinds = ("phone",)
    description = "Checks whether the number is registered on Instagram, Snapchat and Amazon (Ignorant module set)"

    def available(self, config):
        try:
            import ignorant  # noqa: F401
        except ImportError:
            return False, "pip install ignorant"
        return True, ""

    async def search(self, entity: Entity, ctx: Context):
        import importlib

        import httpx as _httpx

        region = ctx.config.get("default_region") or (ctx.knowledge.country_code() if ctx.knowledge else None)
        num = parse(entity.value, region)
        if num is None:
            return
        funcs = []
        for mod, fn in (("ignorant.modules.shopping.amazon", "amazon"), ("ignorant.modules.social_media.instagram", "instagram"),
                        ("ignorant.modules.social_media.snapchat", "snapchat")):
            try:
                funcs.append(getattr(importlib.import_module(mod), fn))
            except (ImportError, AttributeError):
                continue
        out: list[dict] = []
        async with _httpx.AsyncClient(timeout=ctx.options.timeout, proxy=ctx.config.get("proxy") or None) as client:
            async def run(f):
                try:
                    await asyncio.wait_for(f(str(num.national_number), str(num.country_code), client, out), 30)
                except Exception:
                    out.append({"name": f.__name__, "rateLimit": True})
            await asyncio.gather(*(run(f) for f in funcs))
        for res in out:
            if res.get("exists"):
                dom = res.get("domain") or res.get("name")
                yield Finding(category="account", title=str(res.get("name", dom)).capitalize(), value=dom,
                              url=f"https://{dom}", source=self.name, target=entity, confidence=0.85,
                              data={"method": "phone registration check"})
            elif res.get("rateLimit"):
                ctx.log(f"phone-registrations: {res.get('name')} rate-limited", "debug")


class NumverifySource(Source):
    name = "numverify"
    kinds = ("phone",)
    description = "Live carrier & line-type lookup via numverify/APILayer (needs numverify_api_key)"
    requires = ("numverify_api_key",)

    async def search(self, entity: Entity, ctx: Context):
        num = parse(entity.value, ctx.config.get("default_region"))
        if num is None:
            return
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        try:
            d = await ctx.get_json("https://apilayer.net/api/validate",
                                   params={"access_key": ctx.config.get("numverify_api_key"), "number": e164})
        except Exception as exc:
            ctx.log(f"numverify: {exc.__class__.__name__}", "warning")
            return
        if d.get("error"):
            ctx.log(f"numverify: {d['error'].get('info')}", "error")
            return
        for title, key in (("Carrier (live)", "carrier"), ("Line type", "line_type"), ("Location", "location")):
            if d.get(key):
                yield Finding(category="phone", title=title, value=str(d[key]).replace("_", " ").title()
                              if key == "line_type" else str(d[key]), source=self.name, target=entity, confidence=0.9)


def username_candidates(full_name: str) -> list[str]:
    import unicodedata
    clean = unicodedata.normalize("NFKD", full_name).encode("ascii", "ignore").decode().lower()
    parts = [p for p in re.split(r"[^a-z]+", clean) if p]
    if len(parts) < 2:
        return parts
    f, l = parts[0], parts[-1]
    cands = [f + l, f"{f}.{l}", f"{f}_{l}", f"{f}-{l}", f[0] + l, f"{f[0]}.{l}", f + l[0], l + f, f"{l}.{f}", l + f[0]]
    return list(dict.fromkeys(c for c in cands if len(c) >= 4))


class NameUsernamesSource(Source):
    name = "name-usernames"
    kinds = ("name",)
    description = "Generates likely usernames from a full name (searched automatically when name permutations are on)"

    async def search(self, entity: Entity, ctx: Context):
        root = ctx.report is not None and any(e.key() == entity.key() and d == 0 for e, d, _ in ctx.report.entities.values())
        active = ctx.options.name_permutations or root   # a name you searched for directly: try its handles too
        conf = 0.65 if active else 0.45
        limit = 6 if active else 10
        for cand in username_candidates(entity.value)[:limit]:
            yield Finding(category="lead", title="Username candidate", value=cand, source=self.name, target=entity,
                          confidence=conf, pivots=[Entity("username", cand)])


class NameLeadsSource(Source):
    name = "name-leads"
    kinds = ("name",)
    description = "Search links for a person's full name across social networks, records and documents"

    async def search(self, entity: Entity, ctx: Context):
        q = f'"{entity.value}"'
        leads = {
            "Web mentions": q,
            "LinkedIn": f"{q} site:linkedin.com/in",
            "Social media": f"{q} (site:facebook.com OR site:instagram.com OR site:x.com OR site:tiktok.com)",
            "Documents": f"{q} (ext:pdf OR ext:doc OR ext:docx OR ext:pptx)",
            "Code & papers": f"{q} (site:github.com OR site:scholar.google.com OR site:researchgate.net)",
        }
        for title, query in leads.items():
            url = f"https://www.google.com/search?q={quote_plus(query)}"
            yield Finding(category="lead", title=title, value=url, url=url, source=self.name, target=entity,
                          confidence=0.5)
