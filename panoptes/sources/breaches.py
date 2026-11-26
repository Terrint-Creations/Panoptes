"""Breach exposure, merged across Have I Been Pwned, XposedOrNot and LeakCheck.

Every provider's breach names are normalised to one canonical label, so a breach
reported by two providers shows up once with both as sources.
"""
from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source


def canonical(name: str) -> str:
    n = re.sub(r"\.(com|net|org|io|co|ru|de|fr|uk|me|tv|gg)$", "", name.strip(), flags=re.I)
    n = re.sub(r"[-_ ]+(scraped|speculated|dump|leak|breach)$", "", n, flags=re.I)
    return n[:1].upper() + n[1:] if n else name


def _breach(entity: Entity, name: str, source: str, conf: float, **data) -> Finding:
    return Finding(category="breach", title="Data breach", value=canonical(name), source=source, target=entity,
                   confidence=conf, data={k: v for k, v in data.items() if v not in (None, "", [])})


class HIBPSource(Source):
    name = "hibp"
    kinds = ("email",)
    description = "Have I Been Pwned breach exposure (needs hibp_api_key)"
    requires = ("hibp_api_key",)

    async def search(self, entity: Entity, ctx: Context):
        headers = {"hibp-api-key": ctx.config.get("hibp_api_key"), "user-agent": "panoptes-osint"}
        try:
            r = await ctx.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(entity.value)}",
                              headers=headers, params={"truncateResponse": "false"})
        except httpx.HTTPError as exc:
            ctx.log(f"hibp: {exc.__class__.__name__}", "warning")
            return
        if r.status_code == 401:
            ctx.log("hibp: API key rejected", "error")
            return
        if r.status_code != 200:
            return
        for b in r.json():
            yield _breach(entity, b.get("Name", ""), self.name, 0.97, date=b.get("BreachDate"), domain=b.get("Domain"),
                          exposed=b.get("DataClasses"), accounts=b.get("PwnCount"))


class XposedOrNotSource(Source):
    name = "xposedornot"
    kinds = ("email",)
    description = "XposedOrNot free breach database: breach names, dates and exposed data types"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": entity.value},
                              headers=API_HEADERS)
            if r.status_code != 200:
                return
            d = r.json()
        except (httpx.HTTPError, ValueError):
            return
        details = ((d.get("ExposedBreaches") or {}).get("breaches_details")) or []
        for b in details:
            yield _breach(entity, b.get("breach", ""), self.name, 0.9, date=b.get("xposed_date"),
                          domain=b.get("domain"), exposed=(b.get("xposed_data") or "").split(";"),
                          accounts=b.get("xposed_records"), password_risk=b.get("password_risk"))
        risk = (d.get("BreachMetrics") or {}).get("risk") or []
        if risk and isinstance(risk[0], dict) and risk[0].get("risk_label"):
            yield Finding(category="breach", title="Exposure risk (XposedOrNot)",
                          value=f"{risk[0]['risk_label']} (score {risk[0].get('risk_score')})", source=self.name,
                          target=entity, confidence=0.8)


class InfostealerSource(Source):
    name = "hudsonrock"
    kinds = ("email", "username")
    description = "Hudson Rock Cavalier: computers infected by info-stealer malware that held this email/username"

    async def search(self, entity: Entity, ctx: Context):
        kind = "email" if entity.kind == "email" else "username"
        try:
            r = await ctx.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{kind}",
                              params={kind: entity.value}, headers=API_HEADERS)
            d = r.json() if r.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            return
        conf = 0.9 if kind == "email" else 0.6
        for s in d.get("stealers") or []:
            when = (s.get("date_compromised") or "")[:10]
            yield Finding(category="breach", title="Infostealer infection",
                          value=f"{when} - {s.get('operating_system') or 'unknown OS'}"
                                + (f" ({s.get('stealer_family')})" if s.get("stealer_family") else ""),
                          source=self.name, target=entity, confidence=conf,
                          url="https://www.hudsonrock.com/free-tools",
                          data={k: s.get(k) for k in ("computer_name", "malware_path", "antiviruses", "top_logins",
                                                       "total_user_services", "total_corporate_services") if s.get(k)}
                               | {"severity": "high"})


class CombSource(Source):
    """The 'Compilation of Many Breaches' - only reports that credentials exist. Passwords are never read out."""

    name = "comb"
    kinds = ("email",)
    description = "Checks the COMB credential compilation for this exact email (count only - passwords are not stored)"

    async def search(self, entity: Entity, ctx: Context):
        email = entity.value.lower()
        try:
            r = await ctx.get("https://api.proxynova.com/comb", params={"query": email, "start": 0, "limit": 50},
                              headers=API_HEADERS)
            lines = r.json().get("lines", []) if r.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            return
        exact = sum(1 for line in lines if line.split(":", 1)[0].strip().lower() == email)
        if exact:
            yield Finding(category="breach", title="Data breach", value="COMB (Compilation of Many Breaches)",
                          source=self.name, target=entity, confidence=0.85,
                          data={"credential_pairs": exact, "note": "passwords withheld by Panoptes"})


class LeakCheckSource(Source):
    name = "leakcheck"
    kinds = ("email", "username")
    description = "LeakCheck public API: which leaks contain the email/username and what fields leaked"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.get("https://leakcheck.io/api/public", params={"check": entity.value}, headers=API_HEADERS)
            d = r.json() if r.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            return
        if not d.get("success") or not d.get("found"):
            return
        conf = 0.85 if entity.kind == "email" else 0.6   # usernames collide between people
        for src in d.get("sources") or []:
            yield _breach(entity, src.get("name", ""), self.name, conf, date=src.get("date"))
        if d.get("fields"):
            yield Finding(category="breach", title="Leaked data types", value=", ".join(sorted(d["fields"])),
                          source=self.name, target=entity, confidence=conf,
                          data={"total_records": d.get("found")})
