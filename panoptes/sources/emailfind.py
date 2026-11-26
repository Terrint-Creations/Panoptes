"""Email discovery from a username (what an investigator does by hand in five minutes).

1. Collects addresses the person published themselves: commit metadata, GPG keys, npm publisher
   records, Gravatar, link pages (gathered by other sources - this one adds guessing + verification).
2. Generates likely addresses: the handle (and the confirmed real name, when there is one) at the big
   free providers and at personal domains found during the search.
3. Verifies each guess without sending any email: does a Gravatar exist for it, does Spotify say it's
   registered, does Duolingo return an account for it - and if Duolingo returns *this* username, the
   address is confirmed as the person's.

Only verified guesses are reported; unverified guesses are never shown or pivoted on.
"""
from __future__ import annotations

import asyncio
import hashlib
import re

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, findings_for

PROVIDERS = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com",
             "live.com", "gmx.com", "yandex.ru", "mail.ru"]


def candidate_locals(username: str, name: str | None) -> list[tuple[str, str]]:
    """(local part, how it was derived)."""
    u = username.lower()
    out = [(u, "username")]
    bare = re.sub(r"[._\-]", "", u)
    if bare != u:
        out.append((bare, "username without separators"))
    if name:
        import unicodedata
        clean = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
        parts = [p for p in re.split(r"[^a-z]+", clean) if p]
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            out += [(f"{f}.{l}", "real name"), (f"{f}{l}", "real name"), (f"{f[0]}{l}", "real name"), (f"{f}_{l}", "real name")]
    seen, res = set(), []
    for loc, how in out:
        if loc not in seen and re.fullmatch(r"[a-z0-9._\-]{3,40}", loc):
            seen.add(loc)
            res.append((loc, how))
    return res


class EmailDiscoverySource(Source):
    name = "email-discovery"
    kinds = ("username",)
    stage = "late"
    description = ("Finds the email behind a username: guesses likely addresses (handle / real name @ common providers "
                   "and personal domains) and verifies them via Gravatar, Spotify and Duolingo - only verified ones are kept")

    async def search(self, entity: Entity, ctx: Context):
        kb = ctx.knowledge
        name = kb.best_name() if kb else None
        domains = list(PROVIDERS)
        if kb:
            for d in kb.trusted_values("domain")[:3]:
                if d not in domains and "." in d:
                    domains.insert(0, d)
        locals_ = candidate_locals(entity.value, name)
        cands = []
        for loc, how in locals_:
            for d in domains:
                if how == "real name" and d not in PROVIDERS[:4] and d not in (kb.trusted_values("domain") if kb else []):
                    continue  # real-name guesses only at the biggest providers and the person's own domains
                cands.append((f"{loc}@{d}", how, d))
        cands = cands[:40]
        from panoptes.knowledge import ambiguous_handles
        u = entity.value.lower()
        ambiguous = ambiguous_handles(ctx.report) if ctx.report else set()
        distinctive = len(u) >= 7 and str(entity) not in ambiguous and len(findings_for(ctx, entity, "account")) < 120
        ctx.progress(self.name, entity, 0, len(cands))
        done = 0
        sem = asyncio.Semaphore(6)

        async def verify(email, how, domain):
            async with sem:
                signals, linked = [], None
                md5 = hashlib.md5(email.encode()).hexdigest()
                checks = await asyncio.gather(
                    self._gravatar(ctx, md5), self._spotify(ctx, email), self._duolingo(ctx, email),
                    return_exceptions=True)
                grav, spot, duo = [c if not isinstance(c, Exception) else None for c in checks]
                if grav:
                    signals.append("Gravatar exists")
                if spot:
                    signals.append("registered on Spotify")
                if duo:
                    signals.append(f"Duolingo account '{duo}'")
                    if duo.lower() == entity.value.lower():
                        linked = "Duolingo account with this exact username uses this address"
                return email, how, domain, signals, linked, md5 if grav else None

        for fut in asyncio.as_completed([verify(*c) for c in cands]):
            email, how, domain, signals, linked, grav_md5 = await fut
            done += 1
            ctx.progress(self.name, entity, done, len(cands))
            if not signals:
                continue
            if linked:
                conf = 0.95
            else:
                base = {"username": 0.55, "username without separators": 0.5, "real name": 0.45}.get(how, 0.45)
                if how.startswith("username") and distinctive:
                    base += 0.15   # a rare handle at a big provider is very likely the same person
                if domain not in PROVIDERS:
                    base += 0.1  # the person's own domain
                conf = min(0.8 if distinctive else 0.66, base + 0.1 * len(signals))  # exists != belongs to this person
            data = {"derived_from": how, "verified_by": signals, "services": [s.split(" on ")[-1] for s in signals
                                                                             if s.startswith("registered on")],
                    "note": linked or
                    "address exists and matches the handle/name pattern - likely but not proven to be the same person"}
            if grav_md5:
                data["avatar"] = f"https://www.gravatar.com/avatar/{grav_md5}?s=400"
            yield Finding(category="email", title="Likely email (verified exists)" if not linked else "Email (confirmed)",
                          value=email, source=self.name, target=entity, confidence=conf, data=data,
                          pivots=[Entity("email", email)] if linked or conf >= 0.75 else [])

    async def _gravatar(self, ctx, md5) -> bool:
        r = await ctx.get(f"https://www.gravatar.com/avatar/{md5}", params={"d": "404"}, timeout=10)
        return r.status_code == 200

    async def _spotify(self, ctx, email) -> bool:
        r = await ctx.get("https://spclient.wg.spotify.com/signup/public/v1/account",
                          params={"validate": 1, "email": email}, timeout=10)
        return r.status_code == 200 and r.json().get("status") == 20

    async def _duolingo(self, ctx, email) -> str | None:
        r = await ctx.get("https://www.duolingo.com/2017-06-30/users", params={"email": email}, headers=API_HEADERS,
                          timeout=10)
        users = r.json().get("users", []) if r.status_code == 200 else []
        return users[0].get("username") if users else None
