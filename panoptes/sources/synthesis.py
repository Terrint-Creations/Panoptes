"""Cross-source synthesis: aliases and the subject's likely location.

Aliases - display names / nicknames that differ from the username ("jdoe42" shows as "Johnny" on
YouTube). Each is recorded with the platforms that use it. A handle-like alias seen on 2+ platforms
(or on a high-confidence account) becomes a username lead; a one-off stays a speculative lead.

Likely location - combines every location signal from accounts that aren't contradicted:
profile locations (geocoded), photo GPS, addresses, phone country, email/website country domains,
country-specific sites the person uses, and name-origin hints (e.g. Icelandic patronymics).
"""
from __future__ import annotations

import re
from collections import defaultdict

from panoptes.knowledge import doubtful_entities, norm_text
from panoptes.models import Entity, Finding, Report
from panoptes.sources.base import Context, Source, findings_for

GENERIC_DISPLAY = {"user", "admin", "me", "anonymous", "unknown", "null", "none", "-", "player", "guest"}
GENERIC_TLDS = {"co", "io", "me", "tv", "ai", "gg", "cc", "ly", "fm", "to", "so", "sh", "ws", "la", "app", "dev", "xyz"}
COUNTRY_TAGS = {"ru", "de", "fr", "pl", "nl", "ua", "cn", "gb", "us", "it", "tr", "es", "jp", "cz", "br", "vn", "fi", "se",
                "in", "au", "ir", "pk", "kr", "pt", "il", "by", "ro", "gr", "hu", "dk", "kz", "no", "id", "uz", "ch", "bg",
                "nz", "sk", "ar", "mx", "th", "at", "sg", "rs", "be", "tw", "is", "ie", "ca", "ee", "lv", "lt"}


def _name_origin(name: str) -> tuple[str, float] | None:
    parts = name.split()
    if len(parts) < 2:
        return None
    last = parts[-1].lower()
    full = name.lower()
    if re.search(r"(sson|sdóttir|sdottir|dóttir)$", last) or re.search(r"[þð]", full):
        # Icelandic patronymics ("Jónsson", "Sigurðardóttir") and þ/ð - strong, they're rare outside Iceland.
        return "IS", 0.7
    for pattern, cc, w in ((r"(sen)$", "DK", 0.25), (r"(ová|ský|ská)$", "CZ", 0.3), (r"(escu|eanu)$", "RO", 0.4),
                           (r"(oğlu|oglu)$", "TR", 0.4), (r"(inen|nen)$", "FI", 0.4), (r"(ishvili|dze)$", "GE", 0.5),
                           (r"(yan|ian)$", "AM", 0.3), (r"(ović|ovic|ević|evic)$", "RS", 0.25)):
        if re.search(pattern, last):
            return cc, w
    return None


# Letters (almost) unique to one language -> country hint when they appear in the person's own profile texts.
LANG_LETTERS = (("þ", "IS", 0.5), ("ð", "IS", 0.3), ("ő", "HU", 0.4), ("ű", "HU", 0.4), ("ł", "PL", 0.35),
                ("ř", "CZ", 0.4), ("ů", "CZ", 0.4), ("ș", "RO", 0.4), ("ț", "RO", 0.4), ("ğ", "TR", 0.35),
                ("ı", "TR", 0.35), ("ñ", "ES", 0.15), ("ã", "PT", 0.15), ("õ", "EE", 0.2), ("ø", "NO", 0.2),
                ("å", "SE", 0.15), ("ß", "DE", 0.25))


class AliasSource(Source):
    name = "aliases"
    kinds = ("username",)
    stage = "late"
    description = "Records display names/nicknames that differ from the username and follows repeated ones as new leads"

    async def search(self, entity: Entity, ctx: Context):
        from panoptes.knowledge import ambiguous_handles, owned
        ambiguous = ambiguous_handles(ctx.report) if ctx.report else set()
        aliases: dict[str, dict] = {}
        for f in findings_for(ctx, entity):
            if ambiguous and not owned(ctx.report, f, ambiguous):
                continue  # a shared handle: only display names from accounts tied to the subject
            if f.confidence < 0.6 or f.data.get("conflicts_with") or f.source == "profile-metadata":
                continue  # page <title>s ("x's profile on Site") are not display names
            disp = f.data.get("display_name")
            if not disp and f.category == "profile" and re.search(r"display name|nickname", f.title, re.I):
                disp = f.value
            if disp and (entity.value.lower() in str(disp).lower() and str(disp).lower() != entity.value.lower()):
                continue  # templated text containing the handle, not a chosen alias
            if not disp:
                continue
            disp = re.split(r"\s[|\-–·•(]\s?|\s\(@", str(disp))[0].strip()
            key = norm_text(disp)
            if (not key or key in GENERIC_DISPLAY or key.replace(" ", "") == entity.value.lower()
                    or len(key) < 2 or len(key) > 50):
                continue
            platform = f.title.split(" display")[0].split(" nickname")[0].split(" name")[0]
            a = aliases.setdefault(key, {"display": disp, "platforms": set(), "best": 0.0})
            a["platforms"].add(platform)
            a["best"] = max(a["best"], f.confidence)
        name_tokens = ctx.knowledge.name_tokens() if ctx.knowledge else set()
        for key, a in aliases.items():
            n = len(a["platforms"])
            handle_like = re.fullmatch(r"[A-Za-z0-9_.\-]{3,30}", a["display"]) is not None
            repeated = n >= 2 or a["best"] >= 0.9
            conf = min(0.9, 0.5 + 0.15 * n + (0.1 if a["best"] >= 0.9 else 0))
            # Searching an alias as a username only makes sense when it's distinctive: not part of the person's
            # real name ("Anna"), not a short common nickname ("Jo"), not a domain/brand ("Paypal.Me").
            distinctive = (handle_like and key not in name_tokens and len(key) >= 6
                           and not re.search(r"\.[a-z]{2,6}$", key) and (n >= 3 or re.search(r"\d|_", key)))
            pivots = []
            if distinctive:
                pivots = [Entity("username", a["display"])]
            elif 2 <= len(key.split()) <= 4 and all(w.isalpha() for w in key.split()):
                pivots = [Entity("name", a["display"])]
            yield Finding(category="alias", title="Alias / display name", value=a["display"], source=self.name,
                          target=entity, confidence=conf if repeated else min(conf, 0.65),
                          sources=set(a["platforms"]) or {self.name}, pivots=pivots,
                          data={"platforms": sorted(a["platforms"]),
                                "note": "used on several platforms - followed as a lead" if repeated
                                else "seen once - kept as a speculative lead"})


class LocationSynthesisSource(Source):
    """Runs once at the end (finalize) over every entity's findings."""

    name = "location-synthesis"
    kinds = ("username", "email", "name", "phone", "file", "domain")
    stage = "late"
    description = "Combines all location signals into the subject's likely country and city, with evidence"

    async def search(self, entity: Entity, ctx: Context):
        return
        yield  # pragma: no cover

    async def finalize(self, ctx: Context, report: Report) -> list[Finding]:
        from panoptes.sources.geo import nominatim

        from panoptes.knowledge import ambiguous_handles, owned
        doubtful = doubtful_entities(report)
        ambiguous = ambiguous_handles(report)
        weights: dict[str, float] = defaultdict(float)
        evidence: dict[str, list[str]] = defaultdict(list)
        names: dict[str, str] = {}
        cities: dict[tuple, float] = defaultdict(float)

        def vote(cc, w, why):
            if not cc:
                return
            cc = cc.upper()
            weights[cc] += w
            evidence[cc].append(why)

        texts: dict[str, tuple[float, str]] = {}
        for f in report.findings.values():
            if str(f.target) in doubtful or f.data.get("conflicts_with") or f.confidence < 0.55:
                continue
            if ambiguous and not owned(report, f, ambiguous):
                continue
            is_loc = f.category == "location" or (f.category == "profile" and re.search(r"\blocation\b", f.title, re.I))
            if is_loc and "timezone" not in f.title.lower():
                val = re.sub(r"\s*\(\d+ posts?\)$", "", f.value).strip()
                if re.fullmatch(r"[A-Z]{2}", val):  # bare country code (Lichess flag, TikTok region)
                    vote(val, 0.5 * f.confidence, f.title)
                    continue
                w = f.confidence * (1.5 if f.data.get("corroborated_by") else 1.0) * (2.0 if "GPS" in f.title else 1.0)
                if val and (val not in texts or texts[val][0] < w):
                    texts[val] = (w, f.title)
            if f.category == "geo" and f.title.endswith("Address") and f.data.get("country_code"):
                vote(f.data["country_code"], 1.2 * f.confidence, f"{f.title}: {f.data.get('city') or ''}")
                if f.data.get("city"):
                    cities[(f.data["country_code"].upper(), f.data["city"])] += f.confidence
            if f.category == "account" and f.confidence >= 0.8:
                for t in f.data.get("tags", []):
                    if t in COUNTRY_TAGS:
                        vote(t, 0.12, f"uses {f.title} (country-specific site)")
            if f.category in ("profile", "company", "relationship", "web", "news", "record") and f.confidence >= 0.55:
                text = f.value.lower()
                for letter, cc, w in LANG_LETTERS:
                    if letter in text:
                        vote(cc, w, f"'{letter}' in {f.title}")
                        break
                host = re.sub(r"^https?://", "", (f.url or "")).split("/")[0].lower()
                tld = host.rsplit(".", 1)[-1] if "." in host else ""
                if f.category in ("web", "news", "record", "company") and len(tld) == 2 and tld not in GENERIC_TLDS:
                    vote(tld, 0.15, f"{f.title} on .{tld} site")
        for text, (w, why) in sorted(texts.items(), key=lambda kv: -kv[1][0])[:12]:
            res = await nominatim(ctx, "search", {"q": text, "limit": 1, "addressdetails": 1})
            if res:
                a = res[0].get("address", {})
                cc = (a.get("country_code") or "").upper()
                if cc:
                    names[cc] = a.get("country", cc)
                    vote(cc, w, f"{why}: '{text}'")
                    city = a.get("city") or a.get("town") or a.get("village")
                    if city:
                        cities[(cc, city)] += w
        kb = ctx.knowledge
        if kb:
            cc = kb.country_code()
            if cc:
                vote(cc, 1.0, "phone number country")
            for em in kb.trusted_values("email") + kb.trusted_values("domain"):
                tld = em.rsplit(".", 1)[-1].lower()
                if len(tld) == 2 and tld not in GENERIC_TLDS:
                    vote(tld, 0.4, f"country domain .{tld} ({em})")
            for name in kb.trusted_values("name")[:2]:
                origin = _name_origin(name)
                if origin:
                    vote(origin[0], origin[1], f"name origin ('{name}')")
        if not weights:
            return []
        ranked = sorted(weights.items(), key=lambda kv: -kv[1])
        total = sum(weights.values())
        primary = report.targets[0]
        cc, w = ranked[0]
        kinds = len({e.split(":")[0].split(" (")[0] for e in evidence[cc]})
        conf = min(0.95, 0.35 + 0.12 * len(evidence[cc]) + 0.25 * (w / total))
        ctx.shared["likely-country"] = cc
        out = [Finding(category="summary", title="Likely country", value=f"{names.get(cc, cc)} ({cc})",
                       source=self.name, target=primary, confidence=conf,
                       data={"share_of_evidence": round(w / total, 2), "evidence": evidence[cc][:15],
                             "other_candidates": {k: round(v, 2) for k, v in ranked[1:5]}, "signal_types": kinds})]
        city_votes = sorted(((c, v) for (k, c), v in cities.items() if k == cc), key=lambda kv: -kv[1])
        if city_votes and (city_votes[0][1] >= 1.2 or len(city_votes) == 1 and conf >= 0.6):
            out.append(Finding(category="summary", title="Likely city", value=f"{city_votes[0][0]}, {names.get(cc, cc)}",
                               source=self.name, target=primary, confidence=min(0.9, 0.4 + 0.25 * city_votes[0][1]),
                               data={"other_cities": [c for c, _ in city_votes[1:5]]},
                               pivots=[Entity("location", f"{city_votes[0][0]}, {names.get(cc, cc)}")]))
        return out
