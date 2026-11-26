"""Cooperative mode: a shared, conservative knowledge base that lets sources help each other.

Design rules (so cooperation can't snowball into nonsense):
  1. A fact is *trusted* only if the user supplied it, a single source asserts it with
     confidence >= hint_min_confidence, or two independent sources agree on it.
  2. Trusted facts never create findings by themselves. They only (a) raise the confidence of an
     existing finding that independently contains them, or (b) flag a finding that contradicts them,
     and (c) feed hints to sources (e.g. the default phone region, a person's name for alt checks).
  3. Every adjustment is written into the finding's data (`corroborated_by` / `conflicts_with`),
     so the reason is always visible, and a finding is boosted at most once per fact.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from panoptes.models import Entity, Finding, Report, combine_confidence

# Sources whose links/emails are declared by the account owner themselves (not inferred).
OWNER_DECLARED = {"github", "platform-profiles", "gravatar", "link-pages", "social-profiles", "pgp-keys"}
NAME_TITLE = re.compile(r"(\bname\b|display name|full name)", re.I)
GENERIC_NAMES = {"admin", "user", "test", "unknown", "anonymous", "me", "official", "real"}


def norm_text(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9@.\- ]+", " ", s)).strip()


@dataclass
class Fact:
    kind: str
    value: str
    sources: set[str] = field(default_factory=set)
    confidence: float = 0.0
    user_supplied: bool = False

    def trusted(self, threshold: float) -> bool:
        return self.user_supplied or self.confidence >= threshold or len(self.sources) >= 2


class Knowledge:
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold
        self.facts: dict[tuple[str, str], Fact] = {}

    # ------------------------------------------------------------------ learning
    def add(self, kind: str, value: str, source: str, confidence: float, user_supplied: bool = False) -> None:
        value = (value or "").strip()
        key = (kind, norm_text(value))
        if not key[1] or len(key[1]) > 120:
            return
        f = self.facts.setdefault(key, Fact(kind, value))
        f.sources.add(source)
        f.confidence = max(f.confidence, confidence)
        f.user_supplied = f.user_supplied or user_supplied

    def add_entity(self, entity: Entity, user_supplied: bool = False) -> None:
        self.add(entity.kind, entity.value, "user" if user_supplied else "pivot", 1.0 if user_supplied else 0.7,
                 user_supplied)

    def observe(self, f: Finding) -> None:
        """Extract candidate facts from a finding. Only some will ever become trusted."""
        if f.category in ("summary", "insight", "lead"):
            return
        srcs = sorted(f.sources) or [f.source]
        if f.category in ("profile", "person") and NAME_TITLE.search(f.title):
            if len(norm_text(f.value).split()) >= 2:
                for s in srcs:
                    self.add("name", f.value, s, f.confidence)
        if f.category == "location" or (f.category == "profile" and "location" in f.title.lower()):
            for s in srcs:
                self.add("location", f.value, s, f.confidence * 0.9)
        owner = bool(set(srcs) & OWNER_DECLARED)
        for p in f.pivots:
            if p.kind in ("email", "domain", "username", "phone"):
                conf = f.confidence if owner else f.confidence * 0.8
                for s in srcs:
                    self.add(p.kind, p.value, s, conf)
        if f.category == "email" and "@" in f.value:
            for s in srcs:
                self.add("email", f.value, s, f.confidence)

    # ------------------------------------------------------------------ querying
    def trusted(self, kind: str) -> list[Fact]:
        return [f for (k, _), f in self.facts.items() if k == kind and f.trusted(self.threshold)]

    def trusted_values(self, kind: str) -> list[str]:
        return [f.value for f in sorted(self.trusted(kind), key=lambda f: (-len(f.sources), -f.confidence))]

    def best_name(self) -> str | None:
        names = self.trusted_values("name")
        return names[0] if names else None

    def country_code(self) -> str | None:
        """Best early guess of the subject's country: trusted phone > name origin (e.g. Icelandic patronymic)."""
        cc = self.phone_country()
        if cc:
            return cc
        from panoptes.sources.synthesis import _name_origin
        for n in self.trusted_values("name"):
            o = _name_origin(n)
            if o:
                return o[0]
        return None

    def phone_country(self) -> str | None:
        try:
            import phonenumbers
            for ph in self.trusted_values("phone"):
                num = phonenumbers.parse(ph, None if ph.startswith("+") else "US")
                cc = phonenumbers.region_code_for_number(num)
                if cc:
                    return cc
        except Exception:
            pass
        return None

    def evidence_in(self, text: str, exclude_username: str | None = None,
                    exclude_value: str | None = None, from_sources: set[str] | None = None) -> list[str]:
        """Trusted facts that *independently* appear in a piece of text (bio, page title, metadata).

        A fact never corroborates the finding it came from: facts equal to `exclude_value`, or known only
        from `from_sources` (the finding's own sources), are ignored. User-supplied facts always count."""
        t = " " + norm_text(text) + " "
        own = norm_text(exclude_value or "")
        hits = []

        def independent(fact: Fact) -> bool:
            # Corroboration must come from a *different* source than the finding's own. The same value from
            # another platform (GitHub name == Mastodon name) is exactly what independent evidence looks like.
            others = fact.sources - (from_sources or set()) - {"pivot"}
            if own and norm_text(fact.value) == own:
                return bool(others) or (fact.user_supplied and not from_sources)
            return fact.user_supplied or not from_sources or bool(others)

        for fact in self.trusted("name"):
            n = norm_text(fact.value)
            if len(n) >= 5 and f" {n} " in t and independent(fact):
                hits.append(f"name '{fact.value}'")
        for kind in ("email", "domain"):
            for fact in self.trusted(kind):
                v = norm_text(fact.value)
                if len(v) >= 5 and v in t and independent(fact):
                    hits.append(f"{kind} '{fact.value}'")
        raw = " " + (text or "").lower() + " "
        for fact in self.trusted("username"):
            v = fact.value.lower()
            if exclude_username and norm_text(v) == norm_text(exclude_username):
                continue
            # Only explicit references: "@handle" or ".../handle". A word in a display name is not a mention.
            if len(v) >= 4 and re.search(rf"(?:@|/){re.escape(v)}(?![a-z0-9_.\-])", raw) and independent(fact):
                hits.append(f"username '{fact.value}'")
        return hits

    def name_conflict(self, display: str) -> str | None:
        """A different person's full name: the surname differs from every trusted name's surname.

        Sharing a first or middle name ("Anna Smith" vs "Maria Anna Jones") is NOT a match -
        given names are common; surnames (and Icelandic patronymics) are what identify a person."""
        d = norm_text(display).split()
        names = [norm_text(n).split() for n in self.user_names() or self.trusted_values("name")]
        if len(d) < 2 or not names or set(d) & GENERIC_NAMES:
            return None
        for n in names:
            if len(n) >= 2 and d[-1] == n[-1]:
                return None          # same surname
            if set(d) <= set(n):
                return None          # a shortened form of the known name
        return " ".join(display.split())

    def user_names(self) -> list[str]:
        return [f.value for (k, _), f in self.facts.items() if k == "name" and f.user_supplied]

    def name_tokens(self) -> set[str]:
        toks = set()
        for n in self.trusted_values("name"):
            toks |= set(norm_text(n).split())
        return toks


def _host(url: str | None) -> str:
    from urllib.parse import urlparse
    h = (urlparse(url or "").hostname or "").lower().removeprefix("www.")
    return ".".join(h.split(".")[-2:]) if h else ""


def ambiguous_handles(report: Report) -> set[str]:
    """Usernames that clearly belong to several different people (common handles like 'torvalds' or 'ken').

    Signals: account profiles naming people with no name in common, or an enormous number of hits."""
    out = set()
    by_entity: dict[str, list[set[str]]] = {}
    counts: dict[str, int] = {}
    for f in report.findings.values():
        t = str(f.target)
        if f.target.kind != "username":
            continue
        if f.category == "account":
            counts[t] = counts.get(t, 0) + 1
        if f.category == "profile" and NAME_TITLE.search(f.title):
            toks = set(norm_text(f.value).split())
            if len(toks) >= 2:
                by_entity.setdefault(t, []).append(toks)
    for t, names in by_entity.items():
        groups: list[set[str]] = []
        for n in names:
            for g in groups:
                if g & n:
                    g |= n
                    break
            else:
                groups.append(set(n))
        if len(groups) >= 2:
            out.add(t)
    out |= {t for t, n in counts.items() if n >= 150}
    return out


def corroborated_hosts(report: Report, target: str) -> set[str]:
    """Platforms whose account for this handle is independently tied to the subject."""
    return {_host(f.url) for f in report.findings.values()
            if str(f.target) == target and f.data.get("corroborated_by") and f.url}


def owned(report: Report, f: Finding, ambiguous: set[str]) -> bool:
    """Can we trust that this finding is about the subject (for following its leads)?"""
    t = str(f.target)
    if t not in ambiguous:
        return True
    return bool(f.data.get("corroborated_by")) or (f.url and _host(f.url) in corroborated_hosts(report, t))


LINKING_EVIDENCE = ("name '", "email '", "domain '", "username '")


def doubtful_entities(report: Report) -> set[str]:
    """Entities that can't be trusted to be the subject: guessed/low-trust pivots, or pivots whose profiles name
    a different person - unless something independently ties them to the subject.

    Typical cases: a username generated from the subject's name, a display-name alias, an alt candidate."""
    conflicted, corroborated = set(), set()
    for f in report.findings.values():
        if f.data.get("conflicts_with"):
            conflicted.add(str(f.target))
        ev = f.data.get("corroborated_by") or []
        if f.category != "email" and any(str(e).startswith(LINKING_EVIDENCE) for e in ev):
            corroborated.add(str(f.target))
    roots = {str(e) for e, d, _ in report.entities.values() if d == 0}
    speculative = set(report.meta.get("speculative", []))
    trust = report.meta.get("trust", {})
    low_trust = {k for k, t in trust.items() if t < 0.8}
    # conflicts beat corroboration: a profile naming someone else outweighs a shared detail
    strong_conflict = {t for t in conflicted
                       if sum(1 for f in report.findings.values() if str(f.target) == t and f.data.get("conflicts_with")) >= 2}
    return ((conflicted | speculative | low_trust) - corroborated - roots) | (strong_conflict - roots)


def crosscheck(report: Report, kb: Knowledge) -> list[Finding]:
    """Raise confidence of findings that independently contain trusted facts; flag contradictions.

    Returns the findings that changed (already updated in place)."""
    changed = []
    for f in list(report.findings.values()):
        if f.category not in ("account", "profile", "email", "related-domain") or f.confidence >= 0.97:
            continue
        text = " ".join(str(x) for x in (f.title, f.value, f.data.get("page_title", ""), f.data.get("page_desc", ""),
                                         f.data.get("display_name", "")))
        own = f.target.value if f.target.kind == "username" else None
        hits = [h for h in kb.evidence_in(text, exclude_username=own, exclude_value=f.value,
                                          from_sources=set(f.sources) - {"cross-check"})
                if h not in f.data.get("corroborated_by", [])]
        if own:
            handle = re.sub(r"[^a-z0-9]", "", own.lower())
            # A handle generated from the name ("linus-torvalds") trivially "contains" the name - not evidence.
            hits = [h for h in hits if not (h.startswith("name ") and all(
                tok in handle for tok in norm_text(h[6:-1]).split()))]
        if f.target.kind != "username":
            hits = [h for h in hits if norm_text(f.target.value) not in h]
        if hits:
            f.data.setdefault("corroborated_by", []).extend(hits)
            for _ in hits[:2]:
                f.confidence = combine_confidence(f.confidence, 0.6)
            f.sources.add("cross-check")
            changed.append(f)
        display = f.data.get("display_name") or (f.value if f.category == "profile" and NAME_TITLE.search(f.title) else "")
        if display and not f.data.get("conflicts_with"):
            other = kb.name_conflict(display)
            if other:
                f.data["conflicts_with"] = f"profile name '{other}' differs from known name '{kb.best_name()}'"
                f.confidence *= 0.8
                changed.append(f)
    return changed
