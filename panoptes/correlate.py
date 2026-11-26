"""Correlation rules + identity synthesis (SpiderFoot correlation / Maltego-style analysis).

Runs once after a search. Reads every finding across every entity and produces:
  * summary  - who this appears to be: names, locations, emails, usernames, phones, sites,
               each ranked by how many independent sources agree
  * insight  - rule hits with a severity (info / low / medium / high) and an overall exposure score
"""
from __future__ import annotations

import re
from collections import defaultdict

from panoptes.models import Entity, Finding, Report, combine_confidence

SEVERITY_POINTS = {"info": 0, "low": 3, "medium": 8, "high": 18}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
               27017: "MongoDB", 11211: "Memcached", 2375: "Docker API", 5432: "PostgreSQL", 3306: "MySQL"}
NAME_TITLE = re.compile(r"(\bname\b|display name|full name|^person)", re.I)
LOCATION_TITLE = re.compile(r"location|country|city|time zone", re.I)


NAME_SHAPE = re.compile(r"^[^\W\d_][^\W\d_ .'\-]*(?:[ .'\-]+[^\W\d_]+)*$")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().strip(".,")).lower()


def _fold(s: str) -> str:
    """Accent-insensitive key: 'José' and 'Jose' are the same name typed on different keyboards."""
    import unicodedata
    s = s.replace("ð", "d").replace("Ð", "d").replace("þ", "th").replace("Þ", "th").replace("æ", "ae").replace("ø", "o")
    return "".join(c for c in unicodedata.normalize("NFKD", _norm(s)) if not unicodedata.combining(c))


def _insight(target: Entity, title: str, value: str, severity: str, conf: float = 0.9, **data) -> Finding:
    return Finding(category="insight", title=title, value=value, source="correlation", target=target,
                   confidence=conf, data={"severity": severity, **data})


def _privacy_proxy(f: Finding) -> bool:
    return bool(re.search(r"privacy|redacted|proxy|whoisguard|domains by|withheld|contact privacy|not disclosed",
                          f"{f.value} {f.data}", re.I))


def correlate(report: Report) -> list[Finding]:
    findings = list(report.findings.values())
    if not findings or not report.targets:
        return []
    primary = report.targets[0]
    out: list[Finding] = []

    # ------------------------------------------------------------------ identity synthesis
    names: dict[str, tuple[str, set[str]]] = {}
    locations: dict[str, tuple[str, set[str]]] = {}

    handles = {e.value.lower() for e, _, _ in report.entities.values() if e.kind == "username"}

    def vote(bucket, value, source, is_name=False):
        key = _norm(value)
        if not key or len(key) > 80:
            return
        if is_name and len(key.split()) < 2:
            return  # single tokens are handles/nicknames, not real names
        if is_name and not NAME_SHAPE.match(value.strip()):
            return  # hashtags, handles with digits, sentences - not a person's name
        key = _fold(key)
        display, srcs = bucket.get(key, (value.strip(), set()))
        if sum(ord(c) > 127 for c in value) > sum(ord(c) > 127 for c in display):
            display = value.strip()   # keep the spelling with the proper accents
        srcs.add(source)
        bucket[key] = (display, srcs)

    for e, depth, _ in report.entities.values():
        if e.kind == "name" and depth == 0:
            vote(names, e.value, "user", True)
    from panoptes.knowledge import ambiguous_handles, doubtful_entities, owned
    doubtful = doubtful_entities(report)
    ambiguous = ambiguous_handles(report)
    for f in findings:
        if f.category in ("summary", "insight") or str(f.target) in doubtful:
            continue
        if ambiguous and not owned(report, f, ambiguous):
            continue  # a shared handle: other people's profiles don't describe the subject
        if f.category in ("profile", "person") and NAME_TITLE.search(f.title):
            # one vote per *platform* ("Codewars name", "GitHub name"), not per Panoptes module
            vote(names, f.value, re.sub(r"\s*(real |display |full )?name$", "", f.title, flags=re.I) or f.source, True)
        for p in f.pivots:
            # relationship/associate pivots name *other* people - only the subject's own name fields vote
            if p.kind == "name" and f.category in ("profile", "person") and NAME_TITLE.search(f.title):
                vote(names, p.value, re.sub(r"\s*(real |display |full )?name$", "", f.title, flags=re.I) or f.source, True)
        if f.category == "location" or (f.category == "profile" and LOCATION_TITLE.search(f.title)):
            if f.category == "location" and "GPS" in f.title:
                continue
            for s in f.sources:
                vote(locations, f.value, s)

    # A name that appears on the person's own account pages (titles, bios) is corroborated by each of them.
    for key, (display, srcs) in list(names.items()):
        for f in findings:
            if f.category != "account" or str(f.target) in doubtful or f.confidence < 0.6:
                continue
            page = _fold(" ".join(str(f.data.get(k, "")) for k in ("page_title", "page_desc", "display_name")))
            if key and f" {key} " in f" {page} ":
                srcs.add(f"{f.title} page")

    def emit(bucket, title, limit=5):
        ranked = sorted(bucket.values(), key=lambda v: (-len(v[1]), v[0]))[:limit]
        for display, srcs in ranked:
            n = len(srcs - {"user"})
            conf = 0.99 if "user" in srcs else min(0.98, 1 - 0.45 * 0.55 ** max(0, n - 1))
            out.append(Finding(category="summary", title=title, value=display, source="correlation", target=primary,
                               sources=set(srcs), confidence=conf, data={"independent_sources": len(srcs)},
                               pivots=[Entity("name", display)] if title == "Name" else []))
        return ranked

    top_names = emit(names, "Name")
    emit(locations, "Location")

    entities = [e for e, _, _ in report.entities.values()]
    by_kind: dict[str, set[str]] = defaultdict(set)
    for e in entities:
        by_kind[e.kind].add(e.value)
    for f in findings:
        if str(f.target) in doubtful or (ambiguous and not owned(report, f, ambiguous)):
            continue
        if f.target.kind == "ip":
            continue  # network owners' contacts, not the subject's
        for p in f.pivots:
            if p.kind in ("email", "phone") and f.confidence >= 0.6:
                by_kind[p.kind].add(p.value.lower() if p.kind == "email" else p.value)
    # Leads we couldn't tie to the subject, and infrastructure contacts (network abuse desks, registrars), aren't
    # part of who the person is.
    for k in list(by_kind):
        by_kind[k] = {v for v in by_kind[k] if f"{k}:{v}" not in doubtful
                      and not (k == "email" and re.search(r"abuse|noc|hostmaster|ipmanagement|routing|registrar|"
                                                          r"domains?@|dns@|postmaster|support@|privacy|whois", v, re.I))}
    # Usernames *generated* from the name are guesses: they only describe the subject once one of their pages
    # names the subject.
    top = _fold(top_names[0][0]) if top_names else ""
    guessed = {e.value for e, _, via in report.entities.values()
               if e.kind == "username" and via and "candidate" in str(via).lower()}
    for v in list(guessed):
        pages = " ".join(_fold(" ".join(str(f.data.get(k, "")) for k in ("page_title", "page_desc", "display_name")))
                         for f in findings if f.target.kind == "username" and f.target.value == v)
        if top and f" {top} " in f" {pages} ":
            guessed.discard(v)
    by_kind["username"] = by_kind.get("username", set()) - guessed

    # Street addresses - anything already public (WHOIS, registries, profiles, photos) that names a street.
    addresses: dict[str, tuple[str, set[str]]] = {}
    street = re.compile(r"\d+\w?\s*,?\s+\S+|\S+\s+\d+\w?\b")
    for f in findings:
        if str(f.target) in doubtful or f.confidence < 0.55 or f.target.kind == "ip":
            continue  # an IP's RDAP addresses are the network operator's
        if re.search(r"abuse|noc|routing|dns|technical|billing|registrar|administrative", f.title, re.I):
            continue  # infrastructure contacts, not the subject
        if f.category == "registration" and _privacy_proxy(f):
            continue
        val = f.data.get("address") if isinstance(f.data.get("address"), str) else None
        if f.category == "address" or "address" in f.title.lower():
            val = val or f.value
        if val:
            val = re.sub(r"\s*\n\s*", ", ", val.strip())
        if val and street.search(val) and len(val) < 200:
            vote(addresses, val, f.title)
    emit(addresses, "Address")

    for kind, title in (("email", "Email"), ("username", "Username"), ("phone", "Phone"), ("domain", "Website / domain"),
                        ("crypto", "Wallet")):
        for v in sorted(by_kind.get(kind, ()))[:15]:
            searched = any(e.kind == kind and e.value.lower() == v.lower() for e in entities)
            out.append(Finding(category="summary", title=title, value=v, source="correlation", target=primary,
                               confidence=0.9 if searched else 0.7, data={"searched": searched}))

    accounts_by_user: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.category == "account":
            accounts_by_user[str(f.target)] += 1
    total_accounts = sum(accounts_by_user.values())
    if total_accounts:
        out.append(Finding(category="summary", title="Online accounts", value=f"{total_accounts} accounts found",
                           source="correlation", target=primary, confidence=0.9, data=dict(accounts_by_user)))

    # ------------------------------------------------------------------ rules
    if top_names and len(top_names[0][1]) >= 2:
        display, srcs = top_names[0]
        out.append(_insight(primary, "Identity corroborated", f"'{display}' confirmed by {len(srcs)} independent sources",
                            "info", sources=sorted(srcs)))
    if len(top_names) >= 3 and all(len(s) == 1 for _, s in top_names[:3]):
        out.append(_insight(primary, "Conflicting identities", "Several different names found with no corroboration - "
                            "pivots may have reached different people", "low", 0.7))

    for user, n in accounts_by_user.items():
        if n >= 10 and user.startswith("username:"):
            out.append(_insight(Entity("username", user.split(":", 1)[1]), "Username reuse",
                                f"Same username on {n} sites - accounts are easy to link", "low" if n < 40 else "medium"))

    breaches = defaultdict(list)
    for f in findings:
        if f.category == "breach" and f.title == "Data breach":
            breaches[f.target].append(f.value)
        if f.category == "breach" and f.title == "Leaked data types" and "password" in f.value:
            if f.target.kind == "email":
                out.append(_insight(f.target, "Passwords leaked", "Breach data for this email includes passwords", "high"))
            else:
                out.append(_insight(f.target, "Passwords leaked (unconfirmed)", "Leaks containing this username include "
                                    "passwords - may belong to other people using the same name", "low", 0.5))
    for target, names_ in breaches.items():
        listed = ", ".join(sorted(names_)[:8]) + ("…" if len(names_) > 8 else "")
        if target.kind == "email":
            sev = "high" if len(names_) >= 5 else "medium" if len(names_) >= 2 else "low"
            out.append(_insight(target, "Breach exposure", f"Found in {len(names_)} breaches: {listed}", sev))
        else:
            out.append(_insight(target, "Username in leaks (unconfirmed)",
                                f"{len(names_)} leaks contain this username (could be different people): {listed}", "low", 0.5))

    simple_rules = [
        (lambda f: f.category == "email" and f.title == "Commit author email",
         "Email leaked via git commits", "medium", "Public commit metadata exposes this address"),
        (lambda f: f.category == "dns" and f.title == "DMARC" and f.value.startswith("No DMARC"),
         "Domain can be spoofed", "medium", "No DMARC policy - anyone can send mail as this domain"),
        (lambda f: f.category == "email" and f.title == "Disposable address",
         "Disposable email", "low", "Throwaway address - expect little real-world linkage"),
        (lambda f: f.category == "location" and "GPS" in f.title,
         "GPS location in file", "high", "File metadata reveals precise coordinates"),
    ]
    for match, title, sev, text in simple_rules:
        for f in findings:
            if match(f):
                out.append(_insight(f.target, title, f"{text} ({f.value[:80]})", sev))

    grouped = defaultdict(list)
    for f in findings:
        grouped[(f.target, f.category, f.title)].append(f)
    for (target, cat, title), fs in grouped.items():
        if cat == "lookalike":
            continue
        if cat == "exposure" and title == "Vulnerability":
            out.append(_insight(target, "Known vulnerabilities", f"{len(fs)} CVEs associated with exposed software", "high"))
        if cat == "url" and title in ("Sensitive file", "Secret in URL"):
            out.append(_insight(target, f"Archived {title.lower()}s", f"{len(fs)} archived URLs look like {title.lower()}s",
                                "medium"))
        if cat == "person":
            where = "this file's metadata" if target.kind == "file" else "published documents"
            out.append(_insight(target, "People in metadata",
                                f"{len({_norm(f.value) for f in fs})} names/usernames leak from {where}", "low"))
    lookalikes = defaultdict(list)
    for f in findings:
        if f.category == "lookalike":
            lookalikes[f.target].append(f)
    for target, fs in lookalikes.items():
        mail = [f.value for f in fs if f.data.get("mx")]
        out.append(_insight(target, "Lookalike domains", f"{len(fs)} registered lookalikes, {len(mail)} can receive email"
                            + (f" (e.g. {', '.join(mail[:4])})" if mail else ""), "medium" if mail else "low"))
    for f in findings:
        if f.category == "exposure" and f.title == "Open ports":
            ports = {int(p) for p in re.findall(r"\d+", f.value)}
            risky = [f"{p}/{RISKY_PORTS[p]}" for p in sorted(ports & RISKY_PORTS.keys())]
            if risky:
                out.append(_insight(f.target, "Risky services exposed", ", ".join(risky), "high"))
        if f.category == "threat" and f.data.get("severity") in ("medium", "high") and f.confidence >= 0.7:
            out.append(_insight(f.target, f"Threat intel: {f.title}", f.value, f.data["severity"]))
        if f.category == "subdomain" and f.data.get("live") is False:
            continue

    # ------------------------------------------------------------------ rules for the newer capabilities
    stealers = defaultdict(list)
    for f in findings:
        if f.category == "breach" and f.title == "Infostealer infection":
            stealers[f.target].append(f.value)
    for target, vals in stealers.items():
        email = target.kind == "email"
        out.append(_insight(target, "Infostealer infection" if email else "Infostealer infection (unconfirmed)",
                            f"{len(vals)} computer(s) infected by credential-stealing malware held this {target.kind}: "
                            f"{'; '.join(vals[:3])}", "high" if email else "low", 0.9 if email else 0.5))
    for f in findings:
        if (f.category == "image-link" and len(f.data.get("entities", [])) > 1 and not f.data.get("widely_published")
                and not set(f.data.get("entities", [])) & doubtful):
            out.append(_insight(f.target, "Accounts linked by profile picture",
                                f"The same picture is used by {', '.join(f.data['entities'])}", "info"))
        if f.category == "face-match" and f.data.get("involves_target_photo"):
            out.append(_insight(f.target, "Face in photo matches a profile picture",
                                f"{f.value} (similarity {f.data.get('similarity')})", "medium",
                                f.confidence))
        if f.category == "onion" and f.data.get("severity") in ("medium", "high"):
            out.append(_insight(f.target, f"Onion service: {f.title}", f.value, f.data["severity"]))
    alts = defaultdict(list)
    for f in findings:
        if f.category == "alt-account":
            alts[f.target].append(f.data.get("alt_username", f.value))
    for target, names_ in alts.items():
        out.append(_insight(target, "Alternate accounts", f"{len(names_)} likely alt account(s): {', '.join(sorted(set(names_)))}",
                            "info"))
    dark = defaultdict(int)
    for f in findings:
        if f.category == "darkweb" and f.data.get("exact_match"):
            dark[f.target] += 1
    for target, n in dark.items():
        out.append(_insight(target, "Dark-web mentions", f"Appears on {n} indexed .onion page(s)", "medium"))
    trackers = defaultdict(set)
    for f in findings:
        if f.title.startswith("Tracking ID:") and f.target.kind in ("domain", "onion"):
            trackers[f.value].add(f.target.value)
    for tid, sites in trackers.items():
        if len(sites) > 1:
            out.append(_insight(primary, "Shared tracking ID", f"{tid} is used on {', '.join(sorted(sites))} - "
                                "likely the same owner", "medium"))
    conflicts = [f for f in findings if f.data.get("conflicts_with")]
    if conflicts:
        out.append(_insight(primary, "Possibly different people", f"{len(conflicts)} profile(s) show a different "
                            f"name than the confirmed one - review before relying on them", "low", 0.7))

    # Entities reached through a pivot whose profile names a different person: say so once, drop the rest.
    if doubtful:
        out = [i for i in out if not (i.category == "insight" and str(i.target) in doubtful)]
        for key in sorted(doubtful):
            kind, _, value = key.partition(":")
            speculative = key in set(report.meta.get("speculative", []))
            out.append(_insight(Entity(kind, value), "Unverified lead" if speculative else "Probably a different person",
                                ("A guessed identifier that nothing independently tied to the subject - its results are "
                                 "kept for review but not followed or counted") if speculative else
                                ("This pivot's profiles name someone other than the subject - its results are kept "
                                 "but not followed or counted"), "info", 0.7))

    # ------------------------------------------------------------------ email <-> username joins
    # An email registered on a service + the person's handle = the likely profile on that service (and when the
    # handle's account there was already found, the two corroborate each other).
    out += _service_joins(report, findings, doubtful, ambiguous)

    # ------------------------------------------------------------------ overall score
    # one contribution per kind of insight, so 10 similar hits don't max out the score
    worst: dict[str, int] = {}
    for i in out:
        if i.category == "insight" and "unconfirmed" not in i.title:
            pts = SEVERITY_POINTS.get(i.data.get("severity", "info"), 0)
            worst[i.title] = max(worst.get(i.title, 0), pts)
    score = min(100, sum(worst.values()))
    label = "high" if score >= 45 else "medium" if score >= 20 else "low"
    out.append(Finding(category="summary", title="Exposure score", value=f"{score}/100 ({label})", source="correlation",
                       target=primary, confidence=0.9, data={"score": score}))
    return out


SERVICE_PROFILES = {
    "spotify": ("Spotify", "https://open.spotify.com/user/{u}"), "twitter": ("X (Twitter)", "https://x.com/{u}"),
    "x.com": ("X (Twitter)", "https://x.com/{u}"), "instagram": ("Instagram", "https://www.instagram.com/{u}/"),
    "pinterest": ("Pinterest", "https://www.pinterest.com/{u}/"), "github": ("GitHub", "https://github.com/{u}"),
    "tiktok": ("TikTok", "https://www.tiktok.com/@{u}"), "snapchat": ("Snapchat", "https://www.snapchat.com/add/{u}"),
    "imgur": ("Imgur", "https://imgur.com/user/{u}"), "tumblr": ("Tumblr", "https://{u}.tumblr.com"),
    "duolingo": ("Duolingo", "https://www.duolingo.com/profile/{u}"), "chess": ("Chess.com", "https://www.chess.com/member/{u}"),
    "patreon": ("Patreon", "https://www.patreon.com/{u}"), "soundcloud": ("SoundCloud", "https://soundcloud.com/{u}"),
    "wattpad": ("Wattpad", "https://www.wattpad.com/user/{u}"), "strava": ("Strava", "https://www.strava.com/athletes/{u}"),
    "vsco": ("VSCO", "https://vsco.co/{u}"), "flickr": ("Flickr", "https://www.flickr.com/people/{u}"),
    "bitmoji": ("Snapchat", "https://www.snapchat.com/add/{u}"), "discord": ("Discord", ""), "amazon": ("Amazon", ""),
    "adobe": ("Adobe", ""), "office365": ("Microsoft", ""), "firefox": ("Firefox", ""),
}


def _service_key(text: str) -> str | None:
    t = text.lower()
    for k in SERVICE_PROFILES:
        if k in t:
            return k
    return None


def _service_joins(report: Report, findings: list[Finding], doubtful: set[str], ambiguous: set[str]) -> list[Finding]:
    from panoptes.knowledge import owned
    handles = [e.value for e, d, _ in report.entities.values() if e.kind == "username" and str(e) not in doubtful]
    if not handles:
        return []
    registered: dict[str, set[str]] = defaultdict(set)    # service key -> emails registered there
    for f in findings:
        if str(f.target) in doubtful:
            continue
        if f.target.kind == "email" and f.category == "account":          # holehe / email-sites registrations
            k = _service_key(f.title + " " + f.value)
            if k:
                registered[k].add(f.target.value)
        for svc in f.data.get("services", []) if f.category == "email" and f.confidence >= 0.55 else []:
            k = _service_key(svc)
            if k:
                registered[k].add(f.value)
    out: list[Finding] = []
    primary = report.targets[0]
    for k, emails in registered.items():
        label, template = SERVICE_PROFILES[k]
        for h in handles:
            matching = [e for e in emails if e.split("@")[0].lower() == h.lower()]
            existing = [f for f in findings if f.category == "account" and f.target.kind == "username"
                        and f.target.value.lower() == h.lower() and _service_key(f.title + " " + (f.url or "")) == k]
            if existing:
                for f in existing:
                    note = f"email {sorted(emails)[0]} is registered on {label}"
                    if note not in f.data.get("corroborated_by", []):
                        f.data.setdefault("corroborated_by", []).append(note)
                        f.confidence = combine_confidence(f.confidence, 0.6 if matching else 0.4)
                continue
            if template and matching:
                url = template.replace("{u}", h)
                out.append(Finding(category="account", title=f"{label} (likely - email registered there)", value=url, url=url,
                                   source="correlation", target=Entity("username", h), confidence=0.6,
                                   data={"evidence": f"{matching[0]} is registered on {label} and matches this handle",
                                         "note": "profile URL inferred - open it to confirm"}))
    return out
