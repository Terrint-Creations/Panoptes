"""Companies, officers and power networks (OpenCorporates / Oligrapher / LittleSis capabilities).

Company targets: legal entity records (GLEIF LEI - free; OpenCorporates and UK Companies House with keys),
US public-company filings (SEC EDGAR), sanctions/PEP screening (OpenSanctions, key), and relationship
networks (LittleSis - the database behind Oligrapher maps).
Person targets: officer appointments (Companies House), insider filings (EDGAR), power-network
relationships (LittleSis) and sanctions/PEP screening.
"""
from __future__ import annotations

import re
import unicodedata

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source

SEC_HEADERS = {"User-Agent": "Panoptes OSINT research tool admin@panoptes.invalid", "Accept": "application/json"}
LEGAL_SUFFIX = re.compile(r"\b(inc|llc|ltd|limited|gmbh|corp|corporation|plc|sa|ag|bv|nv|srl|oy|ab|as|pty|co|company|"
                          r"holdings|group|the)\b\.?", re.I)


def norm_org(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    s = LEGAL_SUFFIX.sub(" ", s)
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def same_entity(a: str, b: str) -> bool:
    na, nb = norm_org(a), norm_org(b)
    return bool(na) and (na == nb or (len(na) > 5 and (na in nb or nb in na) and abs(len(na) - len(nb)) <= 12))


def _f(source, entity, category, title, value, url=None, conf=0.85, pivots=(), **data) -> Finding:
    return Finding(category=category, title=title, value=str(value)[:800], url=url, source=source, target=entity,
                   confidence=conf, pivots=list(pivots), data={k: v for k, v in data.items() if v not in (None, "", [])})


class GLEIFSource(Source):
    name = "gleif"
    kinds = ("company",)
    description = "Global LEI register: legal name, registration, addresses, status, parent company"

    async def search(self, entity: Entity, ctx: Context):
        try:
            d = await ctx.get_json("https://api.gleif.org/api/v1/lei-records",
                                   params={"filter[fulltext]": entity.value, "page[size]": 10}, headers=API_HEADERS)
        except (httpx.HTTPError, ValueError):
            return
        for rec in d.get("data", []):
            a = rec["attributes"]
            e = a["entity"]
            name = e["legalName"]["name"]
            if not same_entity(name, entity.value):
                continue
            lei = a["lei"]
            url = f"https://search.gleif.org/#/record/{lei}"
            addr = e.get("legalAddress", {})
            hq = e.get("headquartersAddress", {})
            fmt = lambda x: ", ".join(p for p in [" ".join(x.get("addressLines", [])), x.get("city"), x.get("region"),
                                                  x.get("postalCode"), x.get("country")] if p)
            S = self.name
            yield _f(S, entity, "company", "Legal entity (LEI)", f"{name} - {lei}", url, 0.95, status=e.get("status"),
                     legal_form=(e.get("legalForm") or {}).get("id"), jurisdiction=e.get("jurisdiction"),
                     registered_as=e.get("registeredAs"))
            yield _f(S, entity, "location", "Registered address", fmt(addr), url, 0.9,
                     pivots=[Entity("location", fmt(addr))] if addr.get("city") else [])
            if hq and fmt(hq) != fmt(addr):
                yield _f(S, entity, "location", "Headquarters address", fmt(hq), url, 0.9)
            try:
                p = await ctx.get_json(f"https://api.gleif.org/api/v1/lei-records/{lei}/ultimate-parent", headers=API_HEADERS)
                pn = p["data"]["attributes"]["entity"]["legalName"]["name"]
                if not same_entity(pn, name):
                    yield _f(S, entity, "relationship", "Ultimate parent company", pn,
                             f"https://search.gleif.org/#/record/{p['data']['attributes']['lei']}", 0.9,
                             pivots=[Entity("company", pn)])
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                pass
            break


class OpenCorporatesSource(Source):
    name = "opencorporates"
    kinds = ("company", "name")
    description = "OpenCorporates: 200M+ companies from 140 registries; officers for people (needs opencorporates_api_token)"
    requires = ("opencorporates_api_token",)

    async def search(self, entity: Entity, ctx: Context):
        token = ctx.config.get("opencorporates_api_token")
        api = "https://api.opencorporates.com/v0.4"
        try:
            if entity.kind == "company":
                d = await ctx.get_json(f"{api}/companies/search", params={"q": entity.value, "api_token": token, "per_page": 10})
                for item in d["results"]["companies"]:
                    c = item["company"]
                    if not same_entity(c["name"], entity.value):
                        continue
                    yield _f(self.name, entity, "company", f"Registered company ({c.get('jurisdiction_code', '').upper()})",
                             f"{c['name']} #{c.get('company_number')}", c.get("opencorporates_url"), 0.9,
                             status=c.get("current_status"), incorporated=c.get("incorporation_date"),
                             dissolved=c.get("dissolution_date"), type=c.get("company_type"),
                             address=c.get("registered_address_in_full"))
                    if c.get("registered_address_in_full"):
                        yield _f(self.name, entity, "location", "Registered address", c["registered_address_in_full"],
                                 c.get("opencorporates_url"), 0.85)
            else:
                d = await ctx.get_json(f"{api}/officers/search", params={"q": entity.value, "api_token": token, "per_page": 20})
                for item in d["results"]["officers"]:
                    o = item["officer"]
                    comp = o.get("company") or {}
                    yield _f(self.name, entity, "relationship", f"Officer: {o.get('position') or 'role'}",
                             f"{o.get('name')} at {comp.get('name')}", o.get("opencorporates_url"), 0.6,
                             pivots=[Entity("company", comp["name"])] if comp.get("name") else [],
                             start=o.get("start_date"), end=o.get("end_date"), jurisdiction=comp.get("jurisdiction_code"),
                             note="name match - verify it's the same person")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            ctx.log(f"opencorporates: {exc.__class__.__name__}", "warning")


class CompaniesHouseSource(Source):
    name = "companies-house"
    kinds = ("company", "name")
    description = "UK Companies House: company profiles, officers, and every appointment held by a person (needs key)"
    requires = ("companies_house_api_key",)

    async def search(self, entity: Entity, ctx: Context):
        auth = (ctx.config.get("companies_house_api_key"), "")
        api = "https://api.company-information.service.gov.uk"
        try:
            if entity.kind == "company":
                d = await ctx.get_json(f"{api}/search/companies", params={"q": entity.value, "items_per_page": 10}, auth=auth)
                for c in d.get("items", []):
                    if not same_entity(c.get("title", ""), entity.value):
                        continue
                    num = c.get("company_number")
                    url = f"https://find-and-update.company-information.service.gov.uk/company/{num}"
                    yield _f(self.name, entity, "company", "UK company", f"{c['title']} #{num}", url, 0.92,
                             status=c.get("company_status"), created=c.get("date_of_creation"), address=c.get("address_snippet"))
                    off = await ctx.get_json(f"{api}/company/{num}/officers", params={"items_per_page": 50}, auth=auth)
                    for o in off.get("items", []):
                        if o.get("resigned_on"):
                            continue
                        dob = o.get("date_of_birth") or {}
                        yield _f(self.name, entity, "person", f"Officer ({o.get('officer_role')})", o.get("name"), url, 0.9,
                                 pivots=[Entity("name", _ch_name(o.get("name", "")))], appointed=o.get("appointed_on"),
                                 born=f"{dob.get('month', '?')}/{dob.get('year')}" if dob.get("year") else None,
                                 nationality=o.get("nationality"), occupation=o.get("occupation"),
                                 country=o.get("country_of_residence"))
                    break
            else:
                d = await ctx.get_json(f"{api}/search/officers", params={"q": entity.value, "items_per_page": 15}, auth=auth)
                for o in d.get("items", []):
                    if not _names_match(_ch_name(o.get("title", "")), entity.value):
                        continue
                    link = o.get("links", {}).get("self", "")
                    url = f"https://find-and-update.company-information.service.gov.uk{link}"
                    dob = o.get("date_of_birth") or {}
                    yield _f(self.name, entity, "relationship", "UK company officer",
                             f"{o.get('title')} - {o.get('appointment_count')} appointment(s)", url, 0.6,
                             born=f"{dob.get('month', '?')}/{dob.get('year')}" if dob.get("year") else None,
                             address=o.get("address_snippet"), note="name match - verify it's the same person")
                    appts = await ctx.get_json(f"{api}{link}", auth=auth) if link.endswith("appointments") else {}
                    for a in (appts.get("items") or [])[:15]:
                        comp = (a.get("appointed_to") or {}).get("company_name")
                        yield _f(self.name, entity, "relationship", f"Appointment: {a.get('officer_role')}", comp, url, 0.6,
                                 pivots=[Entity("company", comp)] if comp else [], appointed=a.get("appointed_on"),
                                 resigned=a.get("resigned_on"))
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            ctx.log(f"companies-house: {exc.__class__.__name__}", "warning")


def _ch_name(n: str) -> str:
    """Companies House writes 'SURNAME, First Middle' - turn into 'First Middle Surname'."""
    if "," in n:
        last, _, first = n.partition(",")
        return f"{first.strip()} {last.strip().title()}".strip()
    return n.strip()


def _names_match(a: str, b: str) -> bool:
    ta, tb = set(norm_org(a).split()), set(norm_org(b).split())
    return len(ta & tb) >= min(2, len(tb))


class EDGARSource(Source):
    name = "sec-edgar"
    kinds = ("company", "name")
    description = "SEC EDGAR: US public-company profile & filings; insider (Form 3/4/5) filings that name a person"

    async def search(self, entity: Entity, ctx: Context):
        try:
            if entity.kind == "company":
                tickers = await ctx.once("sec-tickers", lambda: ctx.get_json("https://www.sec.gov/files/company_tickers.json",
                                                                             headers=SEC_HEADERS))
                match = next((t for t in tickers.values() if same_entity(t["title"], entity.value)), None)
                if not match:
                    return
                cik = str(match["cik_str"]).zfill(10)
                d = await ctx.get_json(f"https://data.sec.gov/submissions/CIK{cik}.json", headers=SEC_HEADERS)
                url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
                yield _f(self.name, entity, "company", "SEC registrant", f"{d.get('name')} ({match['ticker']}, CIK {cik})", url,
                         0.95, industry=d.get("sicDescription"), state=d.get("stateOfIncorporation"), phone=d.get("phone"),
                         fiscal_year_end=d.get("fiscalYearEnd"), website=d.get("website"))
                biz = (d.get("addresses") or {}).get("business") or {}
                if biz.get("city"):
                    a = ", ".join(x for x in (biz.get("street1"), biz.get("city"), biz.get("stateOrCountry"), biz.get("zipCode")) if x)
                    yield _f(self.name, entity, "location", "Business address (SEC)", a, url, 0.9)
                for fn in d.get("formerNames", [])[:5]:
                    yield _f(self.name, entity, "company", "Former name", fn.get("name"), url, 0.9, until=fn.get("to"))
                recent = d.get("filings", {}).get("recent", {})
                forms = list(zip(recent.get("form", []), recent.get("filingDate", [])))[:8]
                if forms:
                    yield _f(self.name, entity, "company", "Recent filings", ", ".join(f"{f} ({d_})" for f, d_ in forms), url, 0.9)
            else:
                d = await ctx.get_json("https://efts.sec.gov/LATEST/search-index", headers=SEC_HEADERS,
                                       params={"q": f'"{entity.value}"', "forms": "3,4,5,SC 13D,SC 13G"})
                seen = set()
                for hit in d.get("hits", {}).get("hits", [])[:40]:
                    src = hit.get("_source", {})
                    names = src.get("display_names") or []
                    issuers = [n for n in names if not _names_match(n, entity.value)]
                    for issuer in issuers[:1]:
                        clean = re.sub(r"\s*\(CIK.*$", "", issuer).strip()
                        if clean in seen:
                            continue
                        seen.add(clean)
                        yield _f(self.name, entity, "relationship", f"Insider filing ({src.get('form')})",
                                 f"{entity.value} ↔ {clean}", "https://efts.sec.gov/LATEST/search-index?q=" + entity.value,
                                 0.6, pivots=[Entity("company", re.sub(r"\s*\(.*$", "", clean))],
                                 filed=src.get("file_date"), note="name match - verify it's the same person")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            ctx.log(f"sec-edgar: {exc.__class__.__name__}", "debug")


class LittleSisSource(Source):
    name = "littlesis"
    kinds = ("company", "name")
    description = "LittleSis power-network database (behind Oligrapher): board seats, donations, family, business ties"

    async def search(self, entity: Entity, ctx: Context):
        try:
            d = await ctx.get_json("https://littlesis.org/api/entities/search", params={"q": entity.value}, headers=API_HEADERS)
        except (httpx.HTTPError, ValueError):
            return
        match = next((x for x in d.get("data", []) if same_entity(x["attributes"]["name"], entity.value)
                      or _names_match(x["attributes"]["name"], entity.value)), None)
        if not match:
            return
        a = match["attributes"]
        url = f"https://littlesis.org/entities/{match['id']}"
        yield _f(self.name, entity, "relationship", "LittleSis profile", f"{a['name']} - {a.get('blurb') or ''}".strip(" -"),
                 url, 0.85, types=a.get("types"), website=a.get("website"))
        try:
            rel = await ctx.get_json(f"https://littlesis.org/api/entities/{match['id']}/connections", headers=API_HEADERS)
        except (httpx.HTTPError, ValueError):
            return
        cats = {1: "Position", 2: "Education", 3: "Membership", 4: "Family", 5: "Donation", 6: "Transaction",
                7: "Lobbying", 8: "Social", 9: "Professional", 10: "Ownership", 11: "Hierarchy", 12: "Generic"}
        for c in rel.get("data", [])[:40]:
            ca = c["attributes"]
            kind = "company" if ca.get("primary_ext") == "Org" else "name"
            yield _f(self.name, entity, "relationship", f"Network: {cats.get(ca.get('connected_category_id'), 'Connection')}",
                     ca.get("name"), f"https://littlesis.org/entities/{ca.get('id')}", 0.55,
                     pivots=[Entity(kind, ca["name"])] if ca.get("name") else [], blurb=(ca.get("blurb") or "").strip()[:200])


class OpenSanctionsSource(Source):
    name = "opensanctions"
    kinds = ("company", "name")
    description = "Sanctions lists, politically exposed persons and criminal watchlists (needs opensanctions_api_key)"
    requires = ("opensanctions_api_key",)

    async def search(self, entity: Entity, ctx: Context):
        try:
            d = await ctx.get_json("https://api.opensanctions.org/search/default", params={"q": entity.value, "limit": 10},
                                   headers={**API_HEADERS, "Authorization": f"ApiKey {ctx.config.get('opensanctions_api_key')}"})
        except (httpx.HTTPError, ValueError) as exc:
            ctx.log(f"opensanctions: {exc.__class__.__name__}", "warning")
            return
        for r in d.get("results", []):
            if not (_names_match(r.get("caption", ""), entity.value) or same_entity(r.get("caption", ""), entity.value)):
                continue
            topics = r.get("properties", {}).get("topics", [])
            sev = "high" if any(t.startswith(("sanction", "crime")) for t in topics) else "medium" if "role.pep" in topics else "low"
            yield _f(self.name, entity, "threat", f"Watchlist match ({', '.join(topics) or 'listed'})", r.get("caption"),
                     f"https://www.opensanctions.org/entities/{r.get('id')}/", 0.75, severity=sev,
                     datasets=r.get("datasets"), countries=r.get("properties", {}).get("country"),
                     note="name match - confirm birth date / nationality before acting")
