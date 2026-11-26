"""Public registries and records (mostly US, plus global leak databases).

Name searches return name *matches* - common names collide - so every result is scored low unless it
lines up with something already known (a city/state the subject is linked to raises it).

  * Sex-offender registries: NSOPW (all US states/territories/tribes) where it answers automated requests,
    otherwise pre-filled links to NSOPW and the state registries.
  * Federal Bureau of Prisons inmate locator.
  * NPI registry (licensed US healthcare providers, with practice addresses).
  * FINRA BrokerCheck / SEC IAPD (registered brokers and investment advisers, employment history).
  * CourtListener (US court opinions and dockets naming the person; needs a free token).
  * ICIJ Offshore Leaks (Panama/Paradise/Pandora Papers officers and entities).
  * USAspending (federal contract and grant recipients, for companies).
  * US people-search sites (pre-filled lookups: addresses, relatives, phone numbers).
"""
from __future__ import annotations

import asyncio
from urllib.parse import quote, quote_plus

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, USER_AGENT, Context, Source

US_STATES = {"AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California", "CO": "Colorado",
             "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
             "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
             "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota",
             "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
             "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York", "NC": "North Carolina",
             "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania",
             "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas",
             "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington", "WV": "West Virginia",
             "WI": "Wisconsin", "WY": "Wyoming", "DC": "District of Columbia"}
STATE_REGISTRIES = {
    "CA": "https://www.meganslaw.ca.gov/", "TX": "https://publicsite.dps.texas.gov/SexOffenderRegistry",
    "FL": "https://offender.fdle.state.fl.us/offender/sops/search.jsf", "NY": "https://www.criminaljustice.ny.gov/SomsSUBDirectory/search_index.jsp",
    "PA": "https://www.pameganslaw.state.pa.us/", "IL": "https://isp.illinois.gov/Sor", "OH": "https://www.icrimewatch.net/index.php?AgencyID=55149",
    "GA": "https://state.sor.gbi.ga.gov/sort_public/", "NC": "https://sexoffender.ncsbi.gov/", "MI": "https://mspsor.com/",
    "WA": "https://www.icrimewatch.net/index.php?AgencyID=54528", "AZ": "https://www.azdps.gov/services/public/offender",
    "OR": "https://sexoffenders.oregon.gov/", "CO": "https://www.colorado.gov/apps/cdps/sor/",
}


def _not_us(ctx: Context) -> bool:
    """US registries only make sense when the subject could be in the US."""
    cc = (ctx.knowledge.country_code() if ctx.knowledge else None) or ctx.shared.get("likely-country")
    if cc and cc != "US":
        ctx.log(f"us-records: subject appears to be in {cc}, skipping US-only registries", "debug")
        return True
    return False


def _split(name: str) -> tuple[str, str]:
    parts = name.split()
    return (parts[0], parts[-1]) if len(parts) >= 2 else (name, "")


def _f(source, entity, category, title, value, url, conf, **data) -> Finding:
    return Finding(category=category, title=title, value=str(value)[:600], url=url, source=source, target=entity,
                   confidence=conf, data={k: v for k, v in data.items() if v not in (None, "", [])})


def _place_boost(ctx: Context, *places) -> float:
    """A record in a city/state the subject is already tied to is much more likely to be them."""
    if not ctx.knowledge:
        return 0.0
    known = " ".join(ctx.knowledge.trusted_values("location")).lower()
    return 0.25 if any(p and str(p).lower() in known for p in places) else 0.0


class SexOffenderRegistrySource(Source):
    name = "sex-offender-registries"
    kinds = ("name",)
    description = "US National Sex Offender Public Website (all states) + state registries; name matches with locations"

    async def search(self, entity: Entity, ctx: Context):
        if _not_us(ctx):
            return
        first, last = _split(entity.value)
        if not last:
            return
        got = False
        try:
            r = await ctx.post("https://nsopw-api.ojp.gov/nsopw/v1/v1.0/search", headers={
                "User-Agent": USER_AGENT, "Origin": "https://www.nsopw.gov", "Referer": "https://www.nsopw.gov/",
                "Content-Type": "application/json"}, json={"firstName": first, "lastName": last, "city": None,
                                                           "county": None, "zips": None, "jurisdictions": []}, timeout=30)
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                for o in (r.json().get("offenders") or [])[:25]:
                    loc = ", ".join(x for x in (o.get("city"), o.get("state")) if x)
                    got = True
                    yield _f(self.name, entity, "threat", "Sex-offender registry (name match)",
                             f"{o.get('firstName')} {o.get('lastName')} - {loc}", o.get("offenderUri"),
                             min(0.85, 0.45 + _place_boost(ctx, o.get("city"), o.get("state"))), severity="high",
                             address=o.get("address"), dob=o.get("dob"), age=o.get("age"),
                             jurisdiction=o.get("jurisdictionId"), note="name match - compare age, photo and address")
        except (httpx.HTTPError, ValueError):
            pass
        if not got:
            ctx.log("sex-offender-registries: NSOPW blocks automated searches right now - added pre-filled links", "debug")
            yield _f(self.name, entity, "lead", "Sex-offender registry: NSOPW (all US states)",
                     "https://www.nsopw.gov/search-public-sex-offender-registries",
                     "https://www.nsopw.gov/search-public-sex-offender-registries", 0.5,
                     note=f"search first name '{first}', last name '{last}'")
            for st, url in STATE_REGISTRIES.items():
                yield _f(self.name, entity, "lead", f"Sex-offender registry: {US_STATES[st]}", url, url, 0.4)


class USRecordsSource(Source):
    name = "us-records"
    kinds = ("name",)
    description = ("US federal records: Bureau of Prisons inmates, NPI healthcare providers (addresses), FINRA/SEC "
                   "brokers & advisers, CourtListener court records (token), people-search lookups")

    async def search(self, entity: Entity, ctx: Context):
        if _not_us(ctx):
            return
        first, last = _split(entity.value)
        if not last:
            return
        jobs = [self._bop(first, last, entity, ctx), self._npi(first, last, entity, ctx),
                self._finra(entity, ctx), self._courtlistener(entity, ctx)]
        for fut in asyncio.as_completed(jobs):
            try:
                for f in await fut:
                    yield f
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                continue
        for label, url in (("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?name={quote_plus(entity.value)}"),
                           ("FastPeopleSearch", f"https://www.fastpeoplesearch.com/name/{quote(first.lower())}-{quote(last.lower())}"),
                           ("Whitepages", f"https://www.whitepages.com/name/{quote(first)}-{quote(last)}"),
                           ("ThatsThem", f"https://thatsthem.com/name/{quote(first)}-{quote(last)}"),
                           ("Spokeo", f"https://www.spokeo.com/{quote(first)}-{quote(last)}")):
            yield _f(self.name, entity, "lead", f"US people search: {label}", url, url, 0.45,
                     note="addresses, relatives, phone numbers - US records only")

    async def _bop(self, first, last, e, ctx):
        d = await ctx.get_json("https://www.bop.gov/PublicInfo/execute/inmateloc", headers=API_HEADERS,
                               params={"todo": "query", "output": "json", "nameFirst": first, "nameLast": last})
        out = []
        for i in (d.get("InmateLocator") or [])[:15]:
            out.append(_f(self.name, e, "threat", "Federal inmate record (name match)",
                          f"{i.get('nameFirst')} {i.get('nameMiddle', '')} {i.get('nameLast')} - age {i.get('age')}, "
                          f"{i.get('race', '')} {i.get('sex', '')}".replace("  ", " "),
                          "https://www.bop.gov/inmateloc/", 0.4, severity="medium", register=i.get("inmateNum"),
                          release=i.get("actRelDate") or i.get("projRelDate"), facility=i.get("faclName"),
                          note="name match - compare age"))
        return out

    async def _npi(self, first, last, e, ctx):
        d = await ctx.get_json("https://npiregistry.cms.hhs.gov/api/", headers=API_HEADERS,
                               params={"version": "2.1", "first_name": first, "last_name": last, "limit": 10})
        out = []
        for r in d.get("results", []):
            b = r.get("basic", {})
            addr = next((a for a in r.get("addresses", []) if a.get("address_purpose") == "LOCATION"), None) or \
                (r.get("addresses") or [{}])[0]
            line = ", ".join(x for x in (addr.get("address_1"), addr.get("city"), addr.get("state"), addr.get("postal_code", "")[:5]) if x)
            spec = ", ".join(t.get("desc", "") for t in r.get("taxonomies", [])[:2])
            conf = min(0.85, 0.45 + _place_boost(ctx, addr.get("city"), addr.get("state")))
            out.append(_f(self.name, e, "record", "Licensed healthcare provider (NPI)",
                          f"{b.get('first_name', '')} {b.get('last_name', '')} {b.get('credential', '')} - {spec}",
                          f"https://npiregistry.cms.hhs.gov/provider-view/{r.get('number')}", conf, npi=r.get("number")))
            if line:
                out.append(_f(self.name, e, "address", "Practice address (NPI)", line,
                              f"https://www.google.com/maps/search/{quote_plus(line)}", conf, phone=addr.get("telephone_number")))
        return out

    async def _finra(self, e, ctx):
        out = []
        for label, url, page in (("FINRA BrokerCheck", "https://api.brokercheck.finra.org/search/individual",
                                  "https://brokercheck.finra.org/individual/summary/{id}"),
                                 ("SEC investment adviser", "https://api.adviserinfo.sec.gov/search/individual",
                                  "https://adviserinfo.sec.gov/individual/summary/{id}")):
            d = await ctx.get_json(url, headers=API_HEADERS, params={"query": e.value, "nrows": 8, "start": 0, "r": 25, "wt": "json"})
            for h in d.get("hits", {}).get("hits", []):
                s = h.get("_source", {})
                full = " ".join(x for x in (s.get("ind_firstname"), s.get("ind_middlename"), s.get("ind_lastname")) if x)
                if e.value.split()[-1].lower() not in full.lower():
                    continue
                emp = s.get("ind_current_employments") or []
                firm = emp[0].get("firm_name") if emp else ""
                where = f"{emp[0].get('branch_city', '')}, {emp[0].get('branch_state', '')}" if emp else ""
                out.append(_f(self.name, e, "record", f"{label} (name match)", f"{full} - {firm} {where}".strip(" -"),
                              page.replace("{id}", str(s.get("ind_source_id"))),
                              min(0.85, 0.45 + _place_boost(ctx, *(where.split(", ") if where else ()))),
                              scope=s.get("ind_bc_scope"), crd=s.get("ind_source_id")))
            if out:
                break
        return out

    async def _courtlistener(self, e, ctx):
        tok = ctx.config.get("courtlistener_token")
        if not tok:
            return []
        d = await ctx.get_json("https://www.courtlistener.com/api/rest/v4/search/",
                               headers={**API_HEADERS, "Authorization": f"Token {tok}"},
                               params={"q": f'"{e.value}"', "type": "r"})
        return [_f(self.name, e, "record", "US court record (CourtListener)",
                   f"{x.get('caseName')} - {x.get('court')} ({(x.get('dateFiled') or '')[:10]})",
                   "https://www.courtlistener.com" + (x.get("absolute_url") or ""), 0.5, docket=x.get("docketNumber"),
                   note="name appears in the case - confirm it's the same person")
                for x in d.get("results", [])[:15]]


class OffshoreLeaksSource(Source):
    name = "offshore-leaks"
    kinds = ("name", "company")
    description = "ICIJ Offshore Leaks: officers and entities from the Panama, Paradise and Pandora Papers"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.post("https://offshoreleaks.icij.org/api/v1/reconcile", headers=API_HEADERS,
                               json={"queries": {"q0": {"query": entity.value}}})
            results = r.json().get("q0", {}).get("result", [])
        except (httpx.HTTPError, ValueError):
            return
        for x in results[:10]:
            if not x.get("match") and float(x.get("score") or 0) < 80:
                continue
            yield _f(self.name, entity, "record", "Offshore leaks (ICIJ)", f"{x.get('name')} - {x.get('description', '')}",
                     f"https://offshoreleaks.icij.org/nodes/{x.get('id')}", 0.6 if x.get("match") else 0.45,
                     note="name match in leaked offshore records")


class USASpendingSource(Source):
    name = "usaspending"
    kinds = ("company",)
    description = "USAspending.gov: US federal contract and grant recipients"

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.post("https://api.usaspending.gov/api/v2/autocomplete/recipient/", headers=API_HEADERS,
                               json={"search_text": entity.value, "limit": 10})
            results = r.json().get("results", [])
        except (httpx.HTTPError, ValueError):
            return
        from panoptes.sources.company import same_entity
        for x in results:
            if same_entity(x.get("recipient_name", ""), entity.value):
                yield _f(self.name, entity, "company", "US federal funding recipient", x.get("recipient_name"),
                         f"https://www.usaspending.gov/search/?hash=&recipient={quote_plus(x.get('recipient_name', ''))}",
                         0.8, uei=x.get("uei"))
