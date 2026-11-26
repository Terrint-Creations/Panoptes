"""GEOINT (GEOINT toolkits / Geo-Sleuth / SunCalc capabilities).

For a place name or coordinates (typed in, from photo GPS, or from profiles):
  geocoding & reverse geocoding (OpenStreetMap Nominatim), nearby named landmarks (Overpass),
  local time zone & elevation, sun position / sunrise / sunset / shadow length (SunCalc maths),
  and for photos with a capture time: the sun position and the historical weather at that moment -
  a quick way to check whether a photo's claimed time and place are physically consistent.
Plus links to satellite, street-level and historical imagery. WiGLE geolocates Wi-Fi networks.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import math
import re

import httpx

from panoptes.detect import COORD_RE
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source

# ----------------------------------------------------------------------------- SunCalc (port of suncalc.js)
RAD = math.pi / 180
J1970, J2000 = 2440588, 2451545
OBLIQUITY = RAD * 23.4397


def _to_days(when: dt.datetime) -> float:
    return when.timestamp() / 86400 - 0.5 + J1970 - J2000


def _sun_coords(d: float):
    m = RAD * (357.5291 + 0.98560028 * d)
    c = RAD * (1.9148 * math.sin(m) + 0.02 * math.sin(2 * m) + 0.0003 * math.sin(3 * m))
    lon = m + c + RAD * 102.9372 + math.pi
    dec = math.asin(math.sin(lon) * math.sin(OBLIQUITY))
    ra = math.atan2(math.sin(lon) * math.cos(OBLIQUITY), math.cos(lon))
    return m, lon, dec, ra


def sun_position(when: dt.datetime, lat: float, lon: float) -> tuple[float, float]:
    """(compass azimuth°, elevation°) of the sun at an aware datetime."""
    lw, phi, d = RAD * -lon, RAD * lat, _to_days(when)
    _, _, dec, ra = _sun_coords(d)
    h = RAD * (280.16 + 360.9856235 * d) - lw - ra
    az = math.atan2(math.sin(h), math.cos(h) * math.sin(phi) - math.tan(dec) * math.cos(phi))
    alt = math.asin(math.sin(phi) * math.sin(dec) + math.cos(phi) * math.cos(dec) * math.cos(h))
    return (math.degrees(az) + 180) % 360, math.degrees(alt)


def sun_times(date: dt.date, lat: float, lon: float) -> tuple[dt.datetime | None, dt.datetime, dt.datetime | None]:
    """(sunrise, solar noon, sunset) in UTC; sunrise/sunset None during polar day/night."""
    lw, phi = RAD * -lon, RAD * lat
    d = _to_days(dt.datetime(date.year, date.month, date.day, 12, tzinfo=dt.timezone.utc))
    n = round(d - 0.0009 - lw / (2 * math.pi))
    ds = 0.0009 + lw / (2 * math.pi) + n
    m, l, dec, _ = _sun_coords(ds)
    noon = J2000 + ds + 0.0053 * math.sin(m) - 0.0069 * math.sin(2 * l)
    from_j = lambda j: dt.datetime.fromtimestamp((j + 0.5 - J1970) * 86400, dt.timezone.utc)
    cos_w = (math.sin(-0.833 * RAD) - math.sin(phi) * math.sin(dec)) / (math.cos(phi) * math.cos(dec))
    if abs(cos_w) > 1:
        return None, from_j(noon), None
    w = math.acos(cos_w)
    a = 0.0009 + (w + lw) / (2 * math.pi) + n
    j_set = J2000 + a + 0.0053 * math.sin(m) - 0.0069 * math.sin(2 * l)
    return from_j(noon - (j_set - noon)), from_j(noon), from_j(j_set)


def compass(deg: float) -> str:
    return ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"][
        int((deg + 11.25) // 22.5) % 16]


def map_links(lat: float, lon: float) -> dict[str, str]:
    return {
        "OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
        "Google Maps": f"https://www.google.com/maps?q={lat},{lon}",
        "Street View": f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}",
        "Google Earth (3D)": f"https://earth.google.com/web/@{lat},{lon},300a,800d,35y,0h,45t,0r",
        "Bing aerial": f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=18&style=a",
        "Mapillary street photos": f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17",
        "Sentinel satellite history": f"https://apps.sentinel-hub.com/eo-browser/?zoom=15&lat={lat}&lng={lon}",
        "Wikimapia": f"https://wikimapia.org/#lat={lat}&lon={lon}&z=17",
        "SunCalc": f"https://www.suncalc.org/#/{lat},{lon},17/",
    }


# ----------------------------------------------------------------------------- data lookups

async def nominatim(ctx: Context, path: str, params: dict):
    """Nominatim allows ~1 request/second; serialise and space our calls."""
    async with ctx.lock("nominatim"):
        try:
            r = await ctx.get(f"https://nominatim.openstreetmap.org/{path}", params={**params, "format": "jsonv2"},
                              headers={**API_HEADERS, "Accept-Language": "en"})
            return r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None
        finally:
            await asyncio.sleep(1.1)


async def overpass_pois(ctx: Context, lat: float, lon: float, radius: int = 250) -> list[dict]:
    q = (f'[out:json][timeout:20];(node(around:{radius},{lat},{lon})[name]'
         f'[~"^(amenity|shop|tourism|leisure|historic|office|railway|public_transport)$"~"."];);out 30;')
    for host in ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"):
        try:
            r = await ctx.post(host, data={"data": q}, headers=API_HEADERS, timeout=30, deadline=40)
            if r.status_code == 200:
                return r.json().get("elements", [])
        except (httpx.HTTPError, ValueError):
            continue
    return []


async def geo_findings(ctx: Context, entity: Entity, source: str, lat: float, lon: float,
                       capture: dt.datetime | None = None, label: str = "") -> list[Finding]:
    """Everything we can say about a point. Shared by the location source and photo GPS analysis."""
    p = f"{label}: " if label else ""
    out: list[Finding] = []

    def add(cat, title, value, url=None, conf=0.9, **data):
        out.append(Finding(category=cat, title=p + title, value=str(value), url=url, source=source, target=entity,
                           confidence=conf, data={k: v for k, v in data.items() if v is not None}))

    rev, meteo, pois = await asyncio.gather(
        nominatim(ctx, "reverse", {"lat": lat, "lon": lon, "zoom": 18, "addressdetails": 1}),
        _meteo(ctx, lat, lon), overpass_pois(ctx, lat, lon))
    if rev and rev.get("display_name"):
        a = rev.get("address", {})
        add("geo", "Address", rev["display_name"], f"https://www.openstreetmap.org/{rev.get('osm_type', 'node')}/{rev.get('osm_id', '')}",
            0.85, country=a.get("country"), country_code=(a.get("country_code") or "").upper(),
            city=a.get("city") or a.get("town") or a.get("village"))
    tz = None
    if meteo:
        tz = dt.timezone(dt.timedelta(seconds=meteo.get("utc_offset_seconds", 0)))
        add("geo", "Time zone", f"{meteo.get('timezone')} (UTC{meteo.get('utc_offset_seconds', 0) / 3600:+g})", conf=0.95)
        if meteo.get("elevation") is not None:
            add("geo", "Elevation", f"{meteo['elevation']:.0f} m", conf=0.85)
    for poi in pois[:15]:
        tags = poi.get("tags", {})
        kind = next((tags[k] for k in ("amenity", "shop", "tourism", "leisure", "historic", "office", "railway",
                                       "public_transport") if k in tags), "place")
        dist = _distance(lat, lon, poi.get("lat", lat), poi.get("lon", lon))
        add("geo", "Nearby landmark", f"{tags.get('name')} ({kind}, {dist:.0f} m)",
            f"https://www.openstreetmap.org/node/{poi.get('id')}", 0.7)

    today = dt.datetime.now(dt.timezone.utc).date()
    rise, noon, set_ = sun_times(today, lat, lon)
    fmt = lambda t: t.astimezone(tz).strftime("%H:%M") if t and tz else (t.strftime("%H:%M UTC") if t else "none")
    add("sun", "Sun today", f"sunrise {fmt(rise)}, solar noon {fmt(noon)}, sunset {fmt(set_)}", conf=0.95)

    if capture:
        when = capture if capture.tzinfo else capture.replace(tzinfo=tz or dt.timezone.utc)
        az, el = sun_position(when, lat, lon)
        shadow = f", shadows {1 / math.tan(math.radians(el)):.1f}x object height pointing {compass((az + 180) % 360)}" if el > 1 else ""
        add("sun", "Sun at capture time", f"{when.isoformat()}: sun {el:.1f}° high in the {compass(az)} ({az:.0f}°)"
            + (" - below the horizon (night)" if el < 0 else shadow), f"https://www.suncalc.org/#/{lat},{lon},17/"
            f"{when.strftime('%Y.%m.%d/%H:%M')}/1/3", 0.9, azimuth=round(az, 1), elevation=round(el, 1),
            assumed_timezone=None if capture.tzinfo else str(tz or "UTC"))
        weather = await _weather_at(ctx, lat, lon, when)
        if weather:
            add("weather", "Weather at capture time", weather, conf=0.8,
                note="Historical reanalysis (Open-Meteo) - compare with what the photo shows")
    for name, link in map_links(lat, lon).items():
        add("lead", f"Imagery: {name}", link, link, 0.5)
    return out


def _distance(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 12_742_000 * math.asin(math.sqrt(a))


async def _meteo(ctx: Context, lat, lon):
    try:
        return await ctx.get_json("https://api.open-meteo.com/v1/forecast",
                                  params={"latitude": lat, "longitude": lon, "timezone": "auto", "current": "temperature_2m"},
                                  headers=API_HEADERS)
    except (httpx.HTTPError, ValueError):
        return None


WMO = {0: "clear sky", 1: "mainly clear", 2: "partly cloudy", 3: "overcast", 45: "fog", 48: "rime fog",
       51: "light drizzle", 53: "drizzle", 55: "dense drizzle", 61: "light rain", 63: "rain", 65: "heavy rain",
       71: "light snow", 73: "snow", 75: "heavy snow", 77: "snow grains", 80: "rain showers", 81: "rain showers",
       82: "violent rain showers", 85: "snow showers", 86: "heavy snow showers", 95: "thunderstorm",
       96: "thunderstorm with hail", 99: "thunderstorm with heavy hail"}


async def _weather_at(ctx: Context, lat, lon, when: dt.datetime) -> str | None:
    utc = when.astimezone(dt.timezone.utc)
    if utc > dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5):
        return None  # archive lags a few days
    day = utc.date().isoformat()
    try:
        d = await ctx.get_json("https://archive-api.open-meteo.com/v1/archive", headers=API_HEADERS, params={
            "latitude": lat, "longitude": lon, "start_date": day, "end_date": day, "timezone": "UTC",
            "hourly": "temperature_2m,cloud_cover,precipitation,weather_code,snow_depth"})
        h = d["hourly"]
        i = utc.hour
        code = h["weather_code"][i]
        return (f"{WMO.get(code, f'code {code}')}, {h['temperature_2m'][i]}°C, cloud cover {h['cloud_cover'][i]}%, "
                f"precipitation {h['precipitation'][i]} mm" + (f", snow depth {h['snow_depth'][i]} m" if h['snow_depth'][i] else ""))
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
        return None


# ----------------------------------------------------------------------------- sources

def parse_capture(meta: dict) -> dt.datetime | None:
    """EXIF DateTimeOriginal (+ OffsetTimeOriginal if present)."""
    raw = meta.get("DateTimeOriginal") or meta.get("DateTime")
    if not raw:
        return None
    try:
        t = dt.datetime.strptime(raw.strip()[:19], "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    off = meta.get("OffsetTimeOriginal") or meta.get("OffsetTime")
    if off and re.fullmatch(r"[+-]\d{2}:\d{2}", off.strip()):
        sign = 1 if off.strip()[0] == "+" else -1
        hh, mm = off.strip()[1:].split(":")
        t = t.replace(tzinfo=dt.timezone(sign * dt.timedelta(hours=int(hh), minutes=int(mm))))
    return t


class LocationSource(Source):
    name = "geoint"
    kinds = ("location",)
    description = ("Geocoding, address, nearby landmarks, time zone, elevation, sun position/shadows, "
                   "historical weather and satellite/street-level imagery links for a place or coordinates")

    async def search(self, entity: Entity, ctx: Context):
        m = COORD_RE.match(entity.value)
        if m:
            lat, lon = float(m.group(1)), float(m.group(2))
        else:
            res = await nominatim(ctx, "search", {"q": entity.value, "limit": 1, "addressdetails": 1})
            if not res:
                ctx.log(f"geoint: couldn't geocode '{entity.value}'", "warning")
                return
            top = res[0]
            lat, lon = round(float(top["lat"]), 6), round(float(top["lon"]), 6)
            conf = 0.85 if float(top.get("importance") or 0) > 0.4 else 0.65
            yield Finding(category="geo", title="Geocoded to", value=f"{lat}, {lon} - {top.get('display_name')}",
                          url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=13/{lat}/{lon}", source=self.name,
                          target=entity, confidence=conf, data={"type": top.get("type"), "class": top.get("category")})
        capture = (ctx.shared.get("capture_times") or {}).get(entity.value)
        for f in await geo_findings(ctx, entity, self.name, lat, lon, capture):
            yield f


class WigleSource(Source):
    name = "wigle"
    kinds = ("bssid",)
    description = "Geolocates a Wi-Fi access point (BSSID) from WiGLE's wardriving database"
    requires = ("wigle_api_name", "wigle_api_token")

    async def search(self, entity: Entity, ctx: Context):
        try:
            r = await ctx.get("https://api.wigle.net/api/v2/network/search", params={"netid": entity.value},
                              auth=(ctx.config.get("wigle_api_name"), ctx.config.get("wigle_api_token")), headers=API_HEADERS)
            results = r.json().get("results", []) if r.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            return
        for n in results[:3]:
            lat, lon = n.get("trilat"), n.get("trilong")
            if lat is None:
                continue
            loc = f"{lat:.6f}, {lon:.6f}"
            yield Finding(category="location", title=f"Wi-Fi '{n.get('ssid') or '?'}' seen at", value=loc,
                          url=f"https://wigle.net/search?netid={entity.value}", source=self.name, target=entity,
                          confidence=0.85, pivots=[Entity("location", loc)],
                          data={"first_seen": n.get("firsttime"), "last_seen": n.get("lasttime"), "city": n.get("city"),
                                "country": n.get("country"), "encryption": n.get("encryption")})
