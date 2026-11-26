"""Deep image analysis - for images without useful metadata (screenshots, re-shared photos).

  * OCR (RapidOCR, local): reads all text in the image. Coordinates (decimal or degrees/minutes/seconds -
    e.g. the Google Earth status bar), street addresses, URLs, emails, @handles and phone numbers become
    findings and leads; coordinates and addresses go straight into GEOINT analysis.
  * AI vision (Claude, optional anthropic_api_key): describes the scene and estimates where it was taken
    from visual clues (architecture, vegetation, road markings, signs, terrain, sun), GeoSpy-style. The
    estimate is geocoded and analysed like any other location, clearly labelled as an AI estimate.
  * ExifTool: downloaded automatically on Windows the first time it's needed, for the full tag set.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import re
import zipfile
from pathlib import Path

import httpx

from panoptes.config import CACHE_DIR
from panoptes.models import Entity, Finding
from panoptes.sources.base import API_HEADERS, Context, Source, extract_emails

IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic")
TOOLS = CACHE_DIR / "tools"

DMS = re.compile(r"(\d{1,3})\D{1,3}(\d{1,2})\D{1,3}(\d{1,2}(?:[.,]\d+)?)\D{0,3}([NSns])[\s,;]*"
                 r"(\d{1,3})\D{1,3}(\d{1,2})\D{1,3}(\d{1,2}(?:[.,]\d+)?)\D{0,3}([EWew])")
DECIMAL = re.compile(r"(-?\d{1,2}\.\d{3,8})\s*[°º]?\s*([NS])?\s*[,;\s]\s*(-?\d{1,3}\.\d{3,8})\s*[°º]?\s*([EW])?", re.I)
ADDRESS = re.compile(r"\b([A-ZÀ-ÞÁÉÍÓÚÝÞÆÖ][\wÀ-ÿ'\-]{2,}(?:\s[\wÀ-ÿ'\-]+){0,3}\s\d{1,4}[a-zA-Z]?)\b")
HANDLE = re.compile(r"(?<![\w@])@([A-Za-z0-9_.]{3,30})")
PHONE = re.compile(r"\+\d[\d\s\-()]{7,16}\d")


# ----------------------------------------------------------------------------- ExifTool

async def ensure_exiftool(ctx: Context) -> str | None:
    import shutil
    import sys
    found = shutil.which("exiftool")
    if found:
        return found
    exe = TOOLS / "exiftool" / "exiftool.exe"
    if exe.exists():
        return str(exe)
    if sys.platform != "win32":
        return None

    async def install():
        try:
            page = (await ctx.get("https://exiftool.org/", headers=API_HEADERS, timeout=20)).text
            ver = re.search(r"exiftool-(\d+\.\d+)_64\.zip", page).group(1)
            url = f"https://downloads.sourceforge.net/project/exiftool/exiftool-{ver}_64.zip"
            ctx.log(f"file-metadata: downloading ExifTool {ver} (one-time, ~11 MB)")
            r = await ctx.get(url, timeout=120, deadline=240, headers={"User-Agent": "Wget/1.21.4"})
            r.raise_for_status()
            z = zipfile.ZipFile(io.BytesIO(r.content))
        except (httpx.HTTPError, AttributeError, zipfile.BadZipFile) as exc:
            ctx.log(f"file-metadata: couldn't install ExifTool ({exc.__class__.__name__})", "warning")
            return None
        dest = TOOLS / "exiftool"
        dest.mkdir(parents=True, exist_ok=True)
        root = z.namelist()[0].split("/")[0]
        for member in z.namelist():
            rel = member[len(root) + 1:] if member.startswith(root + "/") else member
            if not rel or member.endswith("/"):
                continue
            target = dest / rel.replace("exiftool(-k).exe", "exiftool.exe")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(member))
        return str(exe) if exe.exists() else None
    return await ctx.once("exiftool-install", install)


# ----------------------------------------------------------------------------- shared helpers

async def load_target(entity: Entity, ctx: Context) -> tuple[bytes | None, str]:
    loc = entity.value
    if loc.lower().startswith(("http://", "https://")):
        try:
            r = await ctx.get(loc, timeout=40)
            r.raise_for_status()
            return r.content, loc
        except httpx.HTTPError:
            return None, loc
    try:
        return await asyncio.to_thread(Path(loc).read_bytes), loc
    except OSError:
        return None, loc


def is_image(entity: Entity, data: bytes | None) -> bool:
    if entity.value.lower().split("?")[0].endswith(IMAGE_EXTS):
        return True
    return bool(data) and (data[:3] == b"\xff\xd8\xff" or data[:4] == b"\x89PNG" or data[:4] == b"RIFF")


def parse_coordinates(text: str) -> list[tuple[float, float]]:
    out = []
    for m in DMS.finditer(text):
        try:
            lat = int(m.group(1)) + int(m.group(2)) / 60 + float(m.group(3).replace(",", ".")) / 3600
            lon = int(m.group(5)) + int(m.group(6)) / 60 + float(m.group(7).replace(",", ".")) / 3600
        except ValueError:
            continue
        lat = -lat if m.group(4).upper() == "S" else lat
        lon = -lon if m.group(8).upper() == "W" else lon
        if abs(lat) <= 90 and abs(lon) <= 180:
            out.append((round(lat, 6), round(lon, 6)))
    for m in DECIMAL.finditer(text):
        lat, lon = float(m.group(1)), float(m.group(3))
        if m.group(2) and m.group(2).upper() == "S":
            lat = -abs(lat)
        if m.group(4) and m.group(4).upper() == "W":
            lon = -abs(lon)
        if abs(lat) <= 90 and abs(lon) <= 180 and (lat, lon) not in out:
            out.append((round(lat, 6), round(lon, 6)))
    return out


# ----------------------------------------------------------------------------- OCR

_ocr_engine = None


def run_ocr(data: bytes) -> list[tuple[str, float]]:
    global _ocr_engine
    from rapidocr_onnxruntime import RapidOCR
    if _ocr_engine is None:
        _ocr_engine = RapidOCR()
    result, _ = _ocr_engine(data)
    return [(r[1], float(r[2])) for r in (result or [])]


class ImageTextSource(Source):
    name = "image-text"
    kinds = ("file",)
    option = "ocr"
    description = "OCR: reads text in images - coordinates (e.g. Google Earth), addresses, signs, usernames, emails, phones"

    def available(self, config):
        try:
            import rapidocr_onnxruntime  # noqa: F401
        except ImportError:
            return False, "pip install rapidocr-onnxruntime"
        return True, ""

    async def search(self, entity: Entity, ctx: Context):
        data, loc = await load_target(entity, ctx)
        if not data or not is_image(entity, data):
            return
        ctx.progress(self.name, entity, 0, 1)
        try:
            lines = await asyncio.to_thread(run_ocr, data)
        except Exception as exc:
            ctx.log(f"image-text: OCR failed ({exc.__class__.__name__})", "warning")
            return
        ctx.progress(self.name, entity, 1, 1)
        lines = [(t.strip(), c) for t, c in lines if t.strip() and c >= 0.5]
        if not lines:
            yield Finding(category="text", title="Text in image", value="no readable text", source=self.name,
                          target=entity, confidence=0.8)
            return
        full = "\n".join(t for t, _ in lines)
        yield Finding(category="text", title="Text in image (OCR)", value=full[:1500], source=self.name, target=entity,
                      confidence=0.85, data={"lines": len(lines)})
        from panoptes.sources.geo import geo_findings, nominatim
        coords = parse_coordinates(full)
        for lat, lon in coords[:3]:
            yield Finding(category="location", title="Coordinates written in image", value=f"{lat}, {lon}",
                          url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}", source=self.name,
                          target=entity, confidence=0.9, pivots=[Entity("location", f"{lat}, {lon}")])
            for f in await geo_findings(ctx, entity, self.name, lat, lon, label="Location from image text"):
                yield f
        if not coords:
            for addr in list(dict.fromkeys(ADDRESS.findall(full)))[:3]:
                res = await nominatim(ctx, "search", {"q": addr, "limit": 1, "addressdetails": 1})
                if res:
                    lat, lon = round(float(res[0]["lat"]), 6), round(float(res[0]["lon"]), 6)
                    yield Finding(category="location", title="Address in image (geocoded)",
                                  value=f"{addr} → {res[0].get('display_name')}", source=self.name, target=entity,
                                  confidence=0.55, url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
                                  pivots=[Entity("location", f"{lat}, {lon}")],
                                  data={"note": "street names repeat across towns - check it fits the image"})
        for e in sorted(extract_emails(full)):
            yield Finding(category="email", title="Email in image", value=e, source=self.name, target=entity,
                          confidence=0.85, pivots=[Entity("email", e)])
        for h in sorted(set(HANDLE.findall(full))):
            yield Finding(category="lead", title="@handle in image", value=h, source=self.name, target=entity,
                          confidence=0.7, pivots=[Entity("username", h)])
        for p in sorted(set(PHONE.findall(full))):
            yield Finding(category="phone", title="Phone number in image", value=p.strip(), source=self.name,
                          target=entity, confidence=0.75, pivots=[Entity("phone", p.strip())])
        for url in sorted(set(re.findall(r"(?:https?://|www\.)[^\s]+", full)))[:10]:
            yield Finding(category="web", title="URL in image", value=url, url=url if url.startswith("http") else f"https://{url}",
                          source=self.name, target=entity, confidence=0.75)


# ----------------------------------------------------------------------------- AI vision (Claude)

VISION_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "scene_type": {"type": "string"},
        "visible_text": {"type": "array", "items": {"type": "string"}},
        "location_estimate": {"type": "string"},
        "country": {"type": "string"},
        "region": {"type": "string"},
        "city": {"type": "string"},
        "latitude": {"type": ["number", "null"]},
        "longitude": {"type": ["number", "null"]},
        "confidence": {"type": "number"},
        "clues": {"type": "array", "items": {"type": "string"}},
        "time_of_day": {"type": "string"},
        "season": {"type": "string"},
        "people_visible": {"type": "integer"},
        "is_screenshot": {"type": "boolean"},
        "screenshot_source": {"type": "string"},
    },
    "required": ["description", "scene_type", "visible_text", "location_estimate", "country", "region", "city",
                 "latitude", "longitude", "confidence", "clues", "time_of_day", "season", "people_visible",
                 "is_screenshot", "screenshot_source"],
    "additionalProperties": False,
}
VISION_PROMPT = """You are an expert imagery analyst doing open-source geolocation (GeoGuessr / GEOINT style).
Analyse this image and estimate where it was taken. Work from concrete visual evidence: architecture and
building materials, road markings and signage, licence plates, vegetation and terrain, utility poles, language
of any text, vehicles, sun position and shadows, and any map or app interface (e.g. Google Earth / Street View
coordinates or place labels). If it's a screenshot of a mapping app, read any coordinates or place names shown.
Be honest about uncertainty: give your best estimate, a confidence between 0 and 1, and list the clues you used.
Use an empty string for unknown text fields and null for unknown coordinates. Do not identify any person."""


class AIVisionSource(Source):
    name = "ai-vision"
    kinds = ("file",)
    option = "ai_vision"
    requires = ("anthropic_api_key",)
    description = "Claude vision: scene description and visual geolocation estimate (needs anthropic_api_key)"

    async def search(self, entity: Entity, ctx: Context):
        data, loc = await load_target(entity, ctx)
        if not data or not is_image(entity, data):
            return
        try:
            import anthropic
        except ImportError:
            ctx.log("ai-vision: pip install anthropic", "warning")
            return
        img_b64, media = await asyncio.to_thread(_prepare, data)
        ctx.progress(self.name, entity, 0, 1)
        client = anthropic.AsyncAnthropic(api_key=ctx.config.get("anthropic_api_key"))
        try:
            resp = await client.beta.messages.create(
                model="claude-opus-5-5",
                max_tokens=16000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                output_config={"effort": "high", "format": {"type": "json_schema", "schema": VISION_SCHEMA}},
                messages=[{"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": media, "data": img_b64}},
                    {"type": "text", "text": VISION_PROMPT}]}],
            )
        except anthropic.AuthenticationError:
            ctx.log("ai-vision: anthropic_api_key was rejected", "error")
            return
        except anthropic.RateLimitError:
            ctx.log("ai-vision: Claude API rate limit - try again shortly", "warning")
            return
        except anthropic.APIStatusError as exc:
            ctx.log(f"ai-vision: Claude API error {exc.status_code}", "warning")
            return
        except anthropic.APIConnectionError:
            ctx.log("ai-vision: couldn't reach the Claude API", "warning")
            return
        finally:
            ctx.progress(self.name, entity, 1, 1)
        if resp.stop_reason == "refusal":
            ctx.log("ai-vision: the model declined to analyse this image", "warning")
            return
        text = next((b.text for b in resp.content if b.type == "text"), "")
        try:
            a = json.loads(text)
        except ValueError:
            return
        base = dict(source=self.name, target=entity)
        yield Finding(category="ai", title="AI scene description", value=a.get("description", ""), confidence=0.75,
                      data={"scene": a.get("scene_type"), "time_of_day": a.get("time_of_day"), "season": a.get("season"),
                            "people_visible": a.get("people_visible"), "model": resp.model}, **base)
        if a.get("is_screenshot"):
            yield Finding(category="ai", title="Screenshot of", value=a.get("screenshot_source") or "unknown app",
                          confidence=0.7, **base)
        for t in (a.get("visible_text") or [])[:15]:
            yield Finding(category="text", title="Text seen by AI", value=t, confidence=0.7, **base)
        conf = max(0.1, min(0.9, float(a.get("confidence") or 0))) * 0.85
        estimate = a.get("location_estimate") or ", ".join(x for x in (a.get("city"), a.get("region"), a.get("country")) if x)
        if not estimate:
            return
        yield Finding(category="location", title="AI-estimated location", value=estimate, confidence=conf,
                      data={"clues": a.get("clues"), "model_confidence": a.get("confidence"),
                            "note": "visual estimate - verify with street-level imagery"}, **base)
        from panoptes.sources.geo import geo_findings, nominatim
        lat, lon = a.get("latitude"), a.get("longitude")
        if lat is None or lon is None:
            res = await nominatim(ctx, "search", {"q": estimate, "limit": 1})
            if res:
                lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
        if lat is not None and lon is not None:
            for f in await geo_findings(ctx, entity, self.name, round(float(lat), 6), round(float(lon), 6),
                                        label="AI-estimated location"):
                f.confidence = min(f.confidence, conf + 0.1)
                yield f


def _prepare(data: bytes) -> tuple[str, str]:
    """Downscale to <=1568px (the model's useful resolution) and re-encode as JPEG."""
    from PIL import Image
    img = Image.open(io.BytesIO(data)).convert("RGB")
    img.thumbnail((1568, 1568))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90)
    return base64.standard_b64encode(buf.getvalue()).decode(), "image/jpeg"


# ----------------------------------------------------------------------------- visual geolocation (online Picarta / optional GeoCLIP)

_geoclip = None


def geoclip_available() -> bool:
    try:
        import geoclip  # noqa: F401
        return True
    except ImportError:
        return False


def run_geoclip(data: bytes, top_k: int = 20):
    """GPS predictions for an image (CPU, offline). The model loads once per process."""
    global _geoclip
    import os
    import tempfile
    from geoclip import GeoCLIP
    from PIL import Image
    if _geoclip is None:
        _geoclip = GeoCLIP()
    fd, path = tempfile.mkstemp(suffix=".jpg")
    try:
        with os.fdopen(fd, "wb") as fh:
            Image.open(io.BytesIO(data)).convert("RGB").save(fh, "JPEG", quality=92)
        gps, prob = _geoclip.predict(path, top_k=top_k)
        return [(float(a), float(b)) for a, b in gps.tolist()], [float(p) for p in prob.tolist()]
    finally:
        os.unlink(path)


def _km(a, b) -> float:
    import math
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(b[1] - a[1]) / 2) ** 2
    return 12742 * math.asin(math.sqrt(h))


async def picarta(ctx: Context, data: bytes, top_k: int = 10):
    """Online visual geolocation (Picarta API). Returns [(lat, lon, confidence, label)] best-first."""
    b64, _ = _prepare(data)
    r = await ctx.post("https://api.picarta.ai/v1/geolocalize", timeout=90, headers={"Content-Type": "application/json"},
                       json={"TOKEN": ctx.config.get("picarta_api_key"), "IMAGE": b64, "TOP_K": top_k})
    r.raise_for_status()
    d = r.json()
    out = []

    def add(x):
        lat = x.get("ai_lat", x.get("latitude", x.get("lat")))
        lon = x.get("ai_lon", x.get("longitude", x.get("lon")))
        if lat is None or lon is None:
            return
        label = ", ".join(str(v) for v in (x.get("city"), x.get("province"), x.get("ai_country") or x.get("country")) if v)
        out.append((float(lat), float(lon), float(x.get("ai_confidence", x.get("confidence", 0.5)) or 0.5), label))
    add(d)
    topk = d.get("topk_predictions_dict") or d.get("topk_predictions") or {}
    for x in (topk.values() if isinstance(topk, dict) else topk):
        if isinstance(x, dict):
            add({**x, **(x.get("address") or {})} if isinstance(x.get("address"), dict) else x)
            if "gps" in x and isinstance(x["gps"], (list, tuple)) and len(x["gps"]) == 2:
                out.append((float(x["gps"][0]), float(x["gps"][1]), float(x.get("confidence", 0.3)), str(x.get("address", ""))[:80]))
    return out


class VisualGeolocationSource(Source):
    """Predicts where a photo was taken from what it looks like - no text or metadata needed.

    Online by default (Picarta API, nothing to download). GeoCLIP is used instead only if the user installed it
    (pip install geoclip) - it works offline but needs ~2 GB of models."""

    name = "visual-geolocation"
    kinds = ("file",)
    option = "geoai"
    description = "AI visual geolocation: estimates where a photo was taken from its content (online Picarta API; GeoCLIP if installed)"

    def available(self, config):
        if config.get("picarta_api_key") or geoclip_available():
            return True, ""
        return False, "add a picarta_api_key in Settings (online, nothing to download) - Claude vision and landmark search still run"

    async def search(self, entity: Entity, ctx: Context):
        data, _ = await load_target(entity, ctx)
        if not data or not is_image(entity, data):
            return
        ctx.progress(self.name, entity, 0, 1)
        engine = "Picarta"
        try:
            if ctx.config.get("picarta_api_key"):
                got = await picarta(ctx, data)
                preds = [(a, b) for a, b, _c, _l in got]
                if not preds:
                    ctx.log("visual-geolocation: Picarta returned no prediction", "debug")
                    return
                if len(preds) == 1:   # one confident answer: no clustering possible, use its own confidence
                    preds = preds * max(1, round(got[0][2] * 20))
            else:
                engine = "GeoCLIP"
                async with ctx.lock("geoclip"):   # one model, one inference at a time (it's CPU-heavy)
                    preds, _probs = await asyncio.to_thread(run_geoclip, data)
        except Exception as exc:
            ctx.log(f"visual-geolocation: {exc.__class__.__name__}: {exc}", "warning")
            return
        ctx.progress(self.name, entity, 1, 1)
        # Cluster the top predictions - how many of them agree is the confidence signal.
        best_members: list[int] = []
        for p in preds:
            members = [i for i, q in enumerate(preds) if _km(p, q) <= 25]
            if len(members) > len(best_members):
                best_members = members
        lat = sum(preds[i][0] for i in best_members) / len(best_members)
        lon = sum(preds[i][1] for i in best_members) / len(best_members)
        agreement = len(best_members) / len(preds)
        spread = max(_km((lat, lon), preds[i]) for i in best_members)
        conf = round(min(0.85, 0.3 + 0.55 * agreement), 2)
        from panoptes.sources.geo import geo_findings, nominatim
        place = await nominatim(ctx, "reverse", {"lat": lat, "lon": lon, "zoom": 14, "addressdetails": 1})
        label = (place or {}).get("display_name") or f"{lat:.4f}, {lon:.4f}"
        yield Finding(category="location", title=f"Visual geolocation estimate ({engine})", value=label,
                      url=f"https://www.openstreetmap.org/?mlat={lat:.5f}&mlon={lon:.5f}#map=14/{lat:.5f}/{lon:.5f}",
                      source=self.name, target=entity, confidence=conf, pivots=[Entity("location", f"{lat:.5f}, {lon:.5f}")],
                      data={"coordinates": f"{lat:.5f}, {lon:.5f}",
                            "agreement": f"{len(best_members)}/{len(preds)} top predictions within 25 km",
                            "radius_km": round(spread, 1),
                            "other_candidates": [f"{a:.3f}, {b:.3f}" for i, (a, b) in enumerate(preds[:10])
                                                 if i not in best_members][:5],
                            "note": "AI estimate from the picture's content - verify with street-level imagery"})
        for f in await geo_findings(ctx, entity, self.name, round(lat, 6), round(lon, 6), label="Visual estimate"):
            f.confidence = min(f.confidence, conf)
            yield f


class ImageLocationVerdictSource(Source):
    """Always answers 'where was this taken?' for an image - combining every method, or saying why it can't."""

    name = "image-location"
    kinds = ("file",)
    stage = "late"
    description = "Combines GPS, OCR text, landmark recognition, visual AI and Claude into one location verdict per image"

    async def search(self, entity: Entity, ctx: Context):
        from panoptes.sources.base import findings_for
        data, _ = await load_target(entity, ctx)
        if data is None or not is_image(entity, data):
            return
        locs = [f for f in findings_for(ctx, entity, "location") if f.confidence >= 0.3 and f.title != "Location verdict"]
        if not locs:
            missing = []
            if not ctx.config.get("picarta_api_key") and not geoclip_available():
                missing.append("add a picarta_api_key for online visual geolocation")
            if not ctx.config.get("anthropic_api_key"):
                missing.append("add an anthropic_api_key for Claude visual analysis")
            yield Finding(category="location", title="Location verdict",
                          value="Not determined - no GPS metadata, no readable coordinates or addresses, and the picture "
                                "wasn't recognised as a known place", source=self.name, target=entity, confidence=0.9,
                          data={"to_improve": missing or ["try a larger / uncropped version of the image"]})
            return
        rank = {"GPS": 6, "Coordinates written": 5, "Address in image": 4, "AI-estimated": 3, "Visual geolocation": 3,
                "Reverse-image": 2}
        best = max(locs, key=lambda f: (max((v for k, v in rank.items() if k in f.title), default=1), f.confidence))
        support = [f"{f.title}: {f.value[:60]}" for f in locs if f is not best]
        yield Finding(category="location", title="Location verdict", value=best.value, url=best.url, source=self.name,
                      target=entity, confidence=min(0.97, best.confidence + 0.04 * len(support)),
                      data={"method": best.title, "supporting": support[:6]})
