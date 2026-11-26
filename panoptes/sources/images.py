"""Image intelligence: reverse image search, avatar matching and local face recognition.

  * Collects every profile picture / image the other sources found (plus image targets).
  * Perceptual hashes (dHash) link accounts that use the same picture - even on different usernames.
  * Faces are detected (YuNet) and embedded (SFace) locally with OpenCV; the same face appearing in
    a target photo and in a profile picture is reported. Embeddings never leave the machine.
  * Reverse image search: Yandex (by URL or by uploading a local file), Google Lens via SerpAPI when a
    key is set, plus one-click links to TinEye, Bing, PimEyes, FaceCheck.ID, Search4faces and Lenso.
"""
from __future__ import annotations

import asyncio
import html as htmlmod
import io
import json
import re
import threading
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from panoptes.config import CACHE_DIR
from panoptes.detect import social_handle
from panoptes.models import Entity, Finding, Report, combine_confidence
from panoptes.sources.base import Context, Source, findings_for

MODELS = {
    "yunet": ("face_detection_yunet_2023mar.onnx",
              "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"),
    "sface": ("face_recognition_sface_2021dec.onnx",
              "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"),
}
FACE_MATCH = 0.42       # SFace cosine similarity; the model's published same-person threshold is 0.363
MAX_IMAGES_PER_ENTITY = 30
IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic")


# ----------------------------------------------------------------------------- hashing

def dhash(img) -> int:
    g = img.convert("L").resize((9, 8))
    px = list(g.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1])
    return bits


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def load_image(data: bytes):
    from PIL import Image, ImageStat
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        return None, "unreadable"
    if img.width < 40 or img.height < 40:
        return None, "too small"
    if max(ImageStat.Stat(img.convert("L")).stddev) < 8:
        return None, "blank/placeholder"
    return img.convert("RGB"), ""


# ----------------------------------------------------------------------------- faces

_tls = threading.local()


def faces_available() -> bool:
    try:
        import cv2
        return hasattr(cv2, "FaceDetectorYN") and hasattr(cv2, "FaceRecognizerSF")
    except ImportError:
        return False


async def ensure_models(ctx: Context) -> dict[str, Path] | None:
    async def fetch():
        d = CACHE_DIR / "models"
        d.mkdir(parents=True, exist_ok=True)
        paths = {}
        for key, (fname, url) in MODELS.items():
            p = d / fname
            if not p.exists() or p.stat().st_size < 100_000:
                ctx.log(f"faces: downloading {fname} (one-time)")
                try:
                    r = await ctx.get(url, timeout=120, deadline=300)
                    r.raise_for_status()
                    p.write_bytes(r.content)
                except httpx.HTTPError as exc:
                    ctx.log(f"faces: model download failed ({exc.__class__.__name__}); face matching off", "warning")
                    return None
            paths[key] = p
        return paths
    return await ctx.once("face-models", fetch)


def detect_faces(img, models: dict[str, Path]) -> list[dict]:
    """Returns [{box, score, embedding}] for each face (runs in a worker thread)."""
    import cv2
    import numpy as np

    if not hasattr(_tls, "det"):
        _tls.det = cv2.FaceDetectorYN.create(str(models["yunet"]), "", (320, 320), 0.82, 0.3, 5000)
        _tls.rec = cv2.FaceRecognizerSF.create(str(models["sface"]), "")
    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    h, w = arr.shape[:2]
    scale = min(1.0, 1024 / max(h, w))
    if scale < 1:
        arr = cv2.resize(arr, (int(w * scale), int(h * scale)))
        h, w = arr.shape[:2]
    _tls.det.setInputSize((w, h))
    _, faces = _tls.det.detect(arr)
    out = []
    for face in (faces if faces is not None else []):
        if face[2] < 28 or face[3] < 28:
            continue
        aligned = _tls.rec.alignCrop(arr, face)
        emb = _tls.rec.feature(aligned).flatten()
        emb = emb / (np.linalg.norm(emb) + 1e-9)
        out.append({"box": [int(v / scale) for v in face[:4]], "score": float(face[14]), "embedding": emb})
    return out


# ----------------------------------------------------------------------------- reverse search

def _yandex_parse(page: str) -> tuple[list[dict], list[str]]:
    sites, tags = [], []
    for raw in re.findall(r'data-state="([^"]{200,})"', page):
        try:
            st = json.loads(htmlmod.unescape(raw))
        except ValueError:
            continue
        init = st.get("initialState") or {}
        for s in (init.get("cbirSites") or {}).get("sites", []):
            thumb = (s.get("originalImage") or {}).get("url") or (s.get("thumb") or {}).get("url") or ""
            sites.append({"title": s.get("title"), "url": s.get("url"), "domain": s.get("domain"),
                          "image": ("https:" + thumb) if thumb.startswith("//") else thumb})
        for t in (init.get("cbirTags") or {}).get("tags", []):
            tags.append(t.get("text"))
    return sites, [t for t in tags if t]


async def yandex_search(ctx: Context, url: str | None = None, data: bytes | None = None):
    """Reverse search on Yandex by public URL, or by uploading the bytes. Returns (sites, tags) or None."""
    base = "https://yandex.com/images/search"
    try:
        if data is not None:
            r = await ctx.post(base, params={"rpt": "imageview", "format": "json",
                                             "request": json.dumps({"blocks": [{"block": "b-page_type_search-by-image__link"}]})},
                               files={"upfile": ("image.jpg", data, "image/jpeg")}, timeout=40)
            params = r.json()["blocks"][0]["params"]
            if params.get("url"):
                r = await ctx.get(f"{base}?{params['url']}&cbir_page=sites", timeout=40)
            else:  # current response shape: an id for the uploaded image instead of a ready-made query
                r = await ctx.get(base, timeout=40, params={"rpt": "imageview", "url": params["originalImageUrl"],
                                                           "cbir_id": params["cbirId"], "cbir_page": "sites"})
        else:
            r = await ctx.get(base, params={"rpt": "imageview", "url": url, "cbir_page": "sites"}, timeout=40)
    except (httpx.HTTPError, ValueError, KeyError, IndexError):
        return None
    if "showcaptcha" in str(r.url):
        ctx.log("reverse-image: Yandex asked for a CAPTCHA - try again later or use the manual links", "warning")
        return None
    return _yandex_parse(r.text)


async def lens_search(ctx: Context, url: str) -> list[dict]:
    key = ctx.config.get("serpapi_key")
    if not key:
        return []
    try:
        d = await ctx.get_json("https://serpapi.com/search.json", params={"engine": "google_lens", "url": url, "api_key": key},
                               timeout=60)
    except (httpx.HTTPError, ValueError):
        return []
    return [{"title": m.get("title"), "url": m.get("link"), "domain": m.get("source"), "image": m.get("thumbnail")}
            for m in d.get("visual_matches", [])]


def manual_links(url: str | None, faces: bool) -> dict[str, str]:
    if url:
        q = quote(url, safe="")
        links = {"Google Lens": f"https://lens.google.com/uploadbyurl?url={q}",
                 "Bing Visual Search": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
                 "TinEye": f"https://tineye.com/search?url={q}", "Yandex": f"https://yandex.com/images/search?rpt=imageview&url={q}"}
    else:
        links = {"Google Lens": "https://lens.google.com/", "TinEye": "https://tineye.com/",
                 "Bing Visual Search": "https://www.bing.com/visualsearch"}
    if faces:
        links.update({"PimEyes (face search)": "https://pimeyes.com/en", "FaceCheck.ID (face search)": "https://facecheck.id/",
                      "Search4faces (VK/OK faces)": "https://search4faces.com/", "Lenso.ai (faces/places)": "https://lenso.ai/"})
    return links


# ----------------------------------------------------------------------------- the source

class ImageIntelSource(Source):
    name = "image-intel"
    kinds = ("username", "email", "name", "file", "company", "domain")
    stage = "late"
    description = ("Reverse image search (Yandex, Google Lens/SerpAPI), profile-picture matching across accounts, "
                   "and local face detection/recognition (OpenCV YuNet + SFace)")

    async def _collect(self, entity: Entity, ctx: Context) -> list[dict]:
        items, seen = [], set()
        if entity.kind == "file":
            loc = entity.value
            if loc.lower().split("?")[0].endswith(IMAGE_EXTS):
                items.append({"label": "Target image", "url": loc if loc.startswith("http") else None,
                              "path": None if loc.startswith("http") else loc, "conf": 1.0, "profile": None, "target": True})
        for f in sorted(findings_for(ctx, entity), key=lambda f: -f.confidence):
            urls = []
            if f.category == "image":
                urls.append(f.url or f.value)
            if f.data.get("avatar"):
                urls.append(f.data["avatar"])
            for u in urls:
                if u and u.startswith("http") and u not in seen and f.confidence >= 0.6:
                    seen.add(u)
                    items.append({"label": f.title, "url": u, "path": None, "conf": f.confidence,
                                  "profile": f.data.get("profile") or (f.url if f.category == "account" else None),
                                  "target": False})
        return items[:MAX_IMAGES_PER_ENTITY]

    async def search(self, entity: Entity, ctx: Context):
        items = await self._collect(entity, ctx)
        if not items:
            return
        use_faces = ctx.options.faces and faces_available()
        models = await ensure_models(ctx) if use_faces else None
        ctx.progress(self.name, entity, 0, len(items))
        store = ctx.shared.setdefault("images", [])
        done = 0

        async def process(item):
            try:
                if item["path"]:
                    data = await asyncio.to_thread(Path(item["path"]).read_bytes)
                else:
                    r = await ctx.get(item["url"], timeout=20)
                    if r.status_code != 200 or len(r.content) > 12_000_000:
                        return None
                    data = r.content
            except (httpx.HTTPError, OSError):
                return None
            img, why = await asyncio.to_thread(load_image, data)
            if img is None:
                return None
            rec = {**item, "entity": str(entity), "hash": dhash(img), "faces": [], "data": data if item["target"] else None}
            if models:
                try:
                    rec["faces"] = await asyncio.to_thread(detect_faces, img, models)
                except Exception as exc:
                    ctx.log(f"faces: {exc.__class__.__name__}: {exc}", "debug")
            return rec

        gate = asyncio.Semaphore(ctx.options.image_workers)

        async def gated(i):
            async with gate:
                return await process(i)
        for fut in asyncio.as_completed([gated(i) for i in items]):
            rec = await fut
            done += 1
            ctx.progress(self.name, entity, done, len(items))
            if rec:
                store.append(rec)
                if rec["target"]:
                    yield Finding(category="face", title="Faces detected", value=str(len(rec["faces"])),
                                  source=self.name, target=entity, confidence=0.9 if models else 0.5,
                                  data={"boxes": [f["box"] for f in rec["faces"]],
                                        "note": "" if models else "face detection unavailable (opencv missing)"})

        # Reverse image search: the target image itself, plus the two most trusted profile pictures.
        if not ctx.options.reverse_image:
            return
        queries = [r for r in store if r["entity"] == str(entity) and r["target"]]
        dedicated = ("avatar", "photo", "picture")  # pictures from platform APIs, not generic page og:images
        queries += sorted((r for r in store if r["entity"] == str(entity) and not r["target"] and r["url"]
                           and any(d in r["label"].lower() for d in dedicated)), key=lambda r: -r["conf"])[:2]
        for q in queries:
            async for f in self._reverse(q, entity, ctx):
                yield f

    async def _reverse(self, rec: dict, entity: Entity, ctx: Context):
        label = rec["label"]
        res = await yandex_search(ctx, url=rec["url"]) if rec["url"] else await yandex_search(ctx, data=rec["data"])
        hits = []
        if res:
            sites, tags = res
            hits += [(s, "yandex") for s in sites]
            rec["web_hits"] = len(sites)
            if tags:
                yield Finding(category="image-match", title=f"Image appears to show ({label})", value=", ".join(tags[:6]),
                              source=self.name, target=entity, confidence=0.5, data={"engine": "yandex"})
                if rec["target"]:
                    # If the search engine recognises a place/landmark, geolocate it.
                    from panoptes.sources.geo import geo_findings, nominatim
                    for tag in tags[:3]:
                        res = await nominatim(ctx, "search", {"q": tag, "limit": 1})
                        if res and float(res[0].get("importance") or 0) >= 0.35:
                            lat, lon = round(float(res[0]["lat"]), 6), round(float(res[0]["lon"]), 6)
                            yield Finding(category="location", title="Reverse-image location estimate",
                                          value=f"{tag} → {res[0].get('display_name')}", source=self.name, target=entity,
                                          confidence=0.55, url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
                                          data={"note": "what the search engine thinks the photo shows - verify"})
                            for f in await geo_findings(ctx, entity, self.name, lat, lon, label="Reverse-image location"):
                                f.confidence = min(f.confidence, 0.6)
                                yield f
                            break
        if rec["url"]:
            hits += [(s, "google-lens") for s in await lens_search(ctx, rec["url"])]
        known = {entity.value.lower()} | {n.lower() for n in (ctx.knowledge.trusted_values("name") if ctx.knowledge else [])}
        known |= {n.lower() for n in (ctx.knowledge.trusted_values("username") if ctx.knowledge else []) if len(n) >= 4}
        unrelated = 0
        for site, engine in hits[:40]:
            page = site.get("url") or ""
            if not page:
                continue
            text = f"{site.get('title') or ''} {page}".lower()
            related = any(k and k in text for k in known)
            if not related and not rec["target"]:
                continue  # for avatars only pages tied to the person matter; "similar" pictures are noise
            if not related:
                unrelated += 1
                if unrelated > 12:
                    continue
            handle = social_handle(page)
            yield Finding(category="image-match", title=f"Same/similar image ({label})", value=page, url=page,
                          source=self.name, sources={engine}, target=entity, confidence=0.8 if related else 0.45,
                          data={"page_title": site.get("title"), "site": site.get("domain"), "engine": engine,
                                "thumbnail": site.get("image"), "compared_with": rec.get("url") or label},
                          pivots=[Entity("username", handle)] if handle and handle.lower() != entity.value.lower() else [])
        for title, link in manual_links(rec["url"], bool(rec.get("faces"))).items():
            yield Finding(category="lead", title=f"Reverse search: {title}", value=link, url=link, source=self.name,
                          target=entity, confidence=0.5, data={"image": label})

    async def finalize(self, ctx: Context, report: Report) -> list[Finding]:
        """Across everything collected: same picture on several accounts, same face in several images."""
        store = [r for r in ctx.shared.get("images", [])]
        out: list[Finding] = []
        if len(store) < 2:
            return out
        primary = report.targets[0]

        def where(r):
            return r["profile"] or r["url"] or r["label"]

        def site(r):
            if r["target"]:
                return "target"
            host = urlparse(r["profile"] or "").hostname or urlparse(r["url"] or "").hostname or r["label"]
            parts = host.lower().removeprefix("www.").split(".")
            base = ".".join(parts[-2:])
            return {"githubusercontent.com": "github.com", "gravatar.com": "gravatar.com"}.get(base, base)

        # avatar clusters (skip ubiquitous default pictures)
        common = {}
        for r in store:
            common[r["hash"]] = common.get(r["hash"], 0) + 1
        parent = list(range(len(store)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i
        for i in range(len(store)):
            for j in range(i + 1, len(store)):
                if hamming(store[i]["hash"], store[j]["hash"]) <= 5 and common[store[i]["hash"]] < 8:
                    parent[find(i)] = find(j)
        clusters: dict[int, list[dict]] = {}
        for i, r in enumerate(store):
            clusters.setdefault(find(i), []).append(r)
        for members in clusters.values():
            places = {where(m) for m in members}
            if len(places) < 2 or len({site(m) for m in members}) < 2:
                continue
            ents = sorted({m["entity"] for m in members})
            labels = sorted({m["label"] for m in members})
            exact = all(hamming(members[0]["hash"], m["hash"]) <= 2 for m in members)
            # A press photo or meme used by many people proves nothing about who owns an account.
            published = max((m.get("web_hits", 0) for m in members), default=0) >= 5
            conf = 0.5 if published else 0.9 if exact else 0.8
            out.append(Finding(category="image-link", title="Same profile picture", value=" ↔ ".join(labels[:8]),
                               source=self.name, target=primary, confidence=conf,
                               data={"places": sorted(places)[:12], "entities": ents, "widely_published": published,
                                     "note": ("picture is widely published online - weak evidence of common ownership"
                                              if published else "links accounts across different usernames"
                                              if len(ents) > 1 else "")}))
            if published:
                continue
            for f in report.findings.values():
                if f.category == "account" and f.url and f.url in places and "same profile picture" not in str(f.data):
                    f.data.setdefault("corroborated_by", []).append(f"same profile picture as {len(places) - 1} other account(s)")
                    f.confidence = combine_confidence(f.confidence, 0.6)
                    f.sources.add("image-intel")

        # face matches between different images
        faces = [(r, face) for r in store for face in r["faces"]]
        pairs = 0
        for i in range(len(faces)):
            for j in range(i + 1, len(faces)):
                (ra, fa), (rb, fb) = faces[i], faces[j]
                if where(ra) == where(rb) or ra["hash"] == rb["hash"]:
                    continue  # the same picture isn't a "face match"
                sim = float((fa["embedding"] * fb["embedding"]).sum())
                if sim < FACE_MATCH:
                    continue
                pairs += 1
                if pairs > 60:
                    break
                involves_target = ra["target"] or rb["target"]
                out.append(Finding(category="face-match", title="Same face", value=f"{ra['label']} ↔ {rb['label']}",
                                   source=self.name, target=primary, confidence=0.85 if sim >= 0.55 else 0.65,
                                   url=rb["profile"] or rb["url"] if ra["target"] else ra["profile"] or ra["url"],
                                   data={"similarity": round(sim, 3), "a": where(ra), "b": where(rb),
                                         "involves_target_photo": involves_target}))
        return out
