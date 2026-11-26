"""File & image metadata (ExifTool / Metagoofil / FOCA capabilities).

Works on a local path or a URL. Built-in parsers cover EXIF + GPS (Pillow), PDF (pypdf) and
Office OOXML documents; when the real `exiftool` binary is on PATH its full tag dump is merged in.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote, urlparse
from xml.etree import ElementTree as ET

import httpx

from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source, extract_emails

MAX_DOWNLOAD = 50 * 1024 * 1024


def sniff_type(data: bytes, name: str = "") -> str:
    head = data[:16]
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG"):
        return "image/png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1"):
        return "image/heic"
    if data[4:8] == b"ftyp":
        return "video/mp4"
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except zipfile.BadZipFile:
            return "application/zip"
        for prefix, mime in (("word/", "application/docx"), ("xl/", "application/xlsx"), ("ppt/", "application/pptx")):
            if any(n.startswith(prefix) for n in names):
                return mime
        return "application/zip"
    return "application/octet-stream"


def _dms(value, ref) -> float | None:
    try:
        d, m, s = (float(x) for x in value)
        dec = d + m / 60 + s / 3600
        return -dec if ref in ("S", "W") else dec
    except (TypeError, ValueError):
        return None


def image_metadata(data: bytes) -> dict:
    from PIL import ExifTags, Image

    out: dict = {}
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return out
    out["Dimensions"] = f"{img.width}x{img.height}"
    out["Format"] = f"{img.format} ({img.mode})"
    if img.info.get("dpi"):
        out["DPI"] = "x".join(str(round(float(v))) for v in img.info["dpi"])
    if getattr(img, "n_frames", 1) > 1:
        out["Frames"] = str(img.n_frames)
    if img.info.get("icc_profile"):
        try:
            from PIL import ImageCms
            out["Colour profile"] = ImageCms.getProfileDescription(
                ImageCms.ImageCmsProfile(io.BytesIO(img.info["icc_profile"]))).strip()
        except Exception:
            out["Colour profile"] = "embedded ICC profile"
    screens = {(1920, 1080), (2560, 1440), (3840, 2160), (1366, 768), (1536, 864), (1440, 900), (2880, 1800),
               (1280, 720), (1600, 900), (2560, 1600), (3440, 1440), (1170, 2532), (1179, 2556), (1080, 2400),
               (1284, 2778), (1080, 1920), (1290, 2796), (750, 1334)}
    if (img.width, img.height) in screens:
        out["Looks like"] = "a full-screen screenshot (exact screen resolution)"
    out["Perceptual hash"] = f"{_dhash_hex(img)}"
    exif = img.getexif()
    for tag_id, val in exif.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if isinstance(val, bytes) or name in ("ExifOffset", "GPSInfo"):
            continue
        out[name] = str(val).strip("\x00 ")
    for ifd_id in (0x8769,):  # Exif sub-IFD: DateTimeOriginal, lens, body serial...
        try:
            for tag_id, val in exif.get_ifd(ifd_id).items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if not isinstance(val, bytes) and name not in ("MakerNote",):
                    out[name] = str(val).strip("\x00 ")
        except Exception:
            pass
    try:
        gps = exif.get_ifd(0x8825)
        if gps:
            g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}
            lat = _dms(g.get("GPSLatitude"), g.get("GPSLatitudeRef"))
            lon = _dms(g.get("GPSLongitude"), g.get("GPSLongitudeRef"))
            if lat is not None and lon is not None:
                out["_gps"] = (round(lat, 6), round(lon, 6))
            if g.get("GPSAltitude") is not None:
                out["GPSAltitude"] = f"{float(g['GPSAltitude']):.1f} m"
    except Exception:
        pass
    for k, v in (img.info or {}).items():  # PNG text chunks (incl. AI-generator prompts), comments
        if isinstance(v, str) and k not in ("icc_profile",) and len(v) < 4000:
            out[f"Embedded {k}"] = v
    return out


def _dhash_hex(img) -> str:
    g = img.convert("L").resize((9, 8))
    px = list(g.getdata())
    bits = 0
    for r in range(8):
        for c in range(8):
            bits = (bits << 1) | (px[r * 9 + c] > px[r * 9 + c + 1])
    return f"{bits:016x}"


def pdf_metadata(data: bytes) -> dict:
    from pypdf import PdfReader

    out: dict = {}
    try:
        reader = PdfReader(io.BytesIO(data))
        meta = reader.metadata or {}
        for k, v in meta.items():
            out[k.lstrip("/")] = str(v)
        out["Pages"] = str(len(reader.pages))
        text = " ".join((p.extract_text() or "") for p in reader.pages[:5])
        out["_emails"] = sorted(extract_emails(text))
    except Exception as exc:
        out["Error"] = f"unreadable PDF ({exc.__class__.__name__})"
    return out


def office_metadata(data: bytes) -> dict:
    out: dict = {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    for part in ("docProps/core.xml", "docProps/app.xml"):
        try:
            root = ET.fromstring(z.read(part))
        except (KeyError, ET.ParseError):
            continue
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if el.text and el.text.strip() and tag not in ("Properties", "coreProperties", "vt:lpstr"):
                if len(el.text) < 500 and not list(el):
                    out[tag] = el.text.strip()
    return out


def analyze(data: bytes, name: str = "") -> dict:
    mime = sniff_type(data, name)
    meta: dict = {}
    if mime.startswith("image/"):
        meta = image_metadata(data)
    elif mime == "application/pdf":
        meta = pdf_metadata(data)
    elif mime in ("application/docx", "application/xlsx", "application/pptx"):
        meta = office_metadata(data)
    return {
        "mime": mime,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "meta": meta,
    }


def run_exiftool(path: str, exe: str | None = None) -> dict:
    exe = exe or shutil.which("exiftool")
    if not exe:
        return {}
    try:
        out = subprocess.run([exe, "-j", "-G1", "-a", "-api", "largefilesupport=1", path], capture_output=True,
                             timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(out.stdout.decode("utf-8", "replace") or "[]")
        return data[0] if data else {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


PERSON_FIELDS = {"Author", "Creator", "Artist", "creator", "lastModifiedBy", "OwnerName", "XPAuthor", "Copyright",
                 "CameraOwnerName", "Company", "Manager"}
SOFTWARE_FIELDS = {"Producer", "Software", "Application", "CreatorTool", "Creator Tool"}
NOT_PEOPLE = re.compile(r"microsoft|adobe|word|acrobat|pdf|office|writer|latex|tex|libreoffice|openoffice|google|"
                        r"canon|nikon|apple|samsung|sony|unknown|user|admin|owner|windows", re.I)


def metadata_findings(info: dict, entity: Entity, source: str, url: str | None, doc_label: str = "") -> list[Finding]:
    """Turn `analyze()` output into findings, with names/usernames as pivots."""
    out: list[Finding] = []
    prefix = f"{doc_label}: " if doc_label else ""
    meta = info.get("meta", {})
    for key, val in meta.items():
        if key.startswith("_") or not val:
            continue
        pivots: list[Entity] = []
        category = "metadata"
        if key in PERSON_FIELDS and not NOT_PEOPLE.search(val):
            category = "person"
            if " " in val.strip():
                pivots = [Entity("name", val.strip())]
            elif re.fullmatch(r"[A-Za-z0-9._\-]{3,30}", val.strip()):
                pivots = [Entity("username", val.strip())]
        elif key in SOFTWARE_FIELDS:
            category = "software"
        out.append(Finding(category=category, title=f"{prefix}{key}", value=str(val)[:500], source=source,
                           target=entity, url=url, confidence=0.9, pivots=pivots))
    if "_gps" in meta:
        lat, lon = meta["_gps"]
        out.append(Finding(category="location", title=f"{prefix}GPS coordinates", value=f"{lat}, {lon}", source=source,
                           target=entity, confidence=0.95, pivots=[Entity("location", f"{lat}, {lon}")],
                           url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
                           data={"google_maps": f"https://maps.google.com/?q={lat},{lon}"}))
    for e in meta.get("_emails", []):
        out.append(Finding(category="email", title=f"{prefix}Email in document", value=e, source=source, target=entity,
                           url=url, confidence=0.8, pivots=[Entity("email", e)]))
    return out


class FileMetadataSource(Source):
    name = "file-metadata"
    kinds = ("file",)
    description = "ExifTool-style metadata: EXIF/GPS, PDF & Office authors, software, hashes (+ full exiftool if installed)"

    async def search(self, entity: Entity, ctx: Context):
        loc = entity.value
        is_url = loc.lower().startswith(("http://", "https://"))
        tmp_path = None
        try:
            if is_url:
                async with ctx.client.stream("GET", loc, timeout=60) as r:
                    r.raise_for_status()
                    chunks, size = [], 0
                    async for chunk in r.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_DOWNLOAD:
                            ctx.log("file-metadata: file larger than 50 MB, truncated", "warning")
                            break
                        chunks.append(chunk)
                data = b"".join(chunks)
                name = Path(urlparse(loc).path).name
            else:
                data = await asyncio.to_thread(Path(loc).read_bytes)
                name = Path(loc).name
        except httpx.HTTPStatusError as exc:
            ctx.log(f"file-metadata: the site refused the download (HTTP {exc.response.status_code}) - save the file "
                    f"and analyse the local copy instead", "error")
            return
        except (httpx.HTTPError, OSError) as exc:
            ctx.log(f"file-metadata: could not read the file ({exc.__class__.__name__})", "error")
            return

        info = await asyncio.to_thread(analyze, data, name)
        base = dict(source=self.name, target=entity, url=loc if is_url else None)
        if not is_url:
            import datetime as _dt
            st = os.stat(loc)
            fmt = lambda t: _dt.datetime.fromtimestamp(t).isoformat(timespec="seconds")
            yield Finding(category="file", title="File created (this computer)", value=fmt(st.st_ctime), confidence=0.9, **base)
            yield Finding(category="file", title="File modified", value=fmt(st.st_mtime), confidence=0.9, **base)
            if re.search(r"screen ?shot|screenshot|skjámynd|captura|bildschirmfoto", name, re.I):
                yield Finding(category="file", title="Origin", value="screenshot (from the file name) - screenshots "
                              "carry no camera/GPS metadata, so OCR and visual analysis do the work", confidence=0.8, **base)
        yield Finding(category="file", title="Type", value=info["mime"], confidence=0.99, **base)
        yield Finding(category="file", title="Size", value=f"{info['size']:,} bytes", confidence=0.99, **base)
        for h in ("md5", "sha1", "sha256"):
            yield Finding(category="file", title=h.upper(), value=info[h], confidence=0.99,
                          **{**base, "url": f"https://www.virustotal.com/gui/file/{info['sha256']}" if h == "sha256" else base["url"]})
        for f in metadata_findings(info, entity, self.name, base["url"]):
            yield f
        if "_gps" in info["meta"]:
            from panoptes.sources.geo import geo_findings, parse_capture
            lat, lon = info["meta"]["_gps"]
            capture = parse_capture(info["meta"])
            if capture:
                yield Finding(category="metadata", title="Captured at", value=capture.isoformat(), confidence=0.9, **base)
            for f in await geo_findings(ctx, entity, self.name, lat, lon, capture, label="Photo location"):
                yield f

        # Full ExifTool dump when available.
        path = loc
        if is_url:
            fd, tmp_path = tempfile.mkstemp(suffix=Path(name).suffix or ".bin")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            path = tmp_path
        try:
            from panoptes.sources.imageanalysis import ensure_exiftool
            exe = await ensure_exiftool(ctx)
            tags = await asyncio.to_thread(run_exiftool, path, exe) if exe else {}
        finally:
            if tmp_path:
                os.unlink(tmp_path)
        if tags:
            for key, val in tags.items():
                if key in ("SourceFile",) or key.startswith(("System:", "File:Directory")):
                    continue
                yield Finding(category="metadata", title=f"ExifTool {key}", value=str(val)[:500], source="exiftool",
                              target=entity, confidence=0.9)
        elif not exe:
            ctx.log("file-metadata: ExifTool unavailable - showing built-in metadata only", "debug")

        if info["mime"].startswith("image/"):
            if is_url:
                q = quote(loc, safe="")
                leads = {"Google Lens": f"https://lens.google.com/uploadbyurl?url={q}",
                         "Bing Visual Search": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
                         "Yandex Images": f"https://yandex.com/images/search?rpt=imageview&url={q}",
                         "TinEye": f"https://tineye.com/search?url={q}"}
            else:
                leads = {"Google Lens (upload)": "https://lens.google.com/", "Yandex Images (upload)": "https://yandex.com/images/",
                         "TinEye (upload)": "https://tineye.com/", "Bing Visual Search (upload)": "https://www.bing.com/visualsearch"}
            for title, url in leads.items():
                yield Finding(category="lead", title=f"Reverse image: {title}", value=url, url=url, source=self.name,
                              target=entity, confidence=0.5)
