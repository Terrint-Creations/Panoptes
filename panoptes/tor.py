"""Built-in Tor: lets the dark-web sources work immediately, with no setup.

Order of preference:
  1. the tor_proxy set in Settings;
  2. a Tor that's already running (Tor Browser on 9150, the tor service on 9050);
  3. Panoptes' own Tor instance, started privately in the background (its own data directory and port,
     stopped when Panoptes exits). On Linux and macOS it uses the system `tor` binary (install it with your
     package manager); on Windows it downloads the official Tor Expert Bundle once from torproject.org.
"""
from __future__ import annotations

import asyncio
import atexit
import io
import re
import shutil
import socket
import subprocess
import sys
import tarfile

import httpx

from panoptes.config import CACHE_DIR

TOR_DIR = CACHE_DIR / "tools" / "tor"
PORT = 9155
_proc: subprocess.Popen | None = None


def _tor_exe() -> str | None:
    bundled = TOR_DIR / "tor" / ("tor.exe" if sys.platform == "win32" else "tor")
    if bundled.exists():
        return str(bundled)
    return shutil.which("tor")


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


async def _install(client: httpx.AsyncClient, log) -> bool:
    if _tor_exe():
        return True
    if sys.platform != "win32":
        log("tor: install Tor with your package manager (e.g. sudo apt install tor, sudo dnf install tor, "
            "sudo pacman -S tor) to enable dark-web lookups", "warning")
        return False
    base = "https://dist.torproject.org/torbrowser/"
    try:
        idx = (await client.get(base, timeout=30)).text
        versions = sorted(set(re.findall(r'href="(\d+\.\d+(?:\.\d+)?)/"', idx)), key=lambda v: [int(x) for x in v.split(".")])
        for ver in reversed(versions[-4:]):
            listing = (await client.get(f"{base}{ver}/", timeout=30)).text
            m = re.search(r"tor-expert-bundle-windows-x86_64-[\d.]+\.tar\.gz", listing)
            if m:
                log(f"tor: downloading the official Tor Expert Bundle {ver} (one-time, ~20 MB)")
                r = await client.get(f"{base}{ver}/{m.group(0)}", timeout=180)
                r.raise_for_status()
                TOR_DIR.mkdir(parents=True, exist_ok=True)
                with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
                    tar.extractall(TOR_DIR, filter="data")
                return (TOR_DIR / "tor" / "tor.exe").exists()
    except (httpx.HTTPError, tarfile.TarError, OSError) as exc:
        log(f"tor: couldn't install Tor ({exc.__class__.__name__})", "warning")
    return False


async def _start(log) -> bool:
    global _proc
    if _proc and _proc.poll() is None:
        return True
    exe = _tor_exe()
    if not exe:
        return False
    data = TOR_DIR / "data"
    data.mkdir(parents=True, exist_ok=True)
    torrc = data / "torrc"  # an empty private torrc, so a system-wide /etc/tor/torrc can't interfere
    torrc.touch(exist_ok=True)
    args = [exe, "-f", str(torrc), "--SocksPort", f"127.0.0.1:{PORT}", "--DataDirectory", str(data), "--ClientOnly", "1",
            "--Log", "notice stdout"]
    geo = TOR_DIR / "data" / "geoip"
    for name in ("geoip", "geoip6"):
        f = TOR_DIR / "data" / name
        if f.exists():
            args += ["--GeoIPFile" if name == "geoip" else "--GeoIPv6File", str(f)]
    _proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    atexit.register(stop)
    log("tor: starting Tor (connecting to the Tor network can take up to a minute)")

    def wait_bootstrap() -> bool:
        for line in _proc.stdout:
            if "Bootstrapped 100%" in line:
                return True
            if "[err]" in line:
                return False
        return False
    try:
        ok = await asyncio.wait_for(asyncio.to_thread(wait_bootstrap), 120)
    except asyncio.TimeoutError:
        ok = False
    if ok:
        log("tor: connected to the Tor network")
    else:
        log("tor: Tor didn't finish connecting - dark-web lookups will use clearnet indexes only", "warning")
    return ok


def stop() -> None:
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
    _proc = None


async def ensure_tor(ctx) -> str | None:
    """Returns a SOCKS proxy URL for Tor, starting Panoptes' own Tor if needed (once per session)."""
    async def resolve():
        configured = ctx.config.get("tor_proxy")
        if configured:
            return configured
        for port in (9150, 9050, PORT):
            if _port_open(port):
                return f"socks5://127.0.0.1:{port}"
        if not await _install(ctx.client, ctx.log):
            return None
        return f"socks5://127.0.0.1:{PORT}" if await _start(ctx.log) else None
    return await ctx.once("tor-proxy", resolve)
