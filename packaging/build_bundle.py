"""Build the ready-to-run Panoptes download for the current OS.

    python packaging/build_bundle.py

Windows -> dist/Panoptes-windows-x64.zip
    Panoptes.exe (desktop app), panoptes-cli.exe (terminal) and a private copy of the official embeddable
    Python from python.org in runtime\\. No installer, no Python needed on the user's PC.
Linux   -> dist/Panoptes-linux-x64.tar.gz
    panoptes-gui and panoptes launchers plus a relocatable Python (python-build-standalone) in runtime/.

Both contain only what's needed to run Panoptes, not the project sources. The Windows build must run on the
same Python version it bundles (it reads it from the interpreter running this script).
"""
from __future__ import annotations

import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging"
DIST = ROOT / "dist"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
UA = {"User-Agent": "panoptes-build"}

README = """Panoptes {version}
==================

The many-eyed OSINT tool. https://www.panoptes.terrint.com

{start}

Your cases, settings and logs are stored in your home folder under .panoptes, not here, so you can
replace this folder with a newer download at any time.

Panoptes is free software under the GNU GPL v3.0 or later (see LICENSE.txt).
Source code: https://github.com/Terrint-Creations/Panoptes
Only investigate people and organisations you have a legitimate reason and the legal right to look into.
"""


def fetch(url: str) -> bytes:
    print(f"  downloading {url}")
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=300) as r:
        return r.read()


def pip_install(python: list[str], extra: list[str], site_of) -> None:
    env = {**os.environ, "PIP_USER": "0"}
    base = [*python, "-m", "pip", "install", "--disable-pip-version-check", "--no-warn-script-location", *extra]
    subprocess.run([*base, f"{ROOT}[all]"], check=True, env=env)
    # rapidocr pulls in the full opencv-python next to opencv-python-headless. Both install the same cv2 package,
    # and the full one adds GUI/video libraries (a whole Qt 5 on Linux) that Panoptes never uses. Keep headless only.
    site = site_of()
    shutil.rmtree(site / "cv2", ignore_errors=True)
    for d in list(site.glob("opencv_python-*.dist-info")) + list(site.glob("opencv_python_headless-*.dist-info")):
        shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(site / "opencv_python.libs", ignore_errors=True)
    subprocess.run([*base, "--no-deps", "opencv-python-headless>=4.8"], check=True, env=env)


def trim(site: Path) -> None:
    """Drop files Panoptes never uses: caches, tests, Qt tools and translations."""
    for d in list(site.rglob("__pycache__")) + [p for p in site.rglob("tests") if p.is_dir()]:
        shutil.rmtree(d, ignore_errors=True)
    qt = site / "PySide6"
    for pattern in ("translations", "qml", "examples", "include", "typesystems", "glue", "scripts",
                    "designer*", "linguist*", "assistant*", "lupdate*", "lrelease*", "uic*", "rcc*",
                    "qmllint*", "qmlformat*", "qmlls*", "balsam*", "qsb*", "svgtoqml*", "opengl32sw.dll"):
        for p in qt.glob(pattern):
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
    # Qt Quick/QML/PDF and OpenCV's video codec aren't used by Panoptes (widgets + still images only).
    for pattern in ("Qt6Quick*", "Qt6Qml*", "Qt6Pdf*", "Qt6ShaderTools*", "Qt6VirtualKeyboard*", "QtQuick*", "QtQml*",
                    "QtPdf*", "libQt6Quick*", "libQt6Qml*", "libQt6Pdf*", "Qt/lib/libQt6Quick*", "Qt/lib/libQt6Qml*",
                    "Qt/lib/libQt6Pdf*", "Qt/qml", "plugins/platforminputcontexts/*virtualkeyboard*",
                    "Qt/plugins/platforminputcontexts/*virtualkeyboard*"):
        for p in qt.glob(pattern):
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
    for p in (site / "cv2").glob("opencv_videoio_ffmpeg*"):
        p.unlink()
    shutil.rmtree(site / "bin", ignore_errors=True)


def eye_png(size: int = 256):
    """The Panoptes eye, drawn with Pillow (same geometry as the app icon and packaging/panoptes.svg)."""
    from PIL import Image, ImageDraw
    s = size * 4
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = s / 2

    def circle(r, **kw):
        d.ellipse([c - r, c - r, c + r, c + r], **kw)
    circle(s * 0.44, fill="#0d1117", outline="#d4a017", width=round(s * 0.07))
    circle(s * 0.25, fill="#e8b830")
    circle(s * 0.11, fill="#0d1117")
    d.ellipse([c - s * 0.105, c - s * 0.105, c - s * 0.035, c - s * 0.035], fill="#ffffff")
    return im.resize((size, size), Image.LANCZOS)


# ----------------------------------------------------------------------------- Windows

def build_windows() -> Path:
    from build_launcher import find_csc
    ver = platform.python_version()
    tag = "".join(ver.split(".")[:2])
    out = DIST / "Panoptes"
    shutil.rmtree(out, ignore_errors=True)
    runtime = out / "runtime"
    runtime.mkdir(parents=True)

    print(f"[1/4] Embeddable Python {ver}")
    zipfile.ZipFile(io.BytesIO(fetch(f"https://www.python.org/ftp/python/{ver}/python-{ver}-embed-amd64.zip"))).extractall(runtime)
    (runtime / f"python{tag}._pth").write_text(f"python{tag}.zip\n.\nLib\\site-packages\nimport site\n", encoding="ascii")

    print("[2/4] Panoptes and its dependencies")
    site = runtime / "Lib" / "site-packages"
    pip_install([sys.executable], ["--target", str(site)], lambda: site)
    trim(site)

    print("[3/4] Launchers")
    icon = PKG / "panoptes.ico"
    eye_png(256).save(icon, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    gui_src = (PKG / "launcher.cs").read_text(encoding="utf-8").replace("@@PYTHONW@@", "").replace("@@REPO@@", "")
    (build / "launcher_portable.cs").write_text(gui_src, encoding="utf-8")
    csc = str(find_csc())
    common = ["/nologo", "/optimize+", f"/win32icon:{icon}"]
    subprocess.run([csc, *common, "/target:winexe", f"/out:{out / 'Panoptes.exe'}", "/r:System.Windows.Forms.dll",
                    str(build / "launcher_portable.cs")], check=True)
    subprocess.run([csc, *common, "/target:exe", f"/out:{out / 'panoptes-cli.exe'}", str(PKG / "cli_launcher.cs")],
                   check=True)
    (out / "Add shortcuts.cmd").write_text(
        "@echo off\r\nrem Adds Panoptes to the Desktop and the Start Menu.\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$t=Join-Path '%~dp0' 'Panoptes.exe';"
        "$w=New-Object -ComObject WScript.Shell;"
        "foreach($d in @([Environment]::GetFolderPath('Desktop'),(Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs'))){"
        "$s=$w.CreateShortcut((Join-Path $d 'Panoptes.lnk'));$s.TargetPath=$t;$s.WorkingDirectory='%~dp0';"
        "$s.IconLocation=$t+',0';$s.Description='Panoptes OSINT';$s.Save()}\"\r\n"
        "echo Shortcuts added to the Desktop and Start Menu.\r\npause\r\n", encoding="utf-8")
    shutil.copy(ROOT / "LICENSE", out / "LICENSE.txt")
    (out / "README.txt").write_text(README.format(version=VERSION, start=(
        "Desktop app:  double-click Panoptes.exe\n"
        "              (run \"Add shortcuts.cmd\" once to put it on the Desktop and in the Start Menu)\n"
        "Terminal:     panoptes-cli.exe search <username | email | phone | name | domain | ip | file>\n"
        "              panoptes-cli.exe --help\n\n"
        "Windows may show \"Windows protected your PC\" the first time, because Panoptes is a new, unsigned\n"
        "app. Click \"More info\" and then \"Run anyway\".")).replace("\n", "\r\n"), encoding="utf-8")

    print("[4/4] Archive")
    archive = DIST / "Panoptes-windows-x64.zip"
    archive.unlink(missing_ok=True)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(out.rglob("*")):
            if f.is_file():
                z.write(f, Path("Panoptes") / f.relative_to(out))
    return archive


# ----------------------------------------------------------------------------- Linux

def standalone_python_url(minor: str = "3.12") -> str:
    rel = json.loads(fetch("https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"))
    pat = re.compile(rf"cpython-{re.escape(minor)}\.\d+\+\d+-x86_64-unknown-linux-gnu-install_only_stripped\.tar\.gz$")
    for a in rel["assets"]:
        if pat.search(a["name"]):
            return a["browser_download_url"]
    raise SystemExit("No matching python-build-standalone asset found")


def build_linux() -> Path:
    out = DIST / "panoptes"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    print("[1/4] Relocatable Python")
    with tarfile.open(fileobj=io.BytesIO(fetch(standalone_python_url())), mode="r:gz") as t:
        t.extractall(out, filter="data")
    (out / "python").rename(out / "runtime")
    py = out / "runtime" / "bin" / "python3"

    print("[2/4] Panoptes and its dependencies")
    site_of = lambda: next((out / "runtime" / "lib").glob("python3.*")) / "site-packages"
    pip_install([str(py)], [], site_of)
    site = site_of()
    trim(site)
    for p in (out / "runtime" / "bin").iterdir():   # pip's console scripts have absolute shebangs; ours don't
        if p.name.startswith("panoptes"):
            p.unlink()

    print("[3/4] Launchers")
    for name, module in (("panoptes", "panoptes"), ("panoptes-gui", "panoptes.gui")):
        f = out / name
        f.write_text('#!/bin/sh\nHERE="$(dirname "$(readlink -f "$0")")"\n'
                     f'exec "$HERE/runtime/bin/python3" -m {module} "$@"\n', encoding="utf-8")
        f.chmod(0o755)
    shutil.copy(PKG / "linux" / "bundle-install.sh", out / "install.sh")
    (out / "install.sh").chmod(0o755)
    shutil.copy(PKG / "linux" / "panoptes.desktop", out / "panoptes.desktop")
    shutil.copy(PKG / "panoptes.svg", out / "panoptes.svg")
    shutil.copy(ROOT / "LICENSE", out / "LICENSE.txt")
    (out / "README.txt").write_text(README.format(version=VERSION, start=(
        "Desktop app:  ./panoptes-gui\n"
        "Terminal:     ./panoptes search <username | email | phone | name | domain | ip | file>\n\n"
        "Run ./install.sh once to add Panoptes to your applications menu and put the panoptes and\n"
        "panoptes-gui commands on your PATH (~/.local/bin). Nothing is installed system-wide.\n"
        "If the desktop app reports a Qt \"xcb\" error, install libxcb-cursor0 (Debian / Ubuntu).")), encoding="utf-8")

    print("[4/4] Archive")
    archive = DIST / "Panoptes-linux-x64.tar.gz"
    archive.unlink(missing_ok=True)
    with tarfile.open(archive, "w:gz", compresslevel=9) as t:
        t.add(out, arcname="panoptes")
    return archive


def main() -> None:
    os.chdir(ROOT)
    sys.path.insert(0, str(PKG))
    DIST.mkdir(exist_ok=True)
    if sys.platform == "win32":
        archive = build_windows()
    elif sys.platform.startswith("linux"):
        archive = build_linux()
    else:
        raise SystemExit("Ready-to-run bundles are built on Windows and Linux")
    print(f"Built {archive} ({archive.stat().st_size / 1e6:.0f} MB)")


if __name__ == "__main__":
    main()
