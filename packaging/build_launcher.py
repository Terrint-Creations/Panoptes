"""Compile packaging/launcher.cs into Panoptes.exe (project root) and create Desktop + Start Menu shortcuts.

Uses the C# compiler that ships with Windows (.NET Framework 4.x), so no extra tools are needed.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging"


def find_csc() -> Path:
    base = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET"
    for fw in ("Framework64", "Framework"):
        for d in sorted((base / fw).glob("v4*"), reverse=True):
            if (d / "csc.exe").exists():
                return d / "csc.exe"
    sys.exit("C# compiler (csc.exe) not found - .NET Framework 4 is required")


def pythonw() -> str:
    exe = Path(sys.executable)
    cand = exe.with_name("pythonw.exe")
    return str(cand if cand.exists() else exe)


def shortcut(path: Path, target: Path) -> None:
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{path}');"
          f"$s.TargetPath='{target}';$s.WorkingDirectory='{target.parent}';"
          f"$s.IconLocation='{target},0';$s.Description='Panoptes OSINT';$s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)


def main() -> None:
    if not (PKG / "panoptes.ico").exists():
        subprocess.run([sys.executable, str(PKG / "make_icon.py")], check=True)
    src = (PKG / "launcher.cs").read_text(encoding="utf-8")
    src = src.replace("@@PYTHONW@@", pythonw().replace("\\", "\\\\")).replace("@@REPO@@", str(ROOT).replace("\\", "\\\\"))
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    (build / "launcher.cs").write_text(src, encoding="utf-8")
    out = ROOT / "Panoptes.exe"
    subprocess.run([str(find_csc()), "/nologo", "/target:winexe", "/optimize+", f"/win32icon:{PKG / 'panoptes.ico'}",
                    f"/out:{out}", "/r:System.Windows.Forms.dll", str(build / "launcher.cs")], check=True)
    desktop = Path(os.environ["USERPROFILE"]) / "Desktop"
    start_menu = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    for folder in (desktop, start_menu):
        if folder.exists():
            shortcut(folder / "Panoptes.lnk", out)
    print(f"Built {out}\nShortcuts: Desktop and Start Menu")


if __name__ == "__main__":
    main()
