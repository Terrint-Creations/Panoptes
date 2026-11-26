@echo off
rem Builds Panoptes.exe - a small native launcher for the desktop app - and puts shortcuts on the
rem Desktop and Start Menu. It uses your installed Python, so it always runs the latest code.
rem
rem   build_exe.bat             launcher (recommended)
rem   build_exe.bat portable    standalone PyInstaller build in dist\ (no Python needed on the target PC,
rem                             but unsigned PyInstaller apps are often flagged by antivirus heuristics)
cd /d "%~dp0"
python -m pip install -e ".[all]" || goto :error
python packaging\build_launcher.py || goto :error
if /i "%1"=="portable" (
    python -m pip install pyinstaller pillow pypdf || goto :error
    python packaging\make_icon.py || goto :error
    pushd packaging
    python -m PyInstaller --noconfirm --clean --distpath ..\dist --workpath ..\build panoptes.spec || (popd & goto :error)
    popd
    echo Portable build: %~dp0dist\Panoptes\Panoptes.exe
)
exit /b 0
:error
echo Build failed.
exit /b 1
