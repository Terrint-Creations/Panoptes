#!/usr/bin/env sh
# Panoptes installer for Linux (and other Unix-likes).
#
#   ./install.sh            everything: desktop app, email/phone checks, face recognition, OCR, AI
#   ./install.sh --minimal  terminal tool only (smallest install)
#
# Installs into its own virtual environment (~/.local/share/panoptes/venv), links the `panoptes` and
# `panoptes-gui` commands into ~/.local/bin and adds a menu entry. Nothing is installed system-wide.
# Run it again to update after downloading a newer release. Remove with ./install.sh --uninstall
set -eu

cd "$(dirname "$0")"
PREFIX="${PANOPTES_PREFIX:-$HOME/.local/share/panoptes}"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
EXTRAS="all"

case "${1:-}" in
  --minimal) EXTRAS="" ;;
  --uninstall)
    rm -rf "$PREFIX"
    rm -f "$BIN/panoptes" "$BIN/panoptes-gui" "$APPS/panoptes.desktop" "$ICONS/panoptes.svg"
    echo "Panoptes removed. Your cases and settings in ~/.panoptes were kept."
    exit 0 ;;
  "") ;;
  *) echo "usage: $0 [--minimal | --uninstall]"; exit 2 ;;
esac

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for cand in python3.13 python3.12 python3.11 python3; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      PY="$cand"; break
    fi
  done
fi
if [ -z "$PY" ]; then
  echo "Panoptes needs Python 3.11 or newer. Install it with your package manager, e.g."
  echo "  sudo apt install python3 python3-venv     (Debian / Ubuntu)"
  echo "  sudo dnf install python3                  (Fedora)"
  echo "  sudo pacman -S python                     (Arch)"
  exit 1
fi

echo "Using $($PY --version) at $(command -v "$PY")"
if ! "$PY" -m venv "$PREFIX/venv"; then
  echo "Couldn't create a virtual environment. On Debian / Ubuntu: sudo apt install python3-venv"
  exit 1
fi
"$PREFIX/venv/bin/python" -m pip install --upgrade pip >/dev/null
if [ -n "$EXTRAS" ]; then
  "$PREFIX/venv/bin/python" -m pip install ".[$EXTRAS]"
else
  "$PREFIX/venv/bin/python" -m pip install .
fi

mkdir -p "$BIN"
ln -sf "$PREFIX/venv/bin/panoptes" "$BIN/panoptes"
if [ -x "$PREFIX/venv/bin/panoptes-gui" ] && [ -n "$EXTRAS" ]; then
  ln -sf "$PREFIX/venv/bin/panoptes-gui" "$BIN/panoptes-gui"
  mkdir -p "$APPS" "$ICONS"
  cp packaging/panoptes.svg "$ICONS/panoptes.svg"
  sed "s|@@EXEC@@|$PREFIX/venv/bin/panoptes-gui|" packaging/linux/panoptes.desktop > "$APPS/panoptes.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

echo "Downloading site databases (one time, refreshed weekly)..."
"$PREFIX/venv/bin/panoptes" update || echo "Site database download failed - run 'panoptes update' later."

echo
echo "Panoptes is installed."
echo "  Terminal:     panoptes search <username | email | phone | name | domain | ip | file>"
[ -n "$EXTRAS" ] && echo "  Desktop app:  panoptes-gui (or find Panoptes in your applications menu)"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo; echo "Note: $BIN is not on your PATH. Add this line to ~/.bashrc or ~/.profile:"
     echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
if [ -n "$EXTRAS" ]; then
  echo
  echo "If the desktop app won't start with a Qt 'xcb' error, install the missing library:"
  echo "  sudo apt install libxcb-cursor0     (Debian / Ubuntu)"
fi
