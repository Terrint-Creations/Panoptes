#!/bin/sh
# Adds the ready-to-run Panoptes to your applications menu and puts the `panoptes` and `panoptes-gui`
# commands in ~/.local/bin. Panoptes keeps running from this folder, so keep it somewhere permanent.
#
#   ./install.sh              add menu entry and commands
#   ./install.sh --uninstall  remove them again (this folder and your cases in ~/.panoptes are kept)
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$BIN/panoptes" "$BIN/panoptes-gui" "$APPS/panoptes.desktop" "$ICONS/panoptes.svg"
  echo "Removed the Panoptes menu entry and commands."
  exit 0
fi

mkdir -p "$BIN" "$APPS" "$ICONS"
ln -sf "$HERE/panoptes" "$BIN/panoptes"
ln -sf "$HERE/panoptes-gui" "$BIN/panoptes-gui"
cp "$HERE/panoptes.svg" "$ICONS/panoptes.svg"
sed "s|@@EXEC@@|$HERE/panoptes-gui|" "$HERE/panoptes.desktop" > "$APPS/panoptes.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" >/dev/null 2>&1 || true

echo "Panoptes is in your applications menu."
echo "  Desktop app:  panoptes-gui"
echo "  Terminal:     panoptes search <username | email | phone | name | domain | ip | file>"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo; echo "Note: $BIN is not on your PATH. Add this to ~/.bashrc or ~/.profile:"
     echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
