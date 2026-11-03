#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! python3 -c "import gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk" >/dev/null 2>&1; then
  echo "Il manque GTK / python3-gi."
  echo "Debian / Ubuntu / Parrot :"
  echo "  sudo apt install python3 python3-gi gir1.2-gtk-3.0 network-manager"
  exit 1
fi
BIN="$HOME/.local/bin"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
LAUNCHER="$BIN/wifi-acces"

mkdir -p "$BIN" "$APPS" "$ICONS"
chmod +x "$ROOT/wifi_acces.py"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 "$ROOT/wifi_acces.py" "\$@"
EOF
chmod +x "$LAUNCHER"
cp "$ROOT/assets/wifi-acces.svg" "$ICONS/wifi-acces.svg"

cat > "$APPS/wifi-acces.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Wi-Fi Accès
Comment=Voir qui est connecté à ton Wi-Fi et ouvrir la box
Exec=$LAUNCHER
Icon=wifi-acces
Path=$ROOT
Terminal=false
Categories=Network;Utility;
Keywords=wifi;reseau;box;appareils;
StartupNotify=true
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Logiciel installé."
echo "Cherche « Wi-Fi Accès » dans le menu, ou lance : wifi-acces"
