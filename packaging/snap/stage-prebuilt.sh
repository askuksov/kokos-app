#!/usr/bin/env bash
# Lay out the files snapcraft.yaml's `dump` part expects, from binaries that
# `npm run tauri build` already produced. Run this before `snapcraft`.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE=$REPO_ROOT/packaging/snap
TARGET_DIR=${TARGET_DIR:-$REPO_ROOT/target/release}
OUT=$HERE/prebuilt

for f in kokos kokos-nmh; do
  [ -x "$TARGET_DIR/$f" ] || { echo "missing $TARGET_DIR/$f — run 'npm run tauri build' first" >&2; exit 1; }
done

rm -rf "$OUT"
install -Dm755 "$TARGET_DIR/kokos"     "$OUT/usr/bin/kokos"
install -Dm755 "$TARGET_DIR/kokos-nmh" "$OUT/usr/bin/kokos-nmh"

# This build bypasses the Tauri bundler entirely (see the header comment), so
# bundle.resources and the deb/rpm `files` maps never reach a binary staged
# this way -- stage the licence documents by hand or the snap ships neither.
install -Dm644 "$REPO_ROOT/LICENSE" "$OUT/usr/share/doc/kokos/copyright"
install -Dm644 "$REPO_ROOT/THIRD-PARTY-NOTICES.md" "$OUT/usr/share/doc/kokos/THIRD-PARTY-NOTICES.md"

while read -r dir src; do
  [ -f "$REPO_ROOT/src-tauri/icons/$src" ] || continue
  install -Dm644 "$REPO_ROOT/src-tauri/icons/$src" \
    "$OUT/usr/share/icons/hicolor/$dir/apps/kokos.png"
done <<'ICONS'
32x32 32x32.png
64x64 64x64.png
128x128 128x128.png
256x256@2 128x128@2x.png
ICONS

# Icon= is resolved by snapd against $SNAP, so it must be a path, not a
# theme name as in the Flatpak/deb desktop entry.
install -Dm644 /dev/stdin "$OUT/usr/share/applications/kokos.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Kokos
Comment=Local-first, encrypted password manager
Categories=Utility;Security;
Exec=kokos
Icon=${SNAP}/usr/share/icons/hicolor/128x128/apps/kokos.png
StartupWMClass=kokos
Terminal=false
DESKTOP

echo "staged into $OUT"
