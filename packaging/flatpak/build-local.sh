#!/usr/bin/env bash
# Build + install Kokos as a Flatpak from binaries `tauri build` already
# produced. Deliberately avoids flatpak-builder: nothing is compiled inside
# the sandbox, we only lay out prebuilt files, so the core `flatpak build-*`
# commands are enough. That also keeps this working on hosts whose flatpak is
# too old to run a modern flatpak-builder (e.g. Ubuntu 20.04's 1.6.5).
#
# Why this exists at all: the .deb/.rpm/.AppImage inherit the build host's
# glibc (2.39 on Ubuntu 24.04) and will not start on an older distro. A
# Flatpak runs against org.gnome.Platform's own glibc instead, so the same
# binary runs on 20.04.
set -euo pipefail

APPID=dev.kuksov.kokos
RUNTIME_VERSION=47
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# Where `tauri build` left the binaries. Override for a container build that
# used a separate CARGO_TARGET_DIR.
TARGET_DIR=${TARGET_DIR:-$REPO_ROOT/target/release}
BUILD_DIR=${BUILD_DIR:-$(mktemp -d)/kokos-flatpak}
LOCAL_REPO=${LOCAL_REPO:-$REPO_ROOT/.flatpak-repo}

for f in kokos kokos-nmh; do
  [ -x "$TARGET_DIR/$f" ] || { echo "missing $TARGET_DIR/$f — run 'npm run tauri build' first" >&2; exit 1; }
done

flatpak info org.gnome.Platform//$RUNTIME_VERSION >/dev/null 2>&1 || \
  flatpak install --user -y flathub org.gnome.Platform//$RUNTIME_VERSION

rm -rf "$BUILD_DIR"
# Pass the Platform as the SDK too: nothing is compiled here, and requiring
# the (multi-GB) org.gnome.Sdk just to copy files in would be gratuitous.
flatpak build-init "$BUILD_DIR" "$APPID" org.gnome.Platform org.gnome.Platform $RUNTIME_VERSION

install -Dm755 "$TARGET_DIR/kokos"     "$BUILD_DIR/files/bin/kokos"
install -Dm755 "$TARGET_DIR/kokos-nmh" "$BUILD_DIR/files/bin/kokos-nmh"

# This build bypasses the Tauri bundler entirely (see the header comment), so
# bundle.resources and the deb/rpm `files` maps never reach a binary staged
# this way -- stage the licence documents by hand or the Flatpak ships neither.
install -Dm644 "$REPO_ROOT/LICENSE" "$BUILD_DIR/files/usr/share/doc/kokos/copyright"
install -Dm644 "$REPO_ROOT/THIRD-PARTY-NOTICES.md" "$BUILD_DIR/files/usr/share/doc/kokos/THIRD-PARTY-NOTICES.md"

# hicolor theme dir -> source file in src-tauri/icons. Spelled out rather than
# derived: Tauri names the 2x asset "128x128@2x.png" while the theme dir it
# belongs in is "256x256@2", so no string mangling maps one to the other.
while read -r dir src; do
  [ -f "$REPO_ROOT/src-tauri/icons/$src" ] || continue
  install -Dm644 "$REPO_ROOT/src-tauri/icons/$src" \
    "$BUILD_DIR/files/share/icons/hicolor/$dir/apps/$APPID.png"
done <<'ICONS'
32x32 32x32.png
64x64 64x64.png
128x128 128x128.png
256x256@2 128x128@2x.png
ICONS

install -Dm644 /dev/stdin "$BUILD_DIR/files/share/applications/$APPID.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Kokos
Comment=Local-first, encrypted password manager
Categories=Utility;Security;
Exec=kokos
Icon=$APPID
StartupWMClass=kokos
Terminal=false
DESKTOP

# --filesystem=home (not host): a vault may live anywhere under $HOME,
# including dot-directories, which is exactly what Snap's `home` interface
# cannot express. Network is needed for the opt-in HIBP check and Drive sync.
flatpak build-finish "$BUILD_DIR" \
  --command=kokos \
  --socket=x11 --socket=fallback-x11 --socket=wayland --share=ipc \
  --share=network --device=dri \
  --filesystem=home \
  --talk-name=org.freedesktop.secrets

flatpak build-export "$LOCAL_REPO" "$BUILD_DIR"
flatpak --user remote-add --if-not-exists --no-gpg-verify kokos-local "$LOCAL_REPO"
flatpak --user update -y "$APPID" 2>/dev/null || flatpak --user install -y kokos-local "$APPID"

echo
echo "Installed. Run with:  flatpak run $APPID"
