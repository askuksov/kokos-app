#!/usr/bin/env bash
# Exercises prepare-release.sh against a fixture .deb built on the host.
# Needs dpkg-deb (brew install dpkg). Does not need Docker: every case passes
# --skip-srcinfo, because .SRCINFO generation is Arch-only.
set -euo pipefail

AUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd "$AUR_DIR/../.." && pwd)
SCRIPT="$AUR_DIR/prepare-release.sh"
CONF="$REPO_ROOT/src-tauri/tauri.conf.json"

[ -x "$SCRIPT" ] || { echo "FAIL: no executable $SCRIPT"; exit 1; }
command -v dpkg-deb >/dev/null || { echo "FAIL: dpkg-deb not found (brew install dpkg)"; exit 1; }

CONF_VER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$CONF")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Build a minimal .deb carrying the given Version, named like the real bundle.
make_deb() {
  local ver="$1"
  local out="$2"
  local root="$WORK/root-$ver"
  rm -rf "$root"
  mkdir -p "$root/DEBIAN" "$root/usr/bin"
  printf '#!/bin/sh\necho kokos fixture\n' > "$root/usr/bin/kokos"
  chmod 755 "$root/usr/bin/kokos"
  cat > "$root/DEBIAN/control" <<EOF
Package: kokos
Version: $ver
Architecture: amd64
Maintainer: Oleksandr Kuksov <packages@kuksov.dev>
Description: Kokos password manager (fixture)
 Synthetic package used to exercise the AUR release script.
EOF
  dpkg-deb --build --root-owner-group "$root" "$out" >/dev/null
}

fresh_pkgbuild() {                 # an isolated copy the script may rewrite
  local dir="$WORK/aur-$1"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$AUR_DIR/PKGBUILD" "$dir/PKGBUILD"
  echo "$dir"
}

fail=0
note() { echo "FAIL: $1"; fail=1; }

# --- case 1: happy path -------------------------------------------------
DIR=$(fresh_pkgbuild happy)
DEB="$WORK/Kokos_${CONF_VER}_amd64.deb"
make_deb "$CONF_VER" "$DEB"
if AUR_DIR="$DIR" "$SCRIPT" --skip-srcinfo "$DEB" >"$WORK/out1" 2>&1; then
  # shellcheck disable=SC1090
  ( source "$DIR/PKGBUILD"
    [ "$pkgver" = "$CONF_VER" ]                  || { echo "pkgver=$pkgver"; exit 1; }
    [ "$_debfile" = "$(basename "$DEB")" ]       || { echo "_debfile=$_debfile"; exit 1; }
    [ "${sha256sums[0]}" = "$(sha256_of "$DEB")" ] || { echo "sha=${sha256sums[0]}"; exit 1; }
  ) || note "happy path wrote wrong values (see above)"
else
  note "happy path exited non-zero: $(cat "$WORK/out1")"
fi

# --- case 2: version mismatch must abort and change nothing -------------
DIR=$(fresh_pkgbuild mismatch)
BEFORE=$(sha256_of "$DIR/PKGBUILD")
BADDEB="$WORK/Kokos_9.9.9_amd64.deb"
make_deb 9.9.9 "$BADDEB"
if AUR_DIR="$DIR" "$SCRIPT" --skip-srcinfo "$BADDEB" >"$WORK/out2" 2>&1; then
  note "version mismatch exited 0"
else
  grep -q "9.9.9" "$WORK/out2" || note "mismatch message does not name the deb's version"
  [ "$(sha256_of "$DIR/PKGBUILD")" = "$BEFORE" ] || note "PKGBUILD was modified despite the mismatch"
fi

# --- case 3: missing file must diagnose, not crash ----------------------
DIR=$(fresh_pkgbuild missing)
if AUR_DIR="$DIR" "$SCRIPT" --skip-srcinfo "$WORK/nope.deb" >"$WORK/out3" 2>&1; then
  note "missing .deb exited 0"
else
  grep -qi "no such file" "$WORK/out3" || note "missing .deb produced no readable message: $(cat "$WORK/out3")"
fi

# --- case 4: the flag parses after the positional argument --------------
DIR=$(fresh_pkgbuild flagorder)
AUR_DIR="$DIR" "$SCRIPT" "$DEB" --skip-srcinfo >"$WORK/out4" 2>&1 \
  || note "flag after the path was not accepted: $(cat "$WORK/out4")"

# --- case 5: sed drift on a line anchor leaves original untouched --------
# This test ensures that if a PKGBUILD line is renamed or indented, sed fails
# silently, but the verification detects it and aborts BEFORE replacing the file.
DIR=$(fresh_pkgbuild driftdetect)
# Break the _debfile anchor by renaming the variable; sed will not match it.
sed -i -e 's|^_debfile=|_debfileX=|' "$DIR/PKGBUILD"
BEFORE=$(sha256_of "$DIR/PKGBUILD")  # Save hash of the broken file
if AUR_DIR="$DIR" "$SCRIPT" --skip-srcinfo "$DEB" >"$WORK/out5" 2>&1; then
  note "drift-detect exited 0 despite broken anchor"
else
  grep -qE "(_debfile did not take|_debfile.*unbound variable)" "$WORK/out5" || note "drift-detect did not identify the broken field: $(tail -1 "$WORK/out5")"
  [ "$(sha256_of "$DIR/PKGBUILD")" = "$BEFORE" ] || note "PKGBUILD was modified despite verification failure; before=$BEFORE after=$(sha256_of "$DIR/PKGBUILD")"
fi

[ "$fail" -eq 0 ] && echo "PASS: prepare-release.sh"
exit "$fail"
