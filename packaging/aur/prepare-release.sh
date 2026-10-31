#!/usr/bin/env bash
# Points the AUR recipe at one specific .deb: writes pkgver, _debfile and
# sha256sums into PKGBUILD, then regenerates .SRCINFO.
#
# Usage: prepare-release.sh [--skip-srcinfo] <path to the kokos .deb>
#
# The .deb must already be the artifact you are publishing: its Version has to
# agree with src-tauri/tauri.conf.json, and the sha256 recorded here is what
# every AUR user's makepkg will verify the download against.
set -euo pipefail

SKIP_SRCINFO=0
DEB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-srcinfo) SKIP_SRCINFO=1 ;;
    -h|--help) echo "usage: prepare-release.sh [--skip-srcinfo] <deb>"; exit 0 ;;
    -*) echo "FAIL: unknown option $1"; exit 1 ;;
    *)  [ -z "$DEB" ] || { echo "FAIL: unexpected extra argument $1"; exit 1; }
        DEB="$1" ;;
  esac
  shift
done

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
AUR_DIR="${AUR_DIR:-$HERE}"
PKGBUILD="$AUR_DIR/PKGBUILD"
CONF="$REPO_ROOT/src-tauri/tauri.conf.json"

[ -n "$DEB" ]      || { echo "FAIL: usage: prepare-release.sh [--skip-srcinfo] <deb>"; exit 1; }
[ -f "$DEB" ]      || { echo "FAIL: no such file: $DEB"; exit 1; }
[ -f "$PKGBUILD" ] || { echo "FAIL: no PKGBUILD at $PKGBUILD"; exit 1; }
[ -f "$CONF" ]     || { echo "FAIL: no tauri.conf.json at $CONF"; exit 1; }
command -v dpkg-deb >/dev/null || { echo "FAIL: dpkg-deb not found (brew install dpkg)"; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

conf_ver=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$CONF")
deb_ver=$(dpkg-deb -f "$DEB" Version)
[ "$conf_ver" = "$deb_ver" ] || {
  echo "FAIL: version disagreement — tauri.conf.json says $conf_ver, $(basename "$DEB") says $deb_ver"
  echo "      rebuild the bundle, or fix the version, but do not publish these two together"
  exit 1
}

deb_name=$(basename "$DEB")
sum=$(sha256_of "$DEB")

# Write PKGBUILD to a temp file, and (below) .SRCINFO to a temp file too.
# Neither replaces the real file until every check on both has passed —
# including .SRCINFO generation — so an error anywhere below can never leave
# PKGBUILD half-written, or PKGBUILD and .SRCINFO out of sync with each other.
tmp=$(mktemp)
sed -e "s|^pkgver=.*|pkgver=$conf_ver|" \
    -e "s|^_debfile=.*|_debfile=\"$deb_name\"|" \
    -e "s|^sha256sums=.*|sha256sums=('$sum')|" \
    "$PKGBUILD" > "$tmp"

# Read back rather than trust the sed: a renamed variable would otherwise fail
# silently and ship a stale checksum. Check the temp file BEFORE it replaces
# the recipe, so a failed check leaves the original in place.
# shellcheck disable=SC1090
( source "$tmp"
  [ "$pkgver" = "$conf_ver" ]  || { echo "FAIL: pkgver did not take"; exit 1; }
  [ "$_debfile" = "$deb_name" ] || { echo "FAIL: _debfile did not take"; exit 1; }
  [ "${sha256sums[0]}" = "$sum" ] || { echo "FAIL: sha256sums did not take"; exit 1; }
)

if [ "$SKIP_SRCINFO" -eq 1 ]; then
  mv "$tmp" "$PKGBUILD"
  echo "pkgver=$conf_ver"
  echo "_debfile=$deb_name"
  echo "sha256sums=$sum"
  echo "NOTE: .SRCINFO not regenerated (--skip-srcinfo); it now disagrees with"
  echo "      the updated PKGBUILD. AUR's push hook only checks that .SRCINFO"
  echo "      is well-formed and that its pkgbase matches the repo name — it"
  echo "      does NOT check agreement with PKGBUILD, so a stale file is"
  echo "      accepted and silently stops existing users from being offered"
  echo "      this update. Regenerate it before pushing; test-pkgbuild.sh's"
  echo "      consistency check catches a forgotten regeneration."
  exit 0
fi

command -v docker >/dev/null || {
  echo "FAIL: docker is required to regenerate .SRCINFO (makepkg is Arch-only)."
  echo "      Re-run with --skip-srcinfo and regenerate it on the Linux box."
  exit 1
}

# makepkg refuses to run as root, and mounting the candidate PKGBUILD read-only
# keeps the container from touching host file ownership. Mount $tmp — the
# not-yet-installed candidate — rather than the still-current PKGBUILD on
# disk, so .SRCINFO reflects the values this run computed, not the previous
# release's.
srcinfo_tmp=$(mktemp)
docker run --rm --platform linux/amd64 -v "$tmp":/pkg/PKGBUILD:ro archlinux bash -c '
set -e
useradd -m builder
install -o builder -m 644 /pkg/PKGBUILD /home/builder/PKGBUILD
su builder -c "cd /home/builder && makepkg --printsrcinfo"
' > "$srcinfo_tmp"

[ -s "$srcinfo_tmp" ] || { echo "FAIL: .SRCINFO came back empty"; exit 1; }
grep -q "^pkgbase = kokos-bin" "$srcinfo_tmp" || {
  echo "FAIL: .SRCINFO does not start with 'pkgbase = kokos-bin'"; exit 1; }

# Both files verified — move them into place together. Doing this only now,
# after the docker step and the two checks above, means a docker-less run (or
# one where .SRCINFO comes back malformed) leaves BOTH files untouched instead
# of updating PKGBUILD alone.
mv "$tmp" "$PKGBUILD"
mv "$srcinfo_tmp" "$AUR_DIR/.SRCINFO"

echo "pkgver=$conf_ver"
echo "_debfile=$deb_name"
echo "sha256sums=$sum"
echo "PASS: PKGBUILD and .SRCINFO updated for $conf_ver"
