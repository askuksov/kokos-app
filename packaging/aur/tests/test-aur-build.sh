#!/usr/bin/env bash
# Builds the kokos-bin package from the committed recipe in a throwaway Arch
# container, installs it, and checks what landed. This is the gate that proves
# the dependency names resolve against live Arch repositories — nothing on the
# development Mac can prove that.
#
# Usage: test-aur-build.sh [--no-url-check] <path to the kokos .deb>
#
# amd64 Linux + Docker only. On the dev Mac an emulated Arch container is too
# slow to be a gate and pacman -Syu against it is unreliable, so the script
# refuses rather than pretending.
set -euo pipefail

# Checked before anything else, including argument parsing: nothing past this
# point can run on a host that fails this check, so a missing argument or a
# bad path on such a host should not be reported as this script's own defect
# — the host is why it cannot run, not the invocation.
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "SKIP: this test needs amd64 Linux with Docker (host is $(uname -s)/$(uname -m))."
  echo "      Run it on an amd64 Linux host with Docker."
  exit 2
fi

AUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PKGBUILD="$AUR_DIR/PKGBUILD"

NO_URL_CHECK=0
DEB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-url-check) NO_URL_CHECK=1 ;;
    -*) echo "FAIL: unknown option $1"; exit 1 ;;
    *)  [ -z "$DEB" ] || { echo "FAIL: unexpected extra argument $1"; exit 1; }
        DEB="$1" ;;
  esac
  shift
done
[ -n "$DEB" ] || { echo "usage: test-aur-build.sh [--no-url-check] <path to the kokos .deb>" >&2; exit 1; }

[ -f "$PKGBUILD" ] || { echo "FAIL: no PKGBUILD at $PKGBUILD"; exit 1; }
[ -f "$DEB" ]      || { echo "FAIL: no such file: $DEB"; exit 1; }
command -v docker >/dev/null || { echo "FAIL: docker not found"; exit 1; }

# shellcheck disable=SC1090
source "$PKGBUILD"
LOCAL_NAME="kokos-${pkgver}.deb"

# The recipe must already be pointed at this exact artifact. A stale placeholder
# checksum — or one left over from preparing a DIFFERENT .deb — would make the
# main build below fail integrity on the GOOD artifact too, for a reason that
# has nothing to do with what this test checks, with no hint why. Comparing
# against the artifact's real digest (rather than just rejecting all-zeros)
# also catches the "prepared for the wrong .deb" mistake, which is the likelier
# one once real releases start.
sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
deb_sum=$(sha256_of "$DEB")
recipe_sum="${sha256sums[0]:-}"
[ "$recipe_sum" = "$deb_sum" ] || {
  echo "FAIL: PKGBUILD's sha256sums ($recipe_sum) does not match $DEB's sha256 ($deb_sum)."
  echo "      The recipe has not been pointed at this artifact yet — run:"
  echo "      $AUR_DIR/prepare-release.sh $DEB"
  exit 1
}

# The download URL is the one artifact-identity field nothing else here gates:
# the local-copy bypass below means makepkg in this test never downloads, so a
# wrong URL (e.g. a casing mismatch against what the pool actually published)
# would otherwise sail through every check in this file. --no-url-check exists
# for synthetic fixtures (packaging/repo/tests/make-fixture.sh) that are never
# published to R2 under this name, so there is nothing real to fetch.
if [ "$NO_URL_CHECK" -eq 1 ]; then
  echo "NOTE: --no-url-check set — skipping the source-URL fetch (fixture run)."
else
  command -v curl >/dev/null || { echo "FAIL: curl not found"; exit 1; }
  url="${source[0]#*::}"
  url_tmp=$(mktemp)
  if curl -fsSL -o "$url_tmp" "$url"; then
    url_sum=$(sha256_of "$url_tmp")
    rm -f "$url_tmp"
    [ "$url_sum" = "$deb_sum" ] || {
      echo "FAIL: the URL in PKGBUILD's source= does not serve the artifact under test."
      echo "      url:      $url"
      echo "      expected: $deb_sum ($DEB)"
      echo "      got:      $url_sum (downloaded from the URL above)"
      exit 1
    }
    echo "PASS: source URL resolves to the artifact under test"
  else
    rc=$?
    rm -f "$url_tmp"
    echo "FAIL: the URL in PKGBUILD's source= is unreachable (curl exit $rc)."
    echo "      url:      $url"
    echo "      expected: $deb_sum ($DEB); got: nothing — the download failed"
    exit 1
  fi
fi

WORK=$(mktemp -d)
GOOD_LOG=$(mktemp)
trap 'rm -rf "$WORK"; rm -f "$GOOD_LOG"' EXIT
cp "$PKGBUILD" "$WORK/PKGBUILD"
cp "$DEB" "$WORK/$LOCAL_NAME"

run_build() {                       # $1 = build dir, echoes container output
  docker run --rm --platform linux/amd64 -v "$1":/build archlinux bash -c '
set -e
pacman -Syu --noconfirm --needed base-devel sudo >/dev/null
useradd -m builder
echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
cp /build/PKGBUILD /build/*.deb /home/builder/
chown -R builder /home/builder
su builder -c "cd /home/builder && makepkg -sf --noconfirm"
pacman -U --noconfirm /home/builder/kokos-bin-*.pkg.tar.zst

fail=0
command -v kokos >/dev/null || { echo "FAIL: no kokos command on PATH"; fail=1; }
[ -x /usr/bin/kokos-nmh ] || { echo "FAIL: /usr/bin/kokos-nmh missing or not executable"; fail=1; }

desktop=$(find /usr/share/applications -iname "*kokos*" | head -1)
if [ -n "$desktop" ]; then
  exec_cmd=$(grep -m1 "^Exec=" "$desktop" | cut -d= -f2 | cut -d" " -f1)
  command -v "$exec_cmd" >/dev/null || { echo "FAIL: .desktop Exec=$exec_cmd does not resolve"; fail=1; }
else
  echo "NOTE: no .desktop entry in the payload"
fi

find /usr/share/icons/hicolor -iname "*kokos*" | head -1 | grep -q . \
  || echo "NOTE: no hicolor icon in the payload"
[ -f /usr/share/licenses/kokos-bin/LICENSE ] \
  || echo "NOTE: no licence file — the deb carried no usr/share/doc/*/copyright"

pacman -Qi kokos-bin | grep -q "webkit2gtk-4.1" || { echo "FAIL: webkit2gtk-4.1 absent from the installed depends"; fail=1; }
exit "$fail"
'
}

echo "=== build + install ==="
if run_build "$WORK" >"$GOOD_LOG" 2>&1; then
  cat "$GOOD_LOG"
else
  echo "FAIL: the package did not build and install cleanly"
  echo "--- container log ---"
  cat "$GOOD_LOG"
  exit 1
fi

# NOTE only, never a hard failure: this is a sanity check on the local-copy
# bypass that makes this whole test possible (test-pkgbuild.sh pins LOCAL_NAME
# == the recipe's local source name, so makepkg finds the artifact here
# instead of downloading it). The exact wording makepkg uses is unverified
# without a live Arch host — item 4 of the amd64 checklist settles it.
if grep -q "Found $LOCAL_NAME" "$GOOD_LOG"; then
  echo "NOTE: log confirms makepkg found $LOCAL_NAME locally, as expected."
else
  echo "NOTE: could not confirm from the log that makepkg used the local"
  echo "      $LOCAL_NAME instead of downloading; item 4 of the amd64"
  echo "      checklist settles it against a live Arch host."
fi

# Counterfactual: the recorded checksum has to be what actually rejects a
# tampered download. Without this, a green run above proves only that some
# file was unpacked.
echo "=== counterfactual: corrupt the artifact, makepkg must refuse ==="
BAD=$(mktemp -d)
BAD_LOG=$(mktemp)
trap 'rm -rf "$WORK" "$BAD"; rm -f "$BAD_LOG" "$GOOD_LOG"' EXIT
cp "$PKGBUILD" "$BAD/PKGBUILD"
cp "$DEB" "$BAD/$LOCAL_NAME"
printf 'tampered' >> "$BAD/$LOCAL_NAME"
# The log is kept (not /dev/null) so a failure here is diagnosed rather than
# taken on faith: a non-zero exit alone would equally follow from a Docker or
# network hiccup, which would falsely "confirm" that sha256sums is enforcing
# anything.
if run_build "$BAD" >"$BAD_LOG" 2>&1; then
  echo "FAIL: a tampered .deb still built — the sha256sums line is not enforcing anything"
  echo "--- container log ---"
  cat "$BAD_LOG"
  exit 1
fi

# A non-zero exit alone is not proof of anything: a transient Docker pull or a
# flaky pacman mirror fails the build too, without ever touching the checksum.
# Only count this as a pass if the log shows makepkg actually reached source
# validation — match the stage banner it prints unconditionally, before the
# result is known, rather than the rejection wording, so a wording change on
# either side still lands. Exact makepkg wording is unverified without a live
# Arch host, which is why the match stays broad and a miss is treated as
# inconclusive rather than assumed to be a pass.
if grep -qiE "validating source files|validity check|checksum" "$BAD_LOG"; then
  echo "PASS: tampered artifact rejected (makepkg reached source validation and refused it)"
  echo "NOTE: the match above is best-effort — makepkg's exact wording is unverified"
  echo "      without a live Arch host."
else
  echo "FAIL: counterfactual inconclusive — the tampered build failed before makepkg"
  echo "      reached source validation, so this proves nothing about sha256sums."
  echo "      Last 20 lines of the container log:"
  tail -20 "$BAD_LOG"
  exit 1
fi

echo "PASS: kokos-bin builds, installs and validates"
