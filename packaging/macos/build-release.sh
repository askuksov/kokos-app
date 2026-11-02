#!/usr/bin/env bash
# Release build for macOS: Developer ID signature, notarization, stapled DMG.
#
# Usage (Apple Silicon Mac, clean checkout, from anywhere in the repo):
#   packaging/macos/build-release.sh                  # build and verify HEAD
#   packaging/macos/build-release.sh --upload v0.1.0  # HEAD must be the tag;
#                                                     # also attach the DMG to
#                                                     # that draft release
#
# Google Drive: the OAuth client secret is compiled into the app, so the build
# needs it from KOKOS_GDRIVE_CLIENT_SECRET or the gitignored
# src-tauri/.gdrive_client_secret. A release build without it is refused.
#
# Signing identity: the single "Developer ID Application" identity in the
# keychain, or APPLE_SIGNING_IDENTITY when there are several.
#
# Notarization uses a notarytool keychain profile, so no password is passed
# on a command line or kept in shell history. Create it once:
#   xcrun notarytool store-credentials kokos-notary \
#     --apple-id <apple-id> --team-id <team-id>
# (asks for an app-specific password). Another profile name can be given in
# KOKOS_NOTARY_PROFILE.
#
# Steps: sidecar → `tauri build --bundles app` (signed by Tauri) → notarize
# and staple the app → DMG → sign, notarize and staple the DMG → verify.
# The DMG is built here rather than by Tauri, because a Tauri DMG build
# re-bundles and re-signs the app, which would drop its stapled ticket.
#
# Output: target/release/bundle/macos-release/Kokos_<version>_aarch64.dmg
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
usage() { echo "usage: $0 [--upload vX.Y.Z]" >&2; exit 2; }

TAG=
case $# in
  0) ;;
  2) [ "$1" = --upload ] || usage; TAG=$2 ;;
  *) usage ;;
esac

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_ROOT"

[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "run this on an Apple Silicon Mac"
for tool in node npm cargo rustc xcrun codesign hdiutil spctl; do
  command -v "$tool" >/dev/null || die "$tool not found"
done
[ -z "$TAG" ] || command -v gh >/dev/null || die "gh not found (needed for --upload)"

# A release is built from exactly the committed tree.
[ -z "$(git status --porcelain)" ] || die "the working tree is not clean"
VERSION=$(node -p "require('./src-tauri/tauri.conf.json').version")
if [ -n "$TAG" ]; then
  [ "$TAG" = "v$VERSION" ] || die "tag $TAG does not match version $VERSION"
  git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "no local tag $TAG"
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "$TAG^{commit}")" ] || die "HEAD is not at $TAG"
  # The draft release is built from the tag on GitHub; it must be this commit
  # too. ls-remote patterns also match longer names ending in the tag, so
  # compare full ref names; prefer the peeled `^{}` commit of an annotated tag.
  remote=$(git ls-remote --tags origin | awk -v t="refs/tags/$TAG" \
    '$2 == t { c = $1 } $2 == t "^{}" { p = $1 } END { print (p != "" ? p : c) }')
  [ -n "$remote" ] || die "tag $TAG is not on origin"
  [ "$remote" = "$(git rev-parse HEAD)" ] || die "tag $TAG on origin points to $remote, not HEAD"
  [ "$(gh release view "$TAG" --json isDraft --jq .isDraft)" = true ] || die "release $TAG is not a draft"
fi

# The binary reads the secret as a compile-time value; the file fallback it also
# has only exists in a developer checkout, so a release must embed it here.
if [ -z "${KOKOS_GDRIVE_CLIENT_SECRET:-}" ]; then
  secret_file=src-tauri/.gdrive_client_secret
  [ -f "$secret_file" ] \
    || die "Google Drive client secret is missing: export KOKOS_GDRIVE_CLIENT_SECRET or write $secret_file"
  KOKOS_GDRIVE_CLIENT_SECRET=$(tr -d '\r\n' < "$secret_file")
fi
[ -n "$KOKOS_GDRIVE_CLIENT_SECRET" ] || die "KOKOS_GDRIVE_CLIENT_SECRET is empty"
export KOKOS_GDRIVE_CLIENT_SECRET

if [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
  ids=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | sort -u)
  [ -n "$ids" ] && [ "$(printf '%s\n' "$ids" | wc -l)" -eq 1 ] \
    || die "expected exactly one Developer ID Application identity; set APPLE_SIGNING_IDENTITY"
  APPLE_SIGNING_IDENTITY=$ids
fi
export APPLE_SIGNING_IDENTITY
echo "signing as: $APPLE_SIGNING_IDENTITY"

NOTARY_PROFILE=${KOKOS_NOTARY_PROFILE:-kokos-notary}
xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null \
  || die "notarytool profile '$NOTARY_PROFILE' is missing or invalid (see the header)"
# Tauri notarizes on its own when it sees these; here this script does it.
unset APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_PATH

json_field() { node -e 'const r=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(r[process.argv[1]]??""))' "$1"; }

notarize() {
  local out id status
  echo "notarizing $(basename "$1") (this takes a few minutes)"
  out=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json)
  id=$(json_field id <<<"$out")
  status=$(json_field status <<<"$out")
  if [ "$status" != Accepted ]; then
    echo "$out" >&2
    [ -z "$id" ] || xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" >&2 || true
    die "notarization of $(basename "$1") ended with status: ${status:-unknown}"
  fi
}

echo "== dependencies"
npm ci
cargo fetch --locked

echo "== native-messaging host"
cargo build --release --locked -p kokos-nmh
triple=$(rustc -vV | sed -n 's/^host: //p')
cp target/release/kokos-nmh "src-tauri/binaries/kokos-nmh-$triple"

echo "== app bundle"
npm run tauri build -- --bundles app
APP=target/release/bundle/macos/Kokos.app
[ -d "$APP" ] || die "$APP was not produced"

codesign --verify --deep --strict --verbose=2 "$APP"
for bin in "$APP" "$APP/Contents/MacOS/kokos-nmh"; do
  info=$(codesign -dv --verbose=4 "$bin" 2>&1)
  grep -q '^Authority=Developer ID Application' <<<"$info" || die "$bin is not signed with a Developer ID"
  grep -q '^CodeDirectory.*flags=.*runtime' <<<"$info" || die "$bin lacks the hardened runtime"
  grep -q '^Timestamp=' <<<"$info" || die "$bin has no secure timestamp"
done

echo "== notarize the app"
zip=$(mktemp -d)/Kokos.zip
ditto -c -k --keepParent "$APP" "$zip"
notarize "$zip"
xcrun stapler staple "$APP"

echo "== disk image"
OUT=target/release/bundle/macos-release
DMG=$OUT/Kokos_${VERSION}_aarch64.dmg
mkdir -p "$OUT"
stage=$(mktemp -d)/Kokos
mkdir -p "$stage"
ditto "$APP" "$stage/Kokos.app"
ln -s /Applications "$stage/Applications"
hdiutil create -volname Kokos -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$DMG"
codesign --sign "$APPLE_SIGNING_IDENTITY" --timestamp "$DMG"
notarize "$DMG"
xcrun stapler staple "$DMG"

echo "== verify"
xcrun stapler validate "$APP"
xcrun stapler validate "$DMG"
gatekeeper() {
  local out
  out=$(spctl --assess --verbose=2 "$@" 2>&1) || { echo "$out" >&2; return 1; }
  echo "$out"
  grep -q 'source=Notarized Developer ID' <<<"$out"
}
gatekeeper --type execute "$APP" || die "Gatekeeper does not accept the app as notarized"
gatekeeper --type open --context context:primary-signature "$DMG" || die "Gatekeeper does not accept the DMG as notarized"
(cd "$OUT" && shasum -a 256 "$(basename "$DMG")")

if [ -n "$TAG" ]; then
  echo "== upload to the draft release $TAG"
  name=$(basename "$DMG")
  work=$(mktemp -d)
  gh release download "$TAG" --dir "$work"
  # Keep the release's SHA256SUMS locally: `--clobber` deletes the old asset
  # before uploading, so a failed upload would otherwise lose it. A rerun
  # after such a failure falls back to this copy.
  if [ -f "$work/SHA256SUMS" ]; then
    cp "$work/SHA256SUMS" "$OUT/SHA256SUMS.release"
  elif [ -f "$OUT/SHA256SUMS.release" ]; then
    echo "no SHA256SUMS in $TAG; using the copy kept by an earlier run"
  else
    die "no SHA256SUMS in $TAG"
  fi
  # Every other asset must still match the hashes the workflow wrote, so the
  # file the maintainer signs vouches only for what the workflow built.
  grep -v "  $name\$" "$OUT/SHA256SUMS.release" > "$work/retained" || true
  [ -s "$work/retained" ] || die "SHA256SUMS of $TAG lists no other assets"
  (cd "$work" && shasum -a 256 -c "$work/retained") || die "an asset of $TAG does not match SHA256SUMS"
  for f in "$work"/*; do
    base=$(basename "$f")
    case $base in SHA256SUMS|SHA256SUMS.asc|retained|"$name") continue ;; esac
    grep -q "  $base\$" "$work/retained" || die "$base is attached to $TAG but missing from SHA256SUMS"
  done
  { cat "$work/retained"; (cd "$OUT" && shasum -a 256 "$name"); } | sort -k2 > "$OUT/SHA256SUMS"
  gh release upload "$TAG" "$DMG" --clobber
  gh release upload "$TAG" "$OUT/SHA256SUMS" --clobber \
    || die "uploading SHA256SUMS failed; retry: gh release upload $TAG $OUT/SHA256SUMS --clobber"
  cat "$OUT/SHA256SUMS"
  cat <<NEXT

Uploaded $name and the updated SHA256SUMS. Sign it and upload the signature
before publishing (an older SHA256SUMS.asc, if any, is now stale):

    gpg --armor --detach-sign $OUT/SHA256SUMS
    gh release upload $TAG $OUT/SHA256SUMS.asc --clobber
NEXT
fi
