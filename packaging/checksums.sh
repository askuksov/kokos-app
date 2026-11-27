#!/usr/bin/env bash
# Collect the release artifacts into one directory and write SHA256SUMS.
#
# Users download these over plain HTTPS from a web page; without a digest they
# have no way to tell a real build from a substituted one, and for a password
# manager a substituted build is a total compromise. The digest file is the
# floor. Signing it is what actually makes it trustworthy — a SHA256SUMS served
# from the same host an attacker just replaced the binary on proves nothing —
# so sign the result (see below) before publishing.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET_DIR=${TARGET_DIR:-$REPO_ROOT/target/release}
OUT=${OUT:-$REPO_ROOT/dist-release}

mkdir -p "$OUT"
# Drop what an earlier run left behind: OUT may be reused, and everything in it
# would otherwise end up in the new digest list. Only the artifact types and the
# digest files are touched; anything else in OUT stays.
rm -f -- "$OUT"/*.deb "$OUT"/*.rpm "$OUT"/*.AppImage "$OUT"/*.snap \
  "$OUT"/SHA256SUMS "$OUT"/SHA256SUMS.asc

# nullglob: a pattern with no match expands to nothing, not to itself, so a
# build that produced only some of the package types still works.
shopt -s nullglob
copied=()
for f in \
  "$TARGET_DIR"/bundle/deb/*.deb \
  "$TARGET_DIR"/bundle/rpm/*.rpm \
  "$TARGET_DIR"/bundle/appimage/*.AppImage \
  "$REPO_ROOT"/packaging/snap/*.snap
do
  [ -f "$f" ] || continue
  cp -f -- "$f" "$OUT/"
  copied+=("$(basename -- "$f")")
done
shopt -u nullglob
[ "${#copied[@]}" -gt 0 ] || { echo "no artifacts found — build first" >&2; exit 1; }

# Hash basenames, not paths, so the file verifies with a plain
# `sha256sum -c SHA256SUMS` in whatever directory the user downloaded into.
# The list is the files copied above, never a glob over OUT.
(cd "$OUT" && sha256sum -- "${copied[@]}" > SHA256SUMS)

echo "wrote $OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"
cat <<'NEXT'

Next, sign it — an unsigned digest list only detects corruption, not tampering:

    gpg --armor --detach-sign SHA256SUMS      # produces SHA256SUMS.asc

Publish SHA256SUMS, SHA256SUMS.asc and your public key, and tell users:

    gpg --verify SHA256SUMS.asc SHA256SUMS
    sha256sum -c SHA256SUMS
NEXT
