#!/usr/bin/env bash
# Uploads the staged repository to R2.
#
# Order is correctness, not speed: a client that runs `apt update` while we
# publish must never see an index that references a file we have not uploaded
# yet. Content first, index second, signed entry point last.
#
# Cache-Control is correctness too: a CDN that caches an index will serve a
# stale InRelease against a fresh Packages and every client sees a hash
# mismatch.
set -euo pipefail

# A stray or misplaced argument must be a hard error, never a silent no-op:
# --dry-run has to be recognised in any position, not just as $1, or a flag
# added defensively after the repo-root argument silently performs a real
# publish instead of the rehearsal it looks like.
DRY=0
REPO_ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    -*)        echo "FAIL: unknown option $1"; exit 1 ;;
    *)         [ -z "$REPO_ROOT" ] || { echo "FAIL: unexpected extra argument $1"; exit 1; }
               REPO_ROOT="$1" ;;
  esac
  shift
done
[ -n "$REPO_ROOT" ] || { echo "usage: publish.sh [--dry-run] <repo-root>"; exit 1; }
REMOTE="${KOKOS_R2_REMOTE:-r2:kokos-packages}"

IMMUTABLE='public, max-age=31536000, immutable'
REVALIDATE='public, max-age=0, must-revalidate'

put_file() {  # put_file <cache-class> <subpath relative to repo root>
  local class="$1" sub="$2" header
  [ "$class" = IMMUTABLE ] && header="$IMMUTABLE" || header="$REVALIDATE"
  echo "UPLOAD $class $sub"
  [ "$DRY" -eq 1 ] && return 0
  rclone copyto "$REPO_ROOT/$sub" "$REMOTE/$sub" \
    --header-upload "Cache-Control: $header" --s3-no-check-bucket
}

put_dir() {   # put_dir <cache-class> <subdir relative to repo root>
  local class="$1" sub="$2" header
  [ "$class" = IMMUTABLE ] && header="$IMMUTABLE" || header="$REVALIDATE"
  echo "UPLOAD $class $sub"
  [ "$DRY" -eq 1 ] && return 0
  rclone copy "$REPO_ROOT/$sub" "$REMOTE/$sub" \
    --header-upload "Cache-Control: $header" --s3-no-check-bucket
}

# A rebuilt-but-unsigned or rebuilt-but-not-re-signed repo root uploads
# cleanly today — createrepo_c and apt-ftparchive touch no key, and a stale
# repomd.xml.asc or InRelease is still a perfectly valid signature, just over
# content that no longer matches what is on disk now. dnf's repo_gpgcheck=1
# and apt's signed-by= only catch that on the CLIENT, after we have already
# published. Catch it here instead, before the first byte goes up, and run it
# whether or not this is a dry run — a dry run that "passes" against a broken
# tree is the whole bug this guards against.
require_signed() {
  local dist="$REPO_ROOT/deb/dists/stable"
  local md="$REPO_ROOT/rpm/stable/x86_64/repodata/repomd.xml"
  local f
  for f in "$dist/Release" "$dist/Release.gpg" "$dist/InRelease" "$md" "$md.asc"; do
    [ -f "$f" ] || { echo "FAIL: $f missing — build and sign before publishing"; exit 1; }
  done
  gpg --verify "$dist/Release.gpg" "$dist/Release" >/dev/null 2>&1 \
    || { echo "FAIL: Release.gpg does not verify against Release — re-run sign-apt-repo.sh"; exit 1; }
  # A clearsigned InRelease is a valid signature over whatever content it was
  # made from — that stays true after Release changes underneath it. Only a
  # byte-for-byte comparison against the CURRENT Release catches staleness;
  # `gpg --verify`-ing InRelease alone would just re-confirm the old content.
  gpg --decrypt "$dist/InRelease" 2>/dev/null | diff -q - "$dist/Release" >/dev/null \
    || { echo "FAIL: InRelease is stale — Release changed since signing; re-run sign-apt-repo.sh"; exit 1; }
  gpg --verify "$md.asc" "$md" >/dev/null 2>&1 \
    || { echo "FAIL: repomd.xml.asc does not verify against repomd.xml — re-run sign-rpm-repo.sh --metadata"; exit 1; }
}

require_signed

# 1. Content that the indexes will point at.
put_dir IMMUTABLE deb/pool
for f in "$REPO_ROOT"/rpm/stable/x86_64/*.rpm; do
  put_file IMMUTABLE "rpm/stable/x86_64/$(basename "$f")"
done

# 2. Keys — a first-time user cannot verify anything before these exist.
put_file REVALIDATE kokos-archive-keyring.gpg
put_file REVALIDATE kokos-archive-keyring.asc
put_file REVALIDATE rpm/kokos.repo

# 3. Indexes, and the repodata payload files that repomd.xml will name.
put_file REVALIDATE deb/dists/stable/main/binary-amd64/Packages
put_file REVALIDATE deb/dists/stable/main/binary-amd64/Packages.gz
put_file REVALIDATE deb/dists/stable/Release
for f in "$REPO_ROOT"/rpm/stable/x86_64/repodata/*; do
  case "$(basename "$f")" in repomd.xml|repomd.xml.asc) continue ;; esac
  put_file REVALIDATE "rpm/stable/x86_64/repodata/$(basename "$f")"
done

# 4. Signed entry points, last. A client reads these first, so they must be
#    the last thing to change — everything they reference is already up.
put_file REVALIDATE deb/dists/stable/Release.gpg
put_file REVALIDATE deb/dists/stable/InRelease
put_file REVALIDATE rpm/stable/x86_64/repodata/repomd.xml
put_file REVALIDATE rpm/stable/x86_64/repodata/repomd.xml.asc

echo "published to $REMOTE"
