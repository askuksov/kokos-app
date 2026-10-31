#!/usr/bin/env bash
# Builds the unsigned apt repository tree. Container-side: no key is touched.
set -euo pipefail

BUNDLE_DIR="${1:?usage: build-apt-repo.sh <bundle-dir> <repo-root>}"
REPO_ROOT="${2:?usage: build-apt-repo.sh <bundle-dir> <repo-root>}"

DEB_ROOT="$REPO_ROOT/deb"
POOL="$DEB_ROOT/pool/main/k/kokos"
DIST="$DEB_ROOT/dists/stable"
BIN="$DIST/main/binary-amd64"

mkdir -p "$POOL" "$BIN"

find "$BUNDLE_DIR" -name '*.deb' -exec cp -f {} "$POOL/" \;
ls "$POOL"/*.deb >/dev/null || { echo "FAIL: no .deb copied into the pool"; exit 1; }

# Run from the deb root so Filename: comes out relative to the suite root
# (pool/main/k/kokos/...). An absolute Filename makes every client 404.
cd "$DEB_ROOT"
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -9cf dists/stable/main/binary-amd64/Packages > dists/stable/main/binary-amd64/Packages.gz
grep -q '^Filename: pool/' dists/stable/main/binary-amd64/Packages || {
  echo "FAIL: Packages has no relative Filename: entries"; exit 1; }

apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=Kokos \
  -o APT::FTPArchive::Release::Label=Kokos \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures=amd64 \
  -o APT::FTPArchive::Release::Components=main \
  -o APT::FTPArchive::Release::Description="Kokos password manager" \
  release dists/stable > dists/stable/Release

echo "built unsigned apt repo at $DEB_ROOT"
