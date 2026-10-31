#!/usr/bin/env bash
# The gate: install from the LIVE repository exactly as a user would.
# This is the only run that exercises the URL layout, the CDN headers, the
# upload order and the signature chain together.
set -euo pipefail

BASE="${KOKOS_REPO_URL:-https://packages.kuksov.dev}"
PKG="${1:-kokos}"

echo "== ubuntu:24.04 =="
docker run --rm --platform linux/amd64 -e DEBIAN_FRONTEND=noninteractive ubuntu:24.04 bash -c "
set -e
apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null
curl -fsSL $BASE/kokos-archive-keyring.gpg -o /usr/share/keyrings/kokos.gpg
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/kokos.gpg] $BASE/deb stable main' \
  > /etc/apt/sources.list.d/kokos.list
apt-get update -qq
apt-get install -y --no-install-recommends kokos
dpkg -s kokos | grep -q '^Status: install ok installed'
echo OK-2404"

echo "== ubuntu:22.04 must refuse =="
if docker run --rm --platform linux/amd64 -e DEBIAN_FRONTEND=noninteractive ubuntu:22.04 bash -c "
set -e
apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null
curl -fsSL $BASE/kokos-archive-keyring.gpg -o /usr/share/keyrings/kokos.gpg
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/kokos.gpg] $BASE/deb stable main' \
  > /etc/apt/sources.list.d/kokos.list
apt-get update -qq && apt-get install -y kokos" >/tmp/kokos-live-2204.log 2>&1; then
  echo "FAIL: 22.04 installed from the live repo"; exit 1
fi
grep -qiE 'unmet dependencies|not installable|no installation candidate' /tmp/kokos-live-2204.log || {
  echo "FAIL: 22.04 failed for the wrong reason:"; tail -20 /tmp/kokos-live-2204.log; exit 1; }
echo "OK-2204 (refused)"

echo "== fedora:40 =="
docker run --rm --platform linux/amd64 fedora:40 bash -c "
set -e
curl -fsSL $BASE/rpm/kokos.repo -o /etc/yum.repos.d/kokos.repo
rpm --import $BASE/kokos-archive-keyring.asc
dnf -y --disablerepo='*' --enablerepo=kokos --enablerepo=fedora --enablerepo=updates install $PKG
rpm -q $PKG
echo OK-fedora40"

echo "PASS: live install verified on all three targets"
