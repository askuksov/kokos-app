#!/usr/bin/env bash
# Exercises the built apt repo with a real apt client over file://, both the
# supported distro (must install) and the floor distro (must refuse).
set -euo pipefail

REPO_ROOT="${1:?usage: test-apt-repo.sh <repo-root>}"
REPO_ABS=$(cd "$REPO_ROOT" && pwd)

run_in() {  # run_in <image> <script>
  # --platform is mandatory: the dev host is arm64 and these are amd64 packages.
  docker run --rm --platform linux/amd64 -v "$REPO_ABS":/repo:ro \
    -e DEBIAN_FRONTEND=noninteractive "$1" bash -c "$2"
}

SETUP='set -e
  apt-get update -qq >/dev/null 2>&1 || true
  cp /repo/kokos-archive-keyring.gpg /usr/share/keyrings/kokos.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/kokos.gpg] file:///repo/deb stable main" \
    > /etc/apt/sources.list.d/kokos.list
  apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/kokos.list \
                 -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0'

echo "== ubuntu:24.04 must install =="
run_in ubuntu:24.04 "$SETUP
  apt-get install -y --no-install-recommends -o APT::Get::Fix-Missing=0 kokos
  dpkg -s kokos | grep -q '^Status: install ok installed'
  test -x /usr/bin/kokos
  echo OK-2404"

echo "== ubuntu:22.04 must refuse (glibc floor) =="
if run_in ubuntu:22.04 "$SETUP
  apt-get install -y kokos" >/tmp/kokos-2204.log 2>&1; then
  echo "FAIL: 22.04 installed kokos — the floor is not being enforced"
  exit 1
fi
grep -qiE 'unmet dependencies|not installable|no installation candidate' /tmp/kokos-2204.log || {
  echo "FAIL: 22.04 failed for the wrong reason:"; tail -20 /tmp/kokos-2204.log; exit 1; }
echo "OK-2204 (refused as expected)"

echo "PASS: apt repo verified"
