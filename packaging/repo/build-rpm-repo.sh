#!/usr/bin/env bash
# Builds the dnf repository metadata. Container-side: no key is touched.
# The .rpm files must already be signed — createrepo_c hashes them as they are.
set -euo pipefail

BUNDLE_DIR="${1:?usage: build-rpm-repo.sh <bundle-dir> <repo-root>}"
REPO_ROOT="${2:?usage: build-rpm-repo.sh <bundle-dir> <repo-root>}"

ARCH_DIR="$REPO_ROOT/rpm/stable/x86_64"
mkdir -p "$ARCH_DIR"

find "$BUNDLE_DIR" -name '*.rpm' -exec cp -f {} "$ARCH_DIR/" \;
ls "$ARCH_DIR"/*.rpm >/dev/null || { echo "FAIL: no .rpm copied"; exit 1; }

createrepo_c --general-compress-type=gz "$ARCH_DIR"

# The .repo file a user installs has to point at wherever this repository is
# actually being served, so the host is substituted rather than copied. The
# default reproduces the published file byte for byte; the end-to-end test
# sets KOKOS_REPO_URL to its local server, without which it would drop a file
# naming the production host into the container and test nothing it built.
# apt needs no equivalent — e2e-install.sh composes its sources.list line from
# the same variable directly.
SERVE_URL="${KOKOS_REPO_URL:-https://packages.kuksov.dev}"
sed "s|https://packages\.kuksov\.dev|$SERVE_URL|g" \
  "$(dirname "$0")/kokos.repo" > "$REPO_ROOT/rpm/kokos.repo"

echo "built dnf metadata at $ARCH_DIR"
