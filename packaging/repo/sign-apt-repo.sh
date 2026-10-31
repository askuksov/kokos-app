#!/usr/bin/env bash
# Signs the apt Release file. Host-side: this is where the private key lives.
set -euo pipefail

REPO_ROOT="${1:?usage: sign-apt-repo.sh <repo-root>}"
KEY="${KOKOS_GPG_KEY:?set KOKOS_GPG_KEY to the signing key uid or id}"
DIST="$REPO_ROOT/deb/dists/stable"

[ -f "$DIST/Release" ] || { echo "FAIL: $DIST/Release missing — run build-apt-repo.sh first"; exit 1; }

# An ambiguous $KEY (e.g. a uid substring matching more than one key, or a
# uid shared by an old and a new key during rotation) makes gpg silently
# pick one secret key to sign with and say nothing about the others. That signature is what every future
# apt/dnf client trusts — refuse anything but exactly one matching secret key.
sec_count=$(gpg --list-secret-keys --with-colons "$KEY" 2>/dev/null | grep -c '^sec' || true)
[ "$sec_count" -eq 1 ] || {
  echo "FAIL: KOKOS_GPG_KEY='$KEY' matched $sec_count secret keys, expected exactly 1"; exit 1; }

rm -f "$DIST/InRelease" "$DIST/Release.gpg"
gpg --default-key "$KEY" --clearsign  -o "$DIST/InRelease"   "$DIST/Release"
gpg --default-key "$KEY" --detach-sign --armor -o "$DIST/Release.gpg" "$DIST/Release"

echo "signed $DIST/{InRelease,Release.gpg}"
