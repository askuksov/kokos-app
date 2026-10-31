#!/usr/bin/env bash
# Exports the public signing key in both encodings package managers need:
#   .gpg  dearmored binary  -> apt's signed-by=/usr/share/keyrings/kokos.gpg
#   .asc  ASCII armored     -> dnf's gpgkey=
set -euo pipefail

REPO_ROOT="${1:?usage: export-keyring.sh <repo-root>}"
KEY="${KOKOS_GPG_KEY:?set KOKOS_GPG_KEY to the signing key uid or id}"

mkdir -p "$REPO_ROOT"

GPG_OUT="$REPO_ROOT/kokos-archive-keyring.gpg"
ASC_OUT="$REPO_ROOT/kokos-archive-keyring.asc"
# Export to a temp name in the same directory first, and `mv` into place only
# once the count check below passes. publish.sh uploads whatever sits at
# $GPG_OUT/$ASC_OUT with no check of its own, so a failed run must never have
# touched those paths — not even momentarily widen the trust root every
# user's apt/dnf accepts, and never clobber a good keyring already sitting
# there from a previous successful export. The leading dot keeps a leftover
# temp file (e.g. from a `kill -9`, which skips the trap below) out of every
# glob elsewhere in this pipeline.
TMP_GPG="$REPO_ROOT/.kokos-archive-keyring.gpg.tmp$$"
TMP_ASC="$REPO_ROOT/.kokos-archive-keyring.asc.tmp$$"
trap 'rm -f "$TMP_GPG" "$TMP_ASC"' EXIT

# The -- stops a $KEY shaped like a flag (e.g. "--version") from being read
# as gpg's own option instead of a key identifier.
gpg --export -- "$KEY" > "$TMP_GPG"
gpg --export --armor -- "$KEY" > "$TMP_ASC"

# A zero-length export is gpg's way of saying "no such key" — it exits 0.
[ -s "$TMP_GPG" ] || { echo "FAIL: empty keyring export"; exit 1; }
[ -s "$TMP_ASC" ] || { echo "FAIL: empty armored export"; exit 1; }

# An ambiguous $KEY (e.g. a uid substring matching more than one key) makes
# gpg --export concatenate every match into one blob. The -s checks above only
# catch empty output, not key count, so a widened trust root would otherwise
# pass silently — and this is the key apt/dnf will trust for every future
# update. Refuse anything but exactly one exported public key.
key_count=$(gpg --show-keys --with-colons "$TMP_GPG" | grep -c '^pub' || true)
[ "$key_count" -eq 1 ] || { echo "FAIL: KOKOS_GPG_KEY='$KEY' matched $key_count keys, expected exactly 1"; exit 1; }

mv -f "$TMP_GPG" "$GPG_OUT"
mv -f "$TMP_ASC" "$ASC_OUT"

echo "exported $KEY:"
gpg --show-keys "$GPG_OUT" | sed 's/^/  /'
