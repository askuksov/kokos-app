#!/usr/bin/env bash
# Signs every .rpm in the bundle dir, then the repo metadata. Host-side.
# Usage: sign-rpm-repo.sh <bundle-dir>            # phase 1, before createrepo
#        sign-rpm-repo.sh --metadata <repo-root>  # phase 2, after createrepo
set -euo pipefail

KEY="${KOKOS_GPG_KEY:?set KOKOS_GPG_KEY to the signing key uid or id}"

# An ambiguous $KEY makes gpg pick a matching secret key silently, with no
# warning and exit 0 — and a key rotation
# deliberately puts two keys with the same uid in the keyring at once. Signing
# with the wrong one is a supply-chain failure, so demand exactly one match.
# Checked here, before either phase touches gpg: the --metadata branch below
# signs repomd.xml and exits 0 without ever reaching a guard placed further
# down, so a keyring mid-rotation could publish repomd.xml.asc signed by the
# key export-keyring.sh refuses to export.
sec_count=$(gpg --list-secret-keys --with-colons "$KEY" 2>/dev/null | grep -c '^sec' || true)
[ "$sec_count" -eq 1 ] || {
  echo "FAIL: KOKOS_GPG_KEY='$KEY' matched $sec_count secret keys, expected exactly 1"; exit 1; }

if [ "${1:-}" = "--metadata" ]; then
  REPO_ROOT="${2:?usage: sign-rpm-repo.sh --metadata <repo-root>}"
  MD="$REPO_ROOT/rpm/stable/x86_64/repodata/repomd.xml"
  [ -f "$MD" ] || { echo "FAIL: $MD missing — run build-rpm-repo.sh first"; exit 1; }
  rm -f "$MD.asc"
  gpg --default-key "$KEY" --detach-sign --armor -o "$MD.asc" "$MD"
  echo "signed $MD.asc"
  exit 0
fi

BUNDLE_DIR="${1:?usage: sign-rpm-repo.sh <bundle-dir>}"

# Ask rpm what it resolved rather than grepping a macro FILE: rpm 6.1.0 reads
# ~/.config/rpm/macros and does not look at ~/.rpmmacros at all, so a path-based
# check tests the wrong file on this host.
[ "$(rpm --eval '%{_gpg_name}')" != '%{_gpg_name}' ] || {
  echo "FAIL: rpm has no %_gpg_name configured"; exit 1; }

# Lowercase fingerprint of the signing key, to prove the signature that lands
# is OURS and not merely some signature.
FPR=$(gpg --fingerprint --with-colons "$KEY" | awk -F: '/^fpr:/{print tolower($10); exit}')
[ -n "$FPR" ] || { echo "FAIL: cannot resolve a fingerprint for $KEY"; exit 1; }

# The find|while loop below is the only signature check anywhere in the
# pipeline — build-rpm-repo.sh touches no key, and phase 2 signs repomd.xml
# without inspecting the packages it describes. A stale or mistyped
# BUNDLE_DIR must not let that loop iterate zero times and exit 0 silently,
# so fail explicitly on both an empty match and a missing directory. The
# -d check comes first: find on a missing directory prints its own raw
# "find: ... No such file or directory" and, under set -e, kills the script
# before the FAIL message below could run — handled the same way
# in packaging/repo/tests/test-metadata.sh. Placed after the
# key guards above so a bad key is still reported as a bad key.
[ -d "$BUNDLE_DIR" ] || { echo "FAIL: no such directory $BUNDLE_DIR"; exit 1; }

# `rpm --addsign` REWRITES each package, so its checksum changes. Run against
# a tree createrepo_c has already indexed, this phase leaves repomd.xml
# describing checksums that no longer exist, and the failure surfaces at the
# user's `dnf install` as "Package ... has incorrect checksum" — never in our
# build log. Nothing in the argument shape stops an operator from passing the
# repo root here (phase 2 takes exactly that), so refuse an indexed tree
# instead of silently invalidating it. Re-signing an already-signed package
# is byte-identical and therefore harmless, but that is not a property this
# script can check before it has already rewritten the file.
if find "$BUNDLE_DIR" -type d -name repodata -print -quit | grep -q .; then
  echo "FAIL: $BUNDLE_DIR already contains a repodata/ index."
  echo "      Sign packages BEFORE createrepo_c runs;"
  echo "      to re-sign an existing repo, sign the bundle dir and rebuild the"
  echo "      index with build-rpm-repo.sh, then sign-rpm-repo.sh --metadata."
  exit 1
fi

rpm_count=$(find "$BUNDLE_DIR" -name '*.rpm' | wc -l | tr -d ' ')
[ "$rpm_count" -gt 0 ] || { echo "FAIL: no .rpm found under $BUNDLE_DIR"; exit 1; }

find "$BUNDLE_DIR" -name '*.rpm' -print0 | while IFS= read -r -d '' f; do
  rpm --addsign "$f"
  # rpm -Kv's own exit status is nonzero for ANY non-clean verdict, including
  # the expected NOKEY case (signed, public key just not imported yet) — so
  # under `set -e` it must not be allowed to abort the script here. The case
  # statements below are what actually interpret the captured output; `||
  # true` only suppresses the premature exit, same idiom already used above
  # for `grep -c '^sec'`.
  out=$(rpm -Kv "$f" 2>&1) || true
  # rpm 6.1.0 prints one NOTFOUND line per signature ALGORITHM it did not
  # find (RSA, DSA, legacy variants) even on a package that IS validly
  # signed with EdDSA — confirmed by running this script against the
  # fixture, where a freshly addsign'd rpm still shows "Header OpenPGP RSA
  # signature: NOTFOUND" alongside the real "...EdDSA/SHA512 signature ...:
  # NOKEY" line. So "output contains NOTFOUND" is true in both the signed
  # and unsigned case on this host and cannot tell them apart. The real
  # signal is whether a signature verdict shows up at all (NOKEY = signed,
  # public key not imported; "key fingerprint" = signed and imported/OK).
  # Never match a bare "OK" for that: "NOKEY" contains "OK", and so do the
  # unrelated "Header/Payload SHA256 digest: OK" lines that are present
  # whether or not the package is GPG-signed.
  case "$out" in
    *NOKEY*|*"key fingerprint"*) ;;
    *) echo "FAIL: $f carries no signature"; echo "$out"; exit 1 ;;
  esac
  # In the NOKEY state (public key not imported into rpm's db — expected at
  # this point in the pipeline) rpm prints a truncated key ID rather than the
  # full fingerprint, and how much it truncates depends on the rpm version:
  # 4.18.2 on Ubuntu 24.04 prints the 8-hex short id ("key ID 076efe83"),
  # 6.1.0 prints 16. Both are the tail of $FPR, so accept either alongside
  # the full form, which only appears once the key is imported and rpm
  # reports OK. Eight hex digits alone would be weak provenance in general,
  # but the guard at the top of this script has already established that the
  # keyring holds exactly one matching secret key.
  case "$out" in
    *"$FPR"*|*"${FPR: -16}"*|*"${FPR: -8}"*) ;;
    *) echo "FAIL: $f is not signed by $FPR"; echo "$out"; exit 1 ;;
  esac
  echo "signed $f"
done
