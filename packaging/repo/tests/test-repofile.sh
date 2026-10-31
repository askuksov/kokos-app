#!/usr/bin/env bash
# Asserts the dnf repo definition users install is internally consistent, and
# — when a built repo root is given — that it points at THAT tree rather than
# at the production host. Pure string checking plus a few file existence
# checks; no network, no containers.
#
# Usage: test-repofile.sh [<repo-root>]
#
# Without an argument only the committed template is checked. With one, the
# rendered copy build-rpm-repo.sh wrote into <repo-root>/rpm/ is checked too.
#
# Why this exists: kokos.repo hardcodes absolute URLs, and the e2e's fedora
# arm downloads it FROM THE LOCAL SERVER. Before the KOKOS_REPO_URL
# substitution landed, dnf would have walked off to packages.kuksov.dev and
# tested something other than what was just built. Nothing checked the file
# itself, on either side of that fix.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEMPLATE="$HERE/../kokos.repo"
REPO_ROOT="${1:-}"

fail=0
note() { echo "FAIL: $1"; fail=1; }

value_of() { sed -n -E "s/^$2=(.*)\$/\1/p" "$1" | head -1; }
host_of() { printf '%s\n' "$1" | sed -E 's|^([a-z]+://[^/]+).*|\1|'; }

check_file() {
  local f=$1 label=$2
  [ -f "$f" ] || { note "$label: $f does not exist"; return; }

  # The section id is what `dnf --enablerepo=` and `--disablerepo=` name, and
  # README tells users to type `dnf install kokos`. Both are literals in
  # prose, so a rename here is invisible until a user's install fails.
  grep -qx '\[kokos\]' "$f" || note "$label: no [kokos] section header"

  local baseurl gpgkey
  baseurl=$(value_of "$f" baseurl)
  gpgkey=$(value_of "$f" gpgkey)
  [ -n "$baseurl" ] || note "$label: no baseurl"
  [ -n "$gpgkey" ] || note "$label: no gpgkey"

  # $basearch is expanded by dnf, so it must survive as a literal. A nested
  # container heredoc once turned it into \$basearch, which leaves metadata
  # reachable and breaks only the package download — a repository that looks
  # healthy until someone installs from it.
  case "$baseurl" in
    *'\$basearch'*) note "$label: baseurl has an escaped \\\$basearch: $baseurl" ;;
    */rpm/stable/'$basearch') ;;
    *) note "$label: baseurl does not end in /rpm/stable/\$basearch: $baseurl" ;;
  esac

  # dnf imports an ASCII-armored key; apt wants the dearmored binary keyring.
  # Naming the wrong one fails at key import, after the metadata fetch has
  # already succeeded.
  case "$gpgkey" in
    *kokos-archive-keyring.asc) ;;
    *) note "$label: gpgkey is not the armored kokos-archive-keyring.asc: $gpgkey" ;;
  esac

  # Both gates on, or the signature chain the repo scripts build is decorative:
  # gpgcheck validates each package, repo_gpgcheck validates repomd.xml.asc.
  for k in gpgcheck repo_gpgcheck; do
    [ "$(value_of "$f" "$k")" = "1" ] || note "$label: $k is not 1"
  done

  # A half-substituted file — payload from the local server, key from
  # production — would still pass every check above.
  local b_host k_host
  b_host=$(host_of "$baseurl")
  k_host=$(host_of "$gpgkey")
  [ "$b_host" = "$k_host" ] || note "$label: baseurl host ($b_host) != gpgkey host ($k_host)"
}

check_file "$TEMPLATE" "template"

# The committed template is the file published to users, so it must name the
# production host no matter what any local run substituted.
tmpl_host=$(host_of "$(value_of "$TEMPLATE" baseurl)")
[ "$tmpl_host" = "https://packages.kuksov.dev" ] ||
  note "template: baseurl host is $tmpl_host, expected https://packages.kuksov.dev"

if [ -n "$REPO_ROOT" ]; then
  RENDERED="$REPO_ROOT/rpm/kokos.repo"
  check_file "$RENDERED" "rendered"

  if [ -f "$RENDERED" ]; then
    # The rendered file has to describe the tree it ships in. These two checks
    # are what a string-only test cannot see: that the paths the URLs promise
    # exist at all under this root.
    [ -f "$REPO_ROOT/rpm/stable/x86_64/repodata/repomd.xml" ] ||
      note "rendered: no repodata under $REPO_ROOT/rpm/stable/x86_64"

    key_path=${REPO_ROOT}/$(value_of "$RENDERED" gpgkey | sed -E 's|^[a-z]+://[^/]+/||')
    [ -f "$key_path" ] ||
      note "rendered: gpgkey names $key_path, which is not in this repo root"

    # KOKOS_REPO_URL defaults to production, so a rendered file pointing there
    # is correct for a real publish and wrong for a local e2e. Say which one
    # this is rather than guessing the operator's intent.
    r_host=$(host_of "$(value_of "$RENDERED" baseurl)")
    if [ "$r_host" = "https://packages.kuksov.dev" ]; then
      echo "NOTE: rendered file points at production ($r_host) — for a local e2e"
      echo "      rebuild with KOKOS_REPO_URL=http://<host>:<port>"
    else
      echo "NOTE: rendered file points at $r_host (local serving URL)"
    fi
  fi
fi

[ "$fail" -eq 0 ] && echo "PASS: kokos.repo is consistent"
exit "$fail"
