#!/usr/bin/env bash
# Asserts the dry-run upload plan obeys the ordering and cache rules that make
# a live publish safe. Pure string checking — no network.
set -euo pipefail

REPO_ROOT="${1:?usage: test-publish-order.sh <repo-root>}"
PLAN=$(bash packaging/repo/publish.sh --dry-run "$REPO_ROOT")
echo "$PLAN"

# Anchored to the whole line (^UPLOAD <class> <exact path>$) so a path that
# is a literal prefix of another real path in the plan — Packages vs
# Packages.gz, repomd.xml vs repomd.xml.asc — cannot satisfy the wrong
# assertion. Previously, whichever candidate `head -1` picked first decided
# the match by accident; anchoring makes each lookup unambiguous by
# construction.
line_of() { echo "$PLAN" | grep -n -E -- "^UPLOAD [A-Z]+ $1\$" | head -1 | cut -d: -f1; }

pool=$(line_of 'deb/pool')
pkgs=$(line_of 'deb/dists/stable/main/binary-amd64/Packages')
inrel=$(line_of 'deb/dists/stable/InRelease')
rpms=$(echo "$PLAN" | grep -n -E 'rpm/stable/x86_64/[^/]+\.rpm$' | head -1 | cut -d: -f1)
repodata=$(line_of 'rpm/stable/x86_64/repodata/repomd\.xml')

for v in pool pkgs inrel rpms repodata; do
  [ -n "${!v}" ] || { echo "FAIL: plan has no line for $v"; exit 1; }
done

[ "$pool" -lt "$pkgs" ]   || { echo "FAIL: Packages uploaded before the pool"; exit 1; }
[ "$pkgs" -lt "$inrel" ]  || { echo "FAIL: InRelease uploaded before Packages"; exit 1; }
[ "$rpms" -lt "$repodata" ] || { echo "FAIL: repomd.xml uploaded before the rpms"; exit 1; }

echo "$PLAN" | grep -qE '^UPLOAD IMMUTABLE deb/pool$' \
  || { echo "FAIL: pool not immutable-cached"; exit 1; }
echo "$PLAN" | grep -qE '^UPLOAD REVALIDATE deb/dists/stable/InRelease$' \
  || { echo "FAIL: InRelease is cacheable"; exit 1; }
echo "$PLAN" | grep -qE '^UPLOAD REVALIDATE rpm/stable/x86_64/repodata/repomd\.xml$' \
  || { echo "FAIL: repomd.xml is cacheable"; exit 1; }

echo "PASS: publish plan ordered and cached correctly"
