#!/usr/bin/env bash
# Exercises the built dnf repo with a real dnf client over file://, with both
# package and repo-metadata signature checking on.
set -euo pipefail

REPO_ROOT="${1:?usage: test-rpm-repo.sh <repo-root>}"
REPO_ABS=$(cd "$REPO_ROOT" && pwd)
PKG="${2:-kokos}"   # the rpm NAME printed by test-metadata.sh

docker run --rm --platform linux/amd64 -v "$REPO_ABS":/repo:ro fedora:40 bash -c "
set -e
cat > /etc/yum.repos.d/kokos.repo <<'EOF'
[kokos]
name=Kokos
baseurl=file:///repo/rpm/stable/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///repo/kokos-archive-keyring.asc
EOF
rpm --import /repo/kokos-archive-keyring.asc
# Fedora's own repos have to stay enabled. The package really does require
# gtk3, webkit2gtk4.1 and glibc >= 2.39, and with '*' disabled nothing can
# provide them, so the resolve fails before any signature is ever checked.
# This went unnoticed because the test had only ever run against
# make-fixture.sh's rpm, which declares no dependencies at all. The allowed
# repos are named explicitly rather than dropping the flag, so a third-party
# repo cannot slip into the resolve; 'kokos' is in none of them, so the
# package itself still comes from ours.
dnf -y --disablerepo='*' --enablerepo=kokos --enablerepo=fedora --enablerepo=updates install $PKG
rpm -q $PKG
rpm -qi $PKG | grep -qi 'Signature.*Key ID' || { echo 'FAIL: rpm is unsigned'; exit 1; }
echo OK-fedora40
"

echo "PASS: rpm repo verified"
