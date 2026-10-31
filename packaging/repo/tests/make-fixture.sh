#!/usr/bin/env bash
# Builds synthetic kokos packages for exercising the repository tooling on a
# host that cannot produce the real amd64 bundle. The control metadata mirrors
# what tauri.conf.json declares, so the floor behaviour under test is real.
set -euo pipefail

OUT="${1:?usage: make-fixture.sh <out-dir>}"
mkdir -p "$OUT"
OUT_ABS=$(cd "$OUT" && pwd)

docker run --rm --platform linux/amd64 -v "$OUT_ABS":/out ubuntu:24.04 bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq rpm >/dev/null

# --- .deb -------------------------------------------------------------
root=/tmp/deb/kokos_0.1.0_amd64
mkdir -p "$root/DEBIAN" "$root/usr/bin"
printf "#!/bin/sh\necho kokos fixture\n" > "$root/usr/bin/kokos"
chmod 755 "$root/usr/bin/kokos"
cat > "$root/DEBIAN/control" <<EOF
Package: kokos
Version: 0.1.0
Architecture: amd64
Maintainer: Oleksandr Kuksov <packages@kuksov.dev>
Depends: libc6 (>= 2.39), libwebkit2gtk-4.1-0, libgtk-3-0
Section: utils
Priority: optional
Description: Kokos password manager (fixture build)
 Synthetic package used to exercise repository tooling.
EOF
dpkg-deb --build --root-owner-group "$root" /out/kokos_0.1.0_amd64.deb

# --- .rpm -------------------------------------------------------------
mkdir -p /tmp/rpm/BUILD /tmp/rpm/RPMS
cat > /tmp/kokos.spec <<EOF
Name:           kokos
Version:        0.1.0
Release:        1
Summary:        Kokos password manager (fixture build)
License:        MIT
BuildArch:      x86_64
Requires:       glibc >= 2.39
%description
Synthetic package used to exercise repository tooling.
%install
mkdir -p %{buildroot}/usr/bin
printf "#!/bin/sh\necho kokos fixture\n" > %{buildroot}/usr/bin/kokos
chmod 755 %{buildroot}/usr/bin/kokos
%files
/usr/bin/kokos
EOF
rpmbuild --define "_topdir /tmp/rpm" --define "_binary_payload w9.gzdio" \
         -bb /tmp/kokos.spec >/dev/null
cp /tmp/rpm/RPMS/x86_64/*.rpm /out/kokos-0.1.0-1.x86_64.rpm
chmod 644 /out/*.deb /out/*.rpm
'

ls -l "$OUT_ABS"
