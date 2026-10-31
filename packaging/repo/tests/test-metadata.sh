#!/usr/bin/env bash
# Asserts the built Linux artifacts declare the expected glibc floor.
# Usage: test-metadata.sh <dir containing the bundle output>
set -euo pipefail

BUNDLE_DIR="${1:?usage: test-metadata.sh <bundle-dir>}"
[ -d "$BUNDLE_DIR" ] || { echo "FAIL: no such directory $BUNDLE_DIR"; exit 1; }

DEB=$(find "$BUNDLE_DIR" -name '*.deb' | head -1)
RPM=$(find "$BUNDLE_DIR" -name '*.rpm' | head -1)
[ -n "$DEB" ] || { echo "FAIL: no .deb under $BUNDLE_DIR"; exit 1; }
[ -n "$RPM" ] || { echo "FAIL: no .rpm under $BUNDLE_DIR"; exit 1; }

deb_name=$(dpkg-deb -f "$DEB" Package)
deb_depends=$(dpkg-deb -f "$DEB" Depends)
rpm_name=$(rpm -qp --qf '%{NAME}' "$RPM" 2>/dev/null)
# REQUIRENAME, not `rpm -qpR`. Tauri passes each rpm.depends string straight
# through as a dependency NAME without parsing it, so a versioned entry like
# "glibc >= 2.39" becomes the name of a package that does not exist and the
# rpm installs nowhere. `rpm -qpR` renders that broken form and a correctly
# parsed one as the same text, which is why the substring check this replaced
# stayed green while the package was uninstallable on every Fedora. The floor
# is now declared as the ABI symbol dependency instead — a bare name, so
# nothing can mangle it, and it is what rpm's own dependency generator emits.
rpm_requires=$(rpm -qp --qf '[%{REQUIRENAME}\n]' "$RPM" 2>/dev/null)

echo "deb Package: $deb_name"
echo "rpm Name:    $rpm_name"

fail=0
case "$deb_depends" in
  *"libc6 (>= 2.39)"*) ;;
  *) echo "FAIL: deb Depends lacks 'libc6 (>= 2.39)': $deb_depends"; fail=1 ;;
esac
case "$deb_depends" in
  *libwebkit2gtk-4.1-0*) ;;
  *) echo "FAIL: deb Depends lacks libwebkit2gtk-4.1-0"; fail=1 ;;
esac
case "$deb_depends" in
  *libgtk-3-0*) ;;
  *) echo "FAIL: deb Depends lacks libgtk-3-0: $deb_depends"; fail=1 ;;
esac
# All three rpm dependencies get the same exact-line treatment, not just the
# glibc one: every entry in bundle.linux.rpm.depends travels the same
# unparsed path, so a future "webkit2gtk4.1 >= 2.44" would break exactly the
# way "glibc >= 2.39" did, and a substring check could not tell.
for req in 'libc.so.6(GLIBC_2.39)(64bit)' 'webkit2gtk4.1' 'gtk3'; do
  printf '%s\n' "$rpm_requires" | grep -Fxq "$req" || {
    echo "FAIL: rpm Requires lacks $req"
    echo "requires were: $rpm_requires"; fail=1; }
done

# The name users will type. Debian policy forbids uppercase, so the deb must
# be lowercase; if the rpm disagrees, the README must say what the rpm says.
[ "$deb_name" = "kokos" ] || { echo "FAIL: deb Package is '$deb_name', expected 'kokos'"; fail=1; }
if [ "$rpm_name" != "kokos" ]; then
  echo "NOTE: rpm package name is '$rpm_name' — README and kokos.repo must use it verbatim"
fi

[ "$fail" -eq 0 ] && echo "PASS: metadata floor declared"
exit "$fail"
