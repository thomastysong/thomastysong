#!/bin/sh
# Build the macOS installer package with pkgbuild (macOS only).
# UNTESTED: no macOS host was available where this release was built; the
# script is checked with `sh -n` only. The binary is unsigned unless you sign
# it (codesign) before, and the package unless SPOOR_PKG_SIGN names a
# "Developer ID Installer" identity; Gatekeeper and MDM deployment expect
# both, plus notarization (xcrun notarytool), which this script does not do.
#
#   packaging/macos/build-pkg.sh dist/spoor-darwin-universal_darwin_all/spoor 1.2.3 dist/spoor_1.2.3_darwin_universal.pkg
#
# Payload: /usr/local/bin/spoor (a universal binary: goreleaser's
# universal_binaries entry spoor-darwin-universal writes it to
# dist/<id>_darwin_all/spoor; or `lipo -create`) and the launchd plist from
# packaging/launchd. packaging/macos/postinstall does the rest.
# Uninstall: deploy/fleet/scripts/uninstall-spoor.sh (macOS branch).
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 <spoor binary> <version> <output.pkg>" >&2
	exit 2
fi
bin=$1 version=$2 out=$3
[ "$(uname -s)" = Darwin ] || { echo "pkgbuild exists only on macOS" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
label=com.github.thomastysong.spoor

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
install -d -m 0755 "$work/root/usr/local/bin" "$work/root/Library/LaunchDaemons" "$work/scripts"
install -m 0755 "$bin" "$work/root/usr/local/bin/spoor"
install -m 0644 "$here/../launchd/$label.plist" "$work/root/Library/LaunchDaemons/$label.plist"
install -m 0755 "$here/postinstall" "$work/scripts/postinstall"

set -- --root "$work/root" --scripts "$work/scripts" --identifier "$label" \
	--version "$version" --install-location / --ownership recommended
if [ -n "${SPOOR_PKG_SIGN:-}" ]; then
	set -- "$@" --sign "$SPOOR_PKG_SIGN"
fi
pkgbuild "$@" "$out"
echo "wrote $out"
