#!/bin/sh
# Build the macOS installer package with pkgbuild (macOS only).
# UNTESTED: no macOS host was available where this release was built; the
# script is checked with `sh -n` only. The binary is unsigned unless you sign
# it (codesign) before, and the package unless HAWKBELL_PKG_SIGN names a
# "Developer ID Installer" identity; Gatekeeper and MDM deployment expect
# both, plus notarization (xcrun notarytool), which this script does not do.
#
#   packaging/macos/build-pkg.sh dist/hawkbell-darwin-universal_darwin_all/hawkbell 1.2.3 dist/hawkbell_1.2.3_darwin_universal.pkg
#
# Payload: /usr/local/bin/hawkbell (a universal binary: goreleaser's
# universal_binaries entry hawkbell-darwin-universal writes it to
# dist/<id>_darwin_all/hawkbell; or `lipo -create`) and the launchd plist from
# packaging/launchd. packaging/macos/postinstall does the rest.
# Uninstall: deploy/fleet/scripts/uninstall-hawkbell.sh (macOS branch).
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 <hawkbell binary> <version> <output.pkg>" >&2
	exit 2
fi
bin=$1 version=$2 out=$3
[ "$(uname -s)" = Darwin ] || { echo "pkgbuild exists only on macOS" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
label=com.github.thomastysong.hawkbell

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
install -d -m 0755 "$work/root/usr/local/bin" "$work/root/usr/local/share/doc/hawkbell" "$work/root/Library/LaunchDaemons" "$work/scripts"
install -m 0755 "$bin" "$work/root/usr/local/bin/hawkbell"
install -m 0644 "$here/../launchd/$label.plist" "$work/root/Library/LaunchDaemons/$label.plist"
install -m 0755 "$here/postinstall" "$work/scripts/postinstall"
for f in LICENSE NOTICE THIRD_PARTY_LICENSES; do
	install -m 0644 "$here/../../$f" "$work/root/usr/local/share/doc/hawkbell/$f"
done

set -- --root "$work/root" --scripts "$work/scripts" --identifier "$label" \
	--version "$version" --install-location / --ownership recommended
if [ -n "${HAWKBELL_PKG_SIGN:-}" ]; then
	set -- "$@" --sign "$HAWKBELL_PKG_SIGN"
fi
pkgbuild "$@" "$out"
echo "wrote $out"
