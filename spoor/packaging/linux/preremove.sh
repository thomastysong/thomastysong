#!/bin/sh
# spoor deb prerm / rpm %preun.
#   deb: prerm remove | upgrade <new> | deconfigure ... | failed-upgrade <old>
#   rpm: %preun $1 = 0 (erase) or 1 (upgrade: the new package is already
#        installed and its %post has run)
#
# On an upgrade nothing happens here: the new package's post-install
# restarts the service and refreshes the extension copy.
#
# On removal, while the binary still exists:
#  - stop and disable the service;
#  - remove spoor's managed hook entries, so no agent keeps calling a binary
#    that is about to disappear (guarded entries would exit 0 silently, but
#    fail-closed guard entries would block the agent's tool calls);
#  - unregister the osquery extension: remove spoor's line from
#    /etc/osquery/extensions.load (osquery warns about, and retries, a
#    missing extension otherwise) and the copy osquery runs, then restart
#    osquery detached so it lets go of the running extension.
# Configuration and data stay (deb: until purge).
set -e

BIN=/usr/bin/spoor
EXT_DIR=/usr/lib/spoor
EXT=$EXT_DIR/spoor.ext
LOAD=/etc/osquery/extensions.load

warn() { echo "spoor: warning: $*" >&2; }

case "${1:-}" in
remove | deconfigure | 0) ;;
*) exit 0 ;;
esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now spoor.service >/dev/null 2>&1 || warn "could not stop spoor.service"
fi

if [ "${1:-}" != deconfigure ] && [ -x "$BIN" ]; then
	"$BIN" hooks uninstall --scope managed >/dev/null 2>&1 ||
		warn "could not remove managed hook entries; check with: spoor hooks status (before removal) or the agents' managed settings files"
fi

unregistered=0
if [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	tmp=$(mktemp)
	grep -vxF "$EXT" "$LOAD" >"$tmp" || true
	# Rewrite in place: osquery checks the owner and mode of this file.
	cat "$tmp" >"$LOAD"
	rm -f "$tmp"
	unregistered=1
fi
rm -f "$EXT" "$EXT.new"
rmdir "$EXT_DIR" 2>/dev/null || true

if [ "$unregistered" = 1 ]; then
	svc=osqueryd
	if command -v systemctl >/dev/null 2>&1 && systemctl cat orbit.service >/dev/null 2>&1; then
		svc=orbit
	fi
	if [ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1; then
		systemd-run --on-active=10 --unit="spoor-restart-osquery-$$" "$(command -v systemctl)" restart "$svc" >/dev/null 2>&1 ||
			warn "restart $svc to unload the spoor extension"
		echo "spoor: osquery ($svc) restarts in 10 s to unload the extension"
	else
		warn "restart osquery to unload the spoor extension"
	fi
fi
exit 0
