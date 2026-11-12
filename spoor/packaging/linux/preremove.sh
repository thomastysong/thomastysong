#!/bin/sh
# spoor deb prerm / rpm %preun.
#   deb: prerm remove | upgrade <new> | deconfigure ... | failed-upgrade <old>
#   rpm: %preun $1 = 0 (erase) or 1 (upgrade: the new package is already
#        installed and its %post has run)
#
# On an upgrade nothing happens here: the new package's post-install
# restarts the service and refreshes the extension copy.
#
# deconfigure (deb: another package's installation needs this one
# unconfigured; its files stay): stop the daemon only. Hooks and the
# extension registration keep pointing at a binary that is still there, and
# postinst (configure or abort-deconfigure) starts the daemon again.
#
# On removal, while the binary still exists:
#  - stop and disable the service;
#  - unregister the osquery extension: remove spoor's line from
#    /etc/osquery/extensions.load (osquery warns about, and retries, a
#    missing extension otherwise) and the copy osquery runs, then restart
#    osquery detached so it lets go of the running extension. The line is
#    noted in $DATA/.osquery-extension so that postinst abort-remove can put
#    it back;
#  - last, remove spoor's managed hook entries, so no agent keeps calling a
#    binary that is about to disappear (guarded entries would exit 0
#    silently, but fail-closed guard entries would block the agent's tool
#    calls). Nothing after this step can fail, so a removal that dpkg
#    aborts (postinst abort-remove) has not lost the administrator's hook
#    options: install cannot know them to write them back.
# Every step only warns on failure. Configuration and data stay (deb: until
# purge).
set -e

BIN=/usr/bin/spoor
DATA=/var/lib/spoor
EXT_DIR=/usr/lib/spoor
EXT=$EXT_DIR/spoor.ext
LOAD=/etc/osquery/extensions.load

warn() { echo "spoor: warning: $*" >&2; }
has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

case "${1:-}" in
remove | 0) ;;
deconfigure)
	if has_systemd; then
		systemctl stop spoor.service >/dev/null 2>&1 || warn "could not stop spoor.service"
	fi
	exit 0
	;;
*) exit 0 ;;
esac

if has_systemd; then
	systemctl disable --now spoor.service >/dev/null 2>&1 || warn "could not stop spoor.service"
fi

# Rewritten through a copy that keeps the file's owner and mode (osquery
# checks both) and renamed over it, so a failure never leaves osquery's
# file truncated, and other extensions' lines stay.
unregistered=0
if [ -L "$LOAD" ]; then
	grep -qxF "$EXT" "$LOAD" 2>/dev/null && warn "$LOAD is a symbolic link; remove the line $EXT from it by hand"
elif [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	tmp=$LOAD.spoor-new
	if cp -p "$LOAD" "$tmp" 2>/dev/null && { grep -vxF "$EXT" "$LOAD" >"$tmp" || [ $? -eq 1 ]; } && mv -f "$tmp" "$LOAD"; then
		unregistered=1
		if [ -d "$DATA" ] && [ ! -L "$DATA" ] && [ ! -L "$DATA/.osquery-extension" ]; then
			echo "$EXT" >"$DATA/.osquery-extension" 2>/dev/null || true
		fi
	else
		rm -f "$tmp"
		warn "could not remove $EXT from $LOAD; remove the line by hand"
	fi
fi
rm -f "$EXT" "$EXT.new" || warn "could not remove $EXT"
rmdir "$EXT_DIR" 2>/dev/null || true

if [ "$unregistered" = 1 ]; then
	svc=osqueryd
	if command -v systemctl >/dev/null 2>&1 && systemctl cat orbit.service >/dev/null 2>&1; then
		svc=orbit
	fi
	if has_systemd && command -v systemd-run >/dev/null 2>&1; then
		systemd-run --on-active=10 --unit="spoor-restart-osquery-$$" "$(command -v systemctl)" restart "$svc" >/dev/null 2>&1 ||
			warn "restart $svc to unload the spoor extension"
		echo "spoor: osquery ($svc) restarts in 10 s to unload the extension"
	else
		warn "restart osquery to unload the spoor extension"
	fi
fi

# managed, and Codex's system tier (hooks install --scope system).
if [ -x "$BIN" ]; then
	"$BIN" hooks uninstall --scope managed >/dev/null 2>&1 ||
		warn "could not remove managed hook entries; check with: spoor hooks status (before removal) or the agents' managed settings files"
	"$BIN" hooks uninstall --scope system >/dev/null 2>&1 ||
		warn "could not remove system hook entries; check with: spoor hooks status --scope system (before removal)"
fi
exit 0
