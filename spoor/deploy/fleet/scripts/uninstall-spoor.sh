#!/bin/sh
# Remove the spoor sensor and its osquery extension registration.
# Fleet script for macOS and Linux (runs as root); safe to run again.
# Keeps configuration and data unless SPOOR_PURGE=1.
set -eu
ROOT=${SPOOR_ROOT:-} # test prefix; empty on real hosts

die() { echo "spoor uninstall: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
case $(uname -s) in
Linux)
	os=linux
	BIN=$ROOT/usr/bin/spoor EXTDIR=$ROOT/usr/lib/spoor CONFDIR=$ROOT/etc/spoor DATA=$ROOT/var/lib/spoor
	LOAD=$ROOT/etc/osquery/extensions.load
	;;
Darwin)
	os=darwin
	BIN=$ROOT/usr/local/bin/spoor EXTDIR=$ROOT/usr/local/lib/spoor
	CONFDIR="$ROOT/Library/Application Support/spoor" DATA=$CONFDIR
	LOAD=$ROOT/var/osquery/extensions.load
	;;
*) die "unsupported OS $(uname -s)" ;;
esac
EXT=$EXTDIR/spoor.ext

if [ $os = linux ]; then
	UNIT=$ROOT/etc/systemd/system/spoor.service
	if command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now spoor >/dev/null 2>&1 || true
	fi
	if [ -f "$UNIT" ] || [ -d "$UNIT.d" ]; then
		rm -f "$UNIT" "$UNIT.d/10-outbox-group.conf"
		rmdir "$UNIT.d" 2>/dev/null || true
		systemctl daemon-reload 2>/dev/null || true
	fi
else
	LABEL=com.github.thomastysong.spoor
	launchctl bootout system/$LABEL >/dev/null 2>&1 || true
	rm -f "$ROOT/Library/LaunchDaemons/$LABEL.plist"
fi

# While the binary exists: no agent keeps calling it (fail-closed entries
# would block tool calls), as the deb/rpm pre-removal script does.
if [ -x "$BIN" ]; then
	"$BIN" hooks uninstall --scope managed ${ROOT:+--root "$ROOT"} >/dev/null ||
		echo "spoor uninstall: warning: managed hook entries not removed" >&2
fi

restart=0
if [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	tmp=$(mktemp)
	grep -vxF "$EXT" "$LOAD" >"$tmp" || true
	# Rewrite in place: keeps the owner and mode osquery checks.
	cat "$tmp" >"$LOAD"
	rm -f "$tmp"
	restart=1
fi
rm -f "$EXT" "$BIN"
rmdir "$EXTDIR" 2>/dev/null || true
if [ "${SPOOR_PURGE:-0}" = 1 ]; then
	rm -rf "$DATA" "$CONFDIR"
	[ $os = darwin ] && rm -rf "$ROOT/Library/Logs/spoor"
fi

# osquery keeps a loaded extension until it restarts; restart it detached
# and delayed so the Fleet script that runs this can report first.
if [ $restart = 1 ]; then
	if [ $os = linux ]; then
		svc=osqueryd
		systemctl cat orbit.service >/dev/null 2>&1 && svc=orbit
		if command -v systemd-run >/dev/null 2>&1; then
			systemd-run --on-active=10 --unit=spoor-restart-osquery-$$ "$(command -v systemctl)" restart $svc >/dev/null
		else
			nohup sh -c "sleep 10; systemctl restart $svc" >/dev/null 2>&1 &
		fi
	else
		svc=system/com.facebook.osqueryd
		launchctl print system/com.fleetdm.orbit >/dev/null 2>&1 && svc=system/com.fleetdm.orbit
		nohup sh -c "sleep 10; launchctl kickstart -k $svc" >/dev/null 2>&1 &
	fi
	echo "spoor uninstall: osquery ($svc) restarts in 10 s"
fi
echo "spoor uninstall: removed"
