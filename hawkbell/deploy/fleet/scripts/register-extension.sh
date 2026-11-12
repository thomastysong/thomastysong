#!/bin/sh
# Post-install script for the hawkbell deb, rpm and pkg packages in Fleet
# (Premium software deployment): register the installed binary as an osquery
# extension in osquery's default extensions.load, never orbit's, and restart
# osquery detached so the install reports before osquery goes away.
set -eu
ROOT=${HAWKBELL_ROOT:-} # test prefix; empty on real hosts
case $(uname -s) in
Linux) BIN=$ROOT/usr/bin/hawkbell EXTDIR=$ROOT/usr/lib/hawkbell LOAD=$ROOT/etc/osquery/extensions.load ;;
Darwin) BIN=$ROOT/usr/local/bin/hawkbell EXTDIR=$ROOT/usr/local/lib/hawkbell LOAD=$ROOT/var/osquery/extensions.load ;;
*) echo "unsupported OS" >&2; exit 1 ;;
esac
EXT=$EXTDIR/hawkbell.ext
[ -x "$BIN" ] || { echo "hawkbell binary missing at $BIN" >&2; exit 1; }
# When orbit's own autoload file is not empty (Fleet manages extensions on
# this host), orbit starts osquery with --extensions_autoload pointing at it
# and osquery ignores $LOAD. Fail, so Fleet reports why (and rolls back).
for f in "$ROOT/opt/orbit/extensions.load" "$ROOT/var/lib/orbit/extensions.load"; do
	if [ -s "$f" ]; then
		echo "orbit loads osquery extensions from $f (Fleet's extensions agent option), so osquery ignores $LOAD. Deliver hawkbell through that agent option, or deploy tier 2 (ATC) without this script." >&2
		exit 1
	fi
done
restart=0
install -d -m 0755 -o 0 -g 0 "$EXTDIR"
if ! cmp -s "$BIN" "$EXT" 2>/dev/null; then
	cp "$BIN" "$EXT.new" && chown 0:0 "$EXT.new" && chmod 0755 "$EXT.new" && mv -f "$EXT.new" "$EXT"
	restart=1
fi
install -d -m 0755 "$(dirname "$LOAD")"
if ! grep -qxF "$EXT" "$LOAD" 2>/dev/null; then
	# A last line without a newline would be glued to ours.
	if [ -s "$LOAD" ] && [ -n "$(tail -c 1 "$LOAD")" ]; then echo >>"$LOAD"; fi
	printf '%s\n' "$EXT" >>"$LOAD"
	restart=1
fi
chown 0:0 "$LOAD" && chmod 0644 "$LOAD"
if [ $restart = 1 ]; then
	if [ "$(uname -s)" = Linux ]; then
		svc=osqueryd
		systemctl cat orbit.service >/dev/null 2>&1 && svc=orbit
		if command -v systemd-run >/dev/null 2>&1; then
			systemd-run --on-active=10 --unit=hawkbell-restart-osquery-$$ "$(command -v systemctl)" restart $svc >/dev/null
		else
			nohup sh -c "sleep 10; systemctl restart $svc" >/dev/null 2>&1 &
		fi
	else
		svc=system/com.facebook.osqueryd
		launchctl print system/com.fleetdm.orbit >/dev/null 2>&1 && svc=system/com.fleetdm.orbit
		nohup sh -c "sleep 10; launchctl kickstart -k $svc" >/dev/null 2>&1 &
	fi
	echo "osquery ($svc) restarts in 10 s to load $EXT"
fi
