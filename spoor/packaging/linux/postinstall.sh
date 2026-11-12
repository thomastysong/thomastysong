#!/bin/sh
# spoor deb postinst / rpm %post.
#   deb: postinst configure [previous version]   (no previous version: first install)
#        postinst abort-upgrade|abort-remove|abort-deconfigure ...
#   rpm: %post $1 = 1 (install) or 2 (upgrade)
#
# What it does, in order, and why:
#  1. the spoor group (again: an rpm installed with --noscripts on %pre only,
#     or a group deleted by hand, would keep the unit from starting);
#  2. /etc/spoor (root 0755) and /var/lib/spoor (root:spoor 0750, what the
#     unit's StateDirectory= also sets);
#  3. /etc/spoor/spoor.yaml from `spoor export config` when there is none
#     (0644: unprivileged hooks read it); an existing file is never touched;
#  4. if spoor is registered as an osquery extension (the line in
#     /etc/osquery/extensions.load that deploy/fleet/scripts/register-extension.sh
#     adds), refresh the copy osquery runs and restart osquery detached;
#  5. systemd: reload; enable and start on first install, restart a running
#     service on upgrade (a service the administrator disabled stays disabled);
#  6. rewrite spoor's managed hook entries for every agent that already has
#     them: entries written by an earlier release report "modified" until
#     `spoor hooks install` runs again. Agents that were never hooked are
#     left alone; hooking is the administrator's decision.
# Failures of 3 to 6 are reported and do not fail the package: the binary
# works with built-in defaults and `spoor doctor` shows what is missing.
set -e

BIN=/usr/bin/spoor
CONF_DIR=/etc/spoor
CONF=$CONF_DIR/spoor.yaml
DATA=/var/lib/spoor
EXT_DIR=/usr/lib/spoor
EXT=$EXT_DIR/spoor.ext
LOAD=/etc/osquery/extensions.load

warn() { echo "spoor: warning: $*" >&2; }

case "${1:-}" in
configure) if [ -n "${2:-}" ]; then upgrade=1; else upgrade=0; fi ;;
1) upgrade=0 ;;
2) upgrade=1 ;;
abort-*) upgrade=1 ;;
*) upgrade=0 ;;
esac

# 1. Group.
if ! { getent group spoor >/dev/null 2>&1 || grep -q '^spoor:' /etc/group 2>/dev/null; }; then
	if command -v groupadd >/dev/null 2>&1; then
		groupadd --system spoor
	else
		addgroup --system spoor
	fi
fi

# 2. Directories. A symbolic link where a directory belongs is refused, not
# followed: chown/chmod through it would re-own whatever it points to.
for d in "$CONF_DIR" "$DATA"; do
	if [ -L "$d" ]; then
		echo "spoor: $d is a symbolic link; refusing to use it" >&2
		exit 1
	fi
done
mkdir -p "$CONF_DIR" "$DATA"
chown root:root "$CONF_DIR"
chmod 0755 "$CONF_DIR"
chown root:spoor "$DATA"
chmod 0750 "$DATA"

# 3. Configuration.
if [ ! -e "$CONF" ] && [ ! -L "$CONF" ]; then
	if "$BIN" export config --out "$CONF" >/dev/null 2>&1; then
		chown root:root "$CONF"
		chmod 0644 "$CONF"
	else
		warn "could not write $CONF; the daemon runs with built-in defaults"
	fi
fi

# 4. osquery extension copy. osquery checks the file it opens (root-owned,
# not writable by others, named *.ext), so it runs a copy, which an upgrade
# must refresh or osquery keeps running the previous release.
restart_osquery() {
	svc=osqueryd
	if command -v systemctl >/dev/null 2>&1 && systemctl cat orbit.service >/dev/null 2>&1; then
		svc=orbit
	fi
	# Detached and delayed: a package installed by orbit (Fleet software
	# deployment) must be able to report before orbit restarts.
	if [ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1; then
		systemd-run --on-active=10 --unit="spoor-restart-osquery-$$" "$(command -v systemctl)" restart "$svc" >/dev/null 2>&1 ||
			warn "could not schedule a restart of $svc; restart it to load $EXT"
	elif [ -d /run/systemd/system ]; then
		nohup sh -c "sleep 10; systemctl restart $svc" >/dev/null 2>&1 &
	else
		warn "restart osquery to load the new $EXT"
		return 0
	fi
	echo "spoor: osquery ($svc) restarts in 10 s to load $EXT"
}
if [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	if ! cmp -s "$BIN" "$EXT" 2>/dev/null; then
		mkdir -p "$EXT_DIR"
		chown root:root "$EXT_DIR"
		chmod 0755 "$EXT_DIR"
		if cp "$BIN" "$EXT.new" && chown root:root "$EXT.new" && chmod 0755 "$EXT.new" && mv -f "$EXT.new" "$EXT"; then
			restart_osquery
		else
			rm -f "$EXT.new"
			warn "could not refresh $EXT"
		fi
	fi
fi

# 5. Service.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || warn "systemctl daemon-reload failed"
	if [ "$upgrade" = 1 ]; then
		systemctl try-restart spoor.service || warn "could not restart spoor.service"
	else
		systemctl enable spoor.service >/dev/null 2>&1 || warn "could not enable spoor.service"
		systemctl start spoor.service || warn "could not start spoor.service (journalctl -u spoor)"
	fi
else
	echo "spoor: systemd is not running; start the daemon with: $BIN run --config $CONF"
fi

# 6. Hooks. `hooks status --json` prints one object per (agent, scope) with
# "agent" and "status" on lines of their own; catalog ids are [a-z0-9-].
hooked=$("$BIN" hooks status --scope managed --json 2>/dev/null | awk -F'"' '
	/"agent":/ { a = $4 }
	/"status":/ {
		s = $4
		if ((s == "managed" || s == "modified" || s == "shadowed" || s == "insecure_permissions") && a != "" && !(a in seen)) {
			seen[a] = 1
			out = out (out == "" ? "" : ",") a
		}
	}
	END { print out }') || hooked=""
if [ -n "$hooked" ]; then
	if "$BIN" hooks install --scope managed --agents "$hooked" >/dev/null 2>&1; then
		echo "spoor: managed hooks rewritten for $hooked"
	else
		warn "could not rewrite managed hooks for $hooked; run: $BIN hooks install --scope managed --agents $hooked"
	fi
fi

if ! getent group spoor 2>/dev/null | cut -d: -f4 | grep -q .; then
	echo "spoor: add your log shipper's user to group spoor to let it read $DATA/outbox"
fi
exit 0
