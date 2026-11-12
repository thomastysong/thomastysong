#!/bin/sh
# spoor deb postinst / rpm %post.
#   deb: postinst configure [previous version]   (no previous version: first install)
#        postinst abort-upgrade|abort-remove|abort-deconfigure ...
#   rpm: %post $1 = 1 (install) or 2 (upgrade)
#
# The abort calls undo what prerm did (packaging/linux/preremove.sh):
# abort-deconfigure starts the daemon prerm stopped (when it is enabled);
# abort-remove enables and starts it again and puts back the osquery
# extension registration prerm noted in $DATA/.osquery-extension.
#
# What it does, in order, and why:
#  1. the spoor group (again: an rpm installed with --noscripts on %pre only,
#     or a group deleted by hand, would keep the unit from starting);
#  2. /etc/spoor (root 0755) and /var/lib/spoor (root:spoor 0711, what the
#     unit's StateDirectory=/StateDirectoryMode= set at every start: users
#     traverse it to reach their own spool directory and the public rule
#     bundle; the outbox and state database inside stay restricted);
#  3. /etc/spoor/spoor.yaml from `spoor export config` when there is none
#     (0644: unprivileged hooks read it); an existing file is never touched;
#  4. if spoor is registered as an osquery extension (the line in
#     /etc/osquery/extensions.load that deploy/fleet/scripts/register-extension.sh
#     adds), refresh the copy osquery runs and restart osquery detached;
#  5. systemd: reload; enable and start on first install, restart a running
#     service on upgrade (a service the administrator disabled stays disabled);
#  6. rewrite spoor's managed hook entries written by an earlier release
#     (they report "modified" until `spoor hooks install` runs again), but
#     only where they are exactly what that release wrote with install's
#     default options: the rewrite uses the default options too, so it would
#     turn an administrator's --guard --fail-closed registration into a
#     fail-open one and reset a --timeout. Entries installed with other
#     options or edited by hand are left as they are and reported. Agents
#     that were never hooked are left alone; hooking is the administrator's
#     decision.
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
configure) if [ -n "${2:-}" ]; then mode=upgrade; else mode=install; fi ;;
1) mode=install ;;
2 | abort-upgrade) mode=upgrade ;;
abort-remove) mode=abort-remove ;;
abort-deconfigure) mode=abort-deconfigure ;;
*) mode=install ;;
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
chmod 0711 "$DATA"

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
# A removal dpkg aborted: prerm took spoor's line out of osquery's file and
# noted it; put it back (through a copy that keeps the file's owner and
# mode, renamed over it), and the refresh below restores the copy.
NOTE=$DATA/.osquery-extension
if [ "$mode" = abort-remove ] && [ -f "$NOTE" ] && [ ! -L "$NOTE" ] && [ -f "$LOAD" ] && [ ! -L "$LOAD" ] && ! grep -qxF "$EXT" "$LOAD"; then
	tmp=$LOAD.spoor-new
	if cp -p "$LOAD" "$tmp" && {
		cat "$LOAD"
		[ -z "$(tail -c 1 "$LOAD")" ] || echo
		echo "$EXT"
	} >"$tmp" && mv -f "$tmp" "$LOAD"; then
		echo "spoor: osquery extension registration restored in $LOAD"
	else
		rm -f "$tmp"
		warn "could not restore $EXT in $LOAD; run deploy/fleet/scripts/register-extension.sh"
	fi
fi
rm -f "$NOTE"
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
	case $mode in
	upgrade)
		systemctl try-restart spoor.service || warn "could not restart spoor.service"
		;;
	abort-deconfigure)
		if systemctl is-enabled --quiet spoor.service 2>/dev/null; then
			systemctl start spoor.service || warn "could not start spoor.service (journalctl -u spoor)"
		fi
		;;
	*)
		systemctl enable spoor.service >/dev/null 2>&1 || warn "could not enable spoor.service"
		systemctl start spoor.service || warn "could not start spoor.service (journalctl -u spoor)"
		;;
	esac
else
	echo "spoor: systemd is not running; start the daemon with: $BIN run --config $CONF"
fi

# 6. Hooks. `hooks status --json` prints one object per (agent, scope),
# one key per line, with "agent" first; catalog ids are [a-z0-9-]. Its
# detail starts with "written by an earlier spoor release" (after
# "<reason>; " when the file's permissions are also reported) for entries
# that equal what an earlier release wrote with the default options
# (internal/hookinstall, legacyPrefix; packaging_test.go holds the two
# together); $4 is the detail up to its first escaped quote, so text
# quoted inside it cannot match. Only those agents are rewritten (first
# output line). Agents whose entries differ from install's default output
# in any other way carry options the administrator chose, or an edit, and
# are only listed (second line).
sel=$("$BIN" hooks status --scope managed --json 2>/dev/null | awk -F'"' '
	function flush() {
		if (a != "" && old && !(a in seen)) {
			seen[a] = 1
			out = out (out == "" ? "" : ",") a
		} else if (a != "" && !old && s == "modified" && !(a in kept)) {
			kept[a] = 1
			left = left (left == "" ? "" : ",") a
		}
		a = ""
		s = ""
		old = 0
	}
	/^[ \t]*"agent": "/ { flush(); a = $4 }
	/^[ \t]*"status": "/ { s = $4 }
	/^[ \t]*"detail": "/ {
		d = $4
		if (index(d, "written by an earlier spoor release") == 1 || index(d, "; written by an earlier spoor release") > 0) old = 1
	}
	END { flush(); print out; print left }') || sel=""
hooked=$(printf '%s\n' "$sel" | sed -n 1p)
left=$(printf '%s\n' "$sel" | sed -n 2p)
if [ -n "$hooked" ]; then
	if "$BIN" hooks install --scope managed --agents "$hooked" >/dev/null 2>&1; then
		echo "spoor: managed hooks rewritten for $hooked"
	else
		warn "could not rewrite managed hooks for $hooked; run: $BIN hooks install --scope managed --agents $hooked"
	fi
fi
if [ -n "$left" ]; then
	echo "spoor: managed hooks of $left left as they are: they differ from install's default options (--guard, --fail-closed, --timeout ...) or were edited; if an earlier release wrote them, run $BIN hooks install --scope managed --agents $left with the options they were installed with"
fi

if ! getent group spoor 2>/dev/null | cut -d: -f4 | grep -q .; then
	echo "spoor: add your log shipper's user to group spoor to let it read $DATA/outbox"
fi
exit 0
