#!/bin/sh
# spoor deb postrm / rpm %postun.
#   deb: postrm remove | purge | upgrade <new> | failed-upgrade | abort-install | abort-upgrade | disappear
#   rpm: %postun $1 = 0 (erase) or 1 (upgrade)
#
# remove / erase: the unit file is gone; reload systemd. Configuration, data
# and the spoor group stay.
# purge (deb only): also remove /etc/spoor and /var/lib/spoor, and delete the
# spoor group only when nothing still needs it: no members (a log shipper
# added to it) and no files owned by it in the places spoor writes. A data
# directory configured somewhere else is reported, never deleted: its path
# comes from a file an administrator edits, and rm -rf on a wrong value is
# not recoverable. rpm has no purge; its packages leave groups in place.
set -e

CONF_DIR=/etc/spoor
CONF=$CONF_DIR/spoor.yaml
DATA=/var/lib/spoor

warn() { echo "spoor: warning: $*" >&2; }

case "${1:-}" in
remove | purge | 0) ;;
*) exit 0 ;;
esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed spoor.service >/dev/null 2>&1 || true
fi

# A completed removal: prerm's note for an aborted one is no longer needed.
rm -f "$DATA/.osquery-extension"

[ "$1" = purge ] || exit 0

# data_dir from the configuration, if it names another directory.
other=""
if [ -f "$CONF" ]; then
	other=$(sed -n 's/^data_dir:[[:space:]]*//p' "$CONF" | head -n 1 | tr -d "\"'" | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//')
	if [ "$other" = "$DATA" ] || [ "$other" = "$DATA/" ]; then
		other=""
	fi
fi

rm -rf "$DATA" "$CONF_DIR" /run/spoor
if [ -n "$other" ] && [ -e "$other" ]; then
	warn "data directory $other (data_dir in the removed $CONF) was left in place"
fi

# The group goes only when nothing still uses it.
members=$(getent group spoor 2>/dev/null | cut -d: -f4)
if ! getent group spoor >/dev/null 2>&1; then
	exit 0
fi
if [ -n "$members" ]; then
	echo "spoor: group spoor kept: it has members ($members)"
	exit 0
fi
for d in "$DATA" "$CONF_DIR" /run/spoor /usr/lib/spoor ${other:+"$other"}; do
	if [ -e "$d" ] && [ -n "$(find "$d" -group spoor -print 2>/dev/null | head -n 1)" ]; then
		echo "spoor: group spoor kept: files under $d still belong to it"
		exit 0
	fi
done
if command -v groupdel >/dev/null 2>&1; then
	groupdel spoor || warn "could not delete group spoor"
elif command -v delgroup >/dev/null 2>&1; then
	delgroup --system spoor || warn "could not delete group spoor"
fi
exit 0
