#!/bin/sh
# hawkbell deb postrm / rpm %postun.
#   deb: postrm remove | purge | upgrade <new> | failed-upgrade | abort-install | abort-upgrade | disappear
#   rpm: %postun $1 = 0 (erase) or 1 (upgrade)
#
# remove / erase: the unit file is gone; reload systemd. Configuration, data
# and the hawkbell group stay.
# purge (deb only): also remove /etc/hawkbell and /var/lib/hawkbell, and delete the
# hawkbell group only when nothing still needs it: no members (a log shipper
# added to it) and no files owned by it in the places hawkbell writes. A data
# directory configured somewhere else is reported, never deleted: its path
# comes from a file an administrator edits, and rm -rf on a wrong value is
# not recoverable. rpm has no purge; its packages leave groups in place.
set -e

CONF_DIR=/etc/hawkbell
CONF=$CONF_DIR/hawkbell.yaml
DATA=/var/lib/hawkbell

warn() { echo "hawkbell: warning: $*" >&2; }

case "${1:-}" in
remove | purge | 0) ;;
*) exit 0 ;;
esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed hawkbell.service >/dev/null 2>&1 || true
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

rm -rf "$DATA" "$CONF_DIR" /run/hawkbell
if [ -n "$other" ] && [ -e "$other" ]; then
	warn "data directory $other (data_dir in the removed $CONF) was left in place"
fi

# The group goes only when nothing still uses it.
members=$(getent group hawkbell 2>/dev/null | cut -d: -f4)
if ! getent group hawkbell >/dev/null 2>&1; then
	exit 0
fi
if [ -n "$members" ]; then
	echo "hawkbell: group hawkbell kept: it has members ($members)"
	exit 0
fi
for d in "$DATA" "$CONF_DIR" /run/hawkbell /usr/lib/hawkbell ${other:+"$other"}; do
	if [ -e "$d" ] && [ -n "$(find "$d" -group hawkbell -print 2>/dev/null | head -n 1)" ]; then
		echo "hawkbell: group hawkbell kept: files under $d still belong to it"
		exit 0
	fi
done
if command -v groupdel >/dev/null 2>&1; then
	groupdel hawkbell || warn "could not delete group hawkbell"
elif command -v delgroup >/dev/null 2>&1; then
	delgroup --system hawkbell || warn "could not delete group hawkbell"
fi
exit 0
