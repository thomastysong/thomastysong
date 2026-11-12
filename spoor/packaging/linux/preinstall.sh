#!/bin/sh
# spoor deb preinst / rpm %pre.
#   deb: preinst install|upgrade|abort-upgrade [version]
#   rpm: %pre $1 = 1 (install) or 2 (upgrade)
#
# The systemd unit runs with Group=spoor and does not start when the group
# is missing, so the group must exist before the unit is installed. Members
# of the group (a log shipper) may read the outbox; nothing else is granted.
set -e

has_group() {
	if command -v getent >/dev/null 2>&1; then
		getent group spoor >/dev/null 2>&1
	else
		grep -q '^spoor:' /etc/group 2>/dev/null
	fi
}

if ! has_group; then
	if command -v groupadd >/dev/null 2>&1; then
		groupadd --system spoor
	elif command -v addgroup >/dev/null 2>&1; then
		addgroup --system spoor
	else
		echo "spoor: cannot create the system group spoor (neither groupadd nor addgroup exists)" >&2
		exit 1
	fi
fi
exit 0
