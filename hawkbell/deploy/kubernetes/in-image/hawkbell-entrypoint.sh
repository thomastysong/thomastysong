#!/bin/sh
# Entrypoint wrapper for hawkbell's in-image hook mode (README.md, "In-image
# hook mode"). It starts the hawkbell daemon next to the image's own command so
# that the daemon's records go to the container's stdout, where the cluster's
# log agent collects them, then runs the command.
#
#   ENTRYPOINT ["/usr/local/share/hawkbell/hawkbell-entrypoint.sh"]
#   CMD ["sleep", "infinity"]          # or your workspace's own command
#
# The daemon runs as the container's user. Agents' hooks (`hawkbell hook`,
# registered in the image by `hawkbell hooks install --scope managed`) append to
# a spool under the daemon's data directory; the daemon re-detects with the
# full rule set and writes detections, health and inventory to stdout. Hook
# stdout is the agent's control channel, so hooks never write records there.
#
# This is telemetry, not a tamper-proof control: anyone who can run commands
# in the container as its user can stop the daemon or edit what it reads.
# When the command exits the container stops and the daemon with it; records
# of the last second may be lost.
set -eu

HAWKBELL=${HAWKBELL_BIN:-/usr/local/bin/hawkbell}
if [ "${HAWKBELL_DISABLE:-0}" != 1 ] && [ -x "$HAWKBELL" ]; then
	"$HAWKBELL" run --config "${HAWKBELL_CONFIG:-/etc/hawkbell/hawkbell.yaml}" --log-format json &
fi
exec "$@"
