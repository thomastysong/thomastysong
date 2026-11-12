#!/bin/sh
# devcontainer Feature install script (runs as root at image build).
# SKETCH, UNTESTED with the devcontainer CLI; the layout it creates is the one
# Dockerfile.example builds, which test/e2e/container_test.go runs.
# Options arrive as upper-case environment variables (VERSION, SHA256, URL,
# AGENTS); _REMOTE_USER is the user the workspace runs as.
set -eu

VERSION=${VERSION:-0.1.0}
URL=${URL:-https://downloads.example.com/spoor}
AGENTS=${AGENTS:-claude-code,codex,gemini-cli,copilot-cli}
USER_NAME=${_REMOTE_USER:-root}

echo "${SHA256:-}" | grep -Eq '^[0-9a-f]{64}$' || { echo "spoor feature: set the sha256 option" >&2; exit 1; }
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "spoor feature: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then
	curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp" "$URL/$VERSION/spoor_linux_$arch"
else
	wget -q --https-only -O "$tmp" "$URL/$VERSION/spoor_linux_$arch"
fi
got=$(sha256sum "$tmp" | cut -d' ' -f1)
[ "$got" = "$SHA256" ] || { echo "spoor feature: SHA-256 mismatch: got $got" >&2; exit 1; }
install -m 0755 "$tmp" /usr/local/bin/spoor

/usr/local/bin/spoor hooks install --scope managed --binary /usr/local/bin/spoor --agents "$AGENTS"

install -d -m 0755 /etc/spoor /usr/local/share/spoor
if [ ! -e /etc/spoor/spoor.yaml ]; then
	printf 'data_dir: /var/lib/spoor\noutput:\n  stdout: true\n' >/etc/spoor/spoor.yaml
	chmod 0644 /etc/spoor/spoor.yaml
fi
# The daemon runs as the workspace user when the container does not run as
# root; give that user the data directory.
install -d -m 0700 /var/lib/spoor
uid=$(id -u "$USER_NAME" 2>/dev/null || echo 0)
gid=$(id -g "$USER_NAME" 2>/dev/null || echo 0)
chown "$uid:$gid" /var/lib/spoor

here=$(cd "$(dirname "$0")" && pwd)
if [ -f "$here/spoor-entrypoint.sh" ]; then
	install -m 0755 "$here/spoor-entrypoint.sh" /usr/local/share/spoor/spoor-entrypoint.sh
else
	cat >/usr/local/share/spoor/spoor-entrypoint.sh <<'EOF'
#!/bin/sh
set -eu
SPOOR=${SPOOR_BIN:-/usr/local/bin/spoor}
if [ "${SPOOR_DISABLE:-0}" != 1 ] && [ -x "$SPOOR" ]; then
	"$SPOOR" run --config "${SPOOR_CONFIG:-/etc/spoor/spoor.yaml}" --log-format json &
fi
exec "$@"
EOF
	chmod 0755 /usr/local/share/spoor/spoor-entrypoint.sh
fi
echo "spoor feature: installed spoor $VERSION; hooks registered for $AGENTS"
