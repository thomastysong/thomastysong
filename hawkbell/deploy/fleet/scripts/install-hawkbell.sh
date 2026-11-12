#!/bin/sh
# Install or update the hawkbell sensor; register it as an osquery extension.
# Fleet script for macOS and Linux (runs as root); safe to run again.
# Set the URL and SHA-256 of each build below. A value may name a Fleet
# custom variable (FLEET_SECRET_* after a dollar sign): Fleet fills it in,
# and fleetctl gitops requires it to be set, even in a comment.
# TIER must match the agent options: extension (tier 3, no ATC tables) or
# atc (tier 2, ATC; no extension). Fleet scripts get no environment: edit
# the defaults here (HAWKBELL_* is for manual runs).
set -eu
umask 022

URL_LINUX_AMD64=${HAWKBELL_URL_LINUX_AMD64:-https://downloads.example.com/hawkbell/0.1.0/hawkbell_linux_amd64}
SHA_LINUX_AMD64=${HAWKBELL_SHA256_LINUX_AMD64:-REPLACE_WITH_SHA256}
URL_LINUX_ARM64=${HAWKBELL_URL_LINUX_ARM64:-https://downloads.example.com/hawkbell/0.1.0/hawkbell_linux_arm64}
SHA_LINUX_ARM64=${HAWKBELL_SHA256_LINUX_ARM64:-REPLACE_WITH_SHA256}
URL_DARWIN_AMD64=${HAWKBELL_URL_DARWIN_AMD64:-https://downloads.example.com/hawkbell/0.1.0/hawkbell_darwin_amd64}
SHA_DARWIN_AMD64=${HAWKBELL_SHA256_DARWIN_AMD64:-REPLACE_WITH_SHA256}
URL_DARWIN_ARM64=${HAWKBELL_URL_DARWIN_ARM64:-https://downloads.example.com/hawkbell/0.1.0/hawkbell_darwin_arm64}
SHA_DARWIN_ARM64=${HAWKBELL_SHA256_DARWIN_ARM64:-REPLACE_WITH_SHA256}
TIER=${HAWKBELL_TIER:-extension} # or atc
ROOT=${HAWKBELL_ROOT:-} # test prefix; empty on real hosts

die() { echo "hawkbell install: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
case $TIER in extension | atc) ;; *) die "HAWKBELL_TIER must be extension or atc" ;; esac

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
case $(uname -s) in
Linux)
	os=linux
	BIN=$ROOT/usr/bin/hawkbell EXTDIR=$ROOT/usr/lib/hawkbell CONFDIR=$ROOT/etc/hawkbell DATA=$ROOT/var/lib/hawkbell
	LOAD=$ROOT/etc/osquery/extensions.load
	;;
Darwin)
	os=darwin
	BIN=$ROOT/usr/local/bin/hawkbell EXTDIR=$ROOT/usr/local/lib/hawkbell
	CONFDIR="$ROOT/Library/Application Support/hawkbell" DATA=$CONFDIR
	LOAD=$ROOT/var/osquery/extensions.load
	;;
*) die "unsupported OS $(uname -s)" ;;
esac
EXT=$EXTDIR/hawkbell.ext
# orbit rewrites its own autoload file; osquery's default one is ours.
case $LOAD in */orbit/*) die "refusing to write orbit's extensions.load" ;; esac
# But a non-empty orbit file (Fleet manages extensions) is osquery's
# --extensions_autoload, and $LOAD is ignored.
if [ "$TIER" = extension ]; then
	for f in "$ROOT/opt/orbit/extensions.load" "$ROOT/var/lib/orbit/extensions.load"; do
		if [ -s "$f" ]; then
			die "orbit loads osquery extensions from $f (Fleet's extensions agent option), so osquery ignores $LOAD. Deliver hawkbell through that agent option, or use TIER=atc and ATC."
		fi
	done
fi

eval "url=\$URL_$(echo "${os}_$arch" | tr a-z A-Z)"
eval "want=\$SHA_$(echo "${os}_$arch" | tr a-z A-Z)"
echo "$want" | grep -Eq '^[0-9a-f]{64}$' || die "no valid SHA-256 configured for ${os}_$arch"

sha() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
	else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "${HAWKBELL_SRC:-}" ]; then
	cp "$HAWKBELL_SRC" "$tmp/hawkbell"
elif command -v curl >/dev/null 2>&1; then
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/hawkbell" "$url" || die "download failed: $url"
else
	wget -q --https-only -O "$tmp/hawkbell" "$url" || die "download failed: $url"
fi
got=$(sha "$tmp/hawkbell")
[ "$got" = "$want" ] || die "SHA-256 mismatch for $url: got $got"
chmod 0755 "$tmp/hawkbell"

changed=0
# put SRC DST MODE: replace DST atomically when its content differs.
put() {
	if [ -f "$2" ] && cmp -s "$1" "$2"; then return 0; fi
	cp "$1" "$2.new" && chown 0:0 "$2.new" && chmod "$3" "$2.new" && mv -f "$2.new" "$2"
	changed=1
}

# Group whose members (a log shipper) may read the outbox.
if [ $os = linux ]; then
	getent group hawkbell >/dev/null 2>&1 || groupadd --system hawkbell
else
	dscl . -read /Groups/hawkbell >/dev/null 2>&1 || dseditgroup -o create -r "hawkbell outbox readers" hawkbell
fi

mkdir -p "$(dirname "$BIN")" "$CONFDIR"
install -d -m 0755 -o 0 -g 0 "$EXTDIR"
if [ $os = linux ]; then
	install -d -m 0755 "$CONFDIR"
	# 0711 as in the unit: hooks traverse it (spool, bundle).
	install -d -m 0711 -o 0 -g hawkbell "$DATA"
else
	chmod 0755 "$CONFDIR"
	install -d -m 0755 "$ROOT/Library/Logs/hawkbell"
fi
put "$tmp/hawkbell" "$BIN" 0755
bin_changed=$changed

CONF=$CONFDIR/hawkbell.yaml
[ -f "$CONF" ] || "$BIN" export config --out "$CONF" || echo "hawkbell install: warning: could not write $CONF" >&2

if [ $os = linux ]; then
	command -v systemctl >/dev/null 2>&1 || die "systemd is required"
	UNIT=$ROOT/etc/systemd/system/hawkbell.service
	mkdir -p "$(dirname "$UNIT")"
	cat >"$tmp/unit" <<'EOF'
[Unit]
Description=hawkbell AI agent detection sensor
Documentation=https://github.com/thomastysong/thomastysong/tree/main/hawkbell
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/hawkbell run --config /etc/hawkbell/hawkbell.yaml
Restart=always
RestartSec=5s
TimeoutStopSec=20s
Group=hawkbell
StateDirectory=hawkbell
StateDirectoryMode=0711
RuntimeDirectory=hawkbell
RuntimeDirectoryMode=0755
UMask=0027
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/hawkbell /run/hawkbell
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN CAP_CHOWN CAP_FOWNER
AmbientCapabilities=
Nice=5
IOSchedulingClass=idle
CPUWeight=50
MemoryHigh=256M
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
	# StateDirectory= gives /var/lib/hawkbell the service's group at start
	# (root without Group=). DB 0600, spools 0700: the group reads the outbox.
	printf '[Service]\nGroup=hawkbell\n' >"$tmp/group.conf"
	changed=0
	put "$tmp/unit" "$UNIT" 0644
	mkdir -p "$UNIT.d"
	put "$tmp/group.conf" "$UNIT.d/10-outbox-group.conf" 0644
	[ $changed = 1 ] && systemctl daemon-reload
	systemctl enable hawkbell >/dev/null 2>&1 || true
	if [ $changed = 1 ] || [ $bin_changed = 1 ]; then systemctl restart hawkbell; else systemctl start hawkbell; fi
else
	LABEL=com.github.thomastysong.hawkbell
	PLIST=$ROOT/Library/LaunchDaemons/$LABEL.plist
	cat >"$tmp/plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.github.thomastysong.hawkbell</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/hawkbell</string>
    <string>run</string>
    <string>--config</string>
    <string>/Library/Application Support/hawkbell/hawkbell.yaml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>5</integer>
  <key>Umask</key><integer>23</integer>
  <key>ExitTimeOut</key><integer>20</integer>
  <key>StandardErrorPath</key><string>/Library/Logs/hawkbell/hawkbell.log</string>
</dict>
</plist>
EOF
	changed=0
	put "$tmp/plist" "$PLIST" 0644
	if [ $changed = 1 ] || [ $bin_changed = 1 ]; then
		launchctl bootout system/$LABEL >/dev/null 2>&1 || true
		launchctl bootstrap system "$PLIST"
	else
		launchctl print system/$LABEL >/dev/null 2>&1 || launchctl bootstrap system "$PLIST"
	fi
fi

# Hooks an earlier release wrote read "modified" until reinstalled. Only
# already-hooked agents, with their options; system is Codex's own tier.
"$BIN" hooks install --only-installed --scope managed ${ROOT:+--root "$ROOT"} --binary "${BIN#"$ROOT"}" ||
	echo "hawkbell install: warning: managed hooks not refreshed" >&2
"$BIN" hooks install --only-installed --scope system ${ROOT:+--root "$ROOT"} --binary "${BIN#"$ROOT"}" ||
	echo "hawkbell install: warning: system hooks not refreshed" >&2

# osquery loads only a root-owned *.ext that others cannot write. A copy,
# not a link: osquery checks the file it opens.
changed=0
load_changed=0
if [ "$TIER" = extension ]; then
	put "$BIN" "$EXT" 0755
	install -d -m 0755 "$(dirname "$LOAD")"
	if ! grep -qxF "$EXT" "$LOAD" 2>/dev/null; then
		# A last line without a newline would join ours.
		if [ -s "$LOAD" ] && [ -n "$(tail -c 1 "$LOAD")" ]; then echo >>"$LOAD"; fi
		printf '%s\n' "$EXT" >>"$LOAD"
		load_changed=1
	fi
	chown 0:0 "$LOAD" && chmod 0644 "$LOAD"
elif [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	grep -vxF "$EXT" "$LOAD" >"$tmp/load" || true
	cat "$tmp/load" >"$LOAD"
	load_changed=1
fi

# Restart osquery to load the extension, detached and delayed: under orbit a
# synchronous restart would kill this script before Fleet gets its result.
if [ $changed = 1 ] || [ $load_changed = 1 ]; then
	if [ $os = linux ]; then
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
	echo "hawkbell install: osquery ($svc) restarts in 10 s to load $EXT"
fi
echo "hawkbell install: $("$BIN" version 2>/dev/null || echo hawkbell) installed at $BIN (tier $TIER)"
