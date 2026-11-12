#!/bin/sh
# Install or update the spoor sensor and register it as an osquery extension.
# Fleet script for macOS and Linux (runs as root); safe to run again.
# Set the URL and SHA-256 of each build below. A value may name a Fleet
# custom variable (FLEET_SECRET_* with a leading dollar sign): Fleet fills it
# in before the script runs, and fleetctl gitops then requires it to be set,
# even in a comment. SPOOR_TIER=atc skips the extension (tier 2: osquery
# reads the state DB through ATC agent options).
set -eu
umask 022

URL_LINUX_AMD64=${SPOOR_URL_LINUX_AMD64:-https://downloads.example.com/spoor/0.1.0/spoor_linux_amd64}
SHA_LINUX_AMD64=${SPOOR_SHA256_LINUX_AMD64:-REPLACE_WITH_SHA256}
URL_LINUX_ARM64=${SPOOR_URL_LINUX_ARM64:-https://downloads.example.com/spoor/0.1.0/spoor_linux_arm64}
SHA_LINUX_ARM64=${SPOOR_SHA256_LINUX_ARM64:-REPLACE_WITH_SHA256}
URL_DARWIN_AMD64=${SPOOR_URL_DARWIN_AMD64:-https://downloads.example.com/spoor/0.1.0/spoor_darwin_amd64}
SHA_DARWIN_AMD64=${SPOOR_SHA256_DARWIN_AMD64:-REPLACE_WITH_SHA256}
URL_DARWIN_ARM64=${SPOOR_URL_DARWIN_ARM64:-https://downloads.example.com/spoor/0.1.0/spoor_darwin_arm64}
SHA_DARWIN_ARM64=${SPOOR_SHA256_DARWIN_ARM64:-REPLACE_WITH_SHA256}
TIER=${SPOOR_TIER:-extension}
ROOT=${SPOOR_ROOT:-} # test prefix; empty on real hosts

die() { echo "spoor install: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
case $TIER in extension | atc) ;; *) die "SPOOR_TIER must be extension or atc" ;; esac

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
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
# orbit rewrites its own autoload file; osquery's default one is ours to use.
case $LOAD in */orbit/*) die "refusing to write orbit's extensions.load" ;; esac

eval "url=\$URL_$(echo "${os}_$arch" | tr a-z A-Z)"
eval "want=\$SHA_$(echo "${os}_$arch" | tr a-z A-Z)"
echo "$want" | grep -Eq '^[0-9a-f]{64}$' || die "no valid SHA-256 configured for ${os}_$arch"

sha() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
	else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "${SPOOR_SRC:-}" ]; then
	cp "$SPOOR_SRC" "$tmp/spoor"
elif command -v curl >/dev/null 2>&1; then
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/spoor" "$url" || die "download failed: $url"
else
	wget -q --https-only -O "$tmp/spoor" "$url" || die "download failed: $url"
fi
got=$(sha "$tmp/spoor")
[ "$got" = "$want" ] || die "SHA-256 mismatch for $url: got $got"
chmod 0755 "$tmp/spoor"

changed=0
# put SRC DST MODE: replace DST atomically when its content differs.
put() {
	if [ -f "$2" ] && cmp -s "$1" "$2"; then return 0; fi
	cp "$1" "$2.new" && chown 0:0 "$2.new" && chmod "$3" "$2.new" && mv -f "$2.new" "$2"
	changed=1
}

# Group whose members (a log shipper) may read the outbox.
if [ $os = linux ]; then
	getent group spoor >/dev/null 2>&1 || groupadd --system spoor
else
	dscl . -read /Groups/spoor >/dev/null 2>&1 || dseditgroup -o create -r "spoor outbox readers" spoor
fi

mkdir -p "$(dirname "$BIN")" "$CONFDIR"
install -d -m 0755 -o 0 -g 0 "$EXTDIR"
if [ $os = linux ]; then
	install -d -m 0755 "$CONFDIR"
	install -d -m 0750 -o 0 -g spoor "$DATA"
else
	chmod 0755 "$CONFDIR"
	install -d -m 0755 "$ROOT/Library/Logs/spoor"
fi
put "$tmp/spoor" "$BIN" 0755
bin_changed=$changed

CONF=$CONFDIR/spoor.yaml
[ -f "$CONF" ] || "$BIN" export config --out "$CONF" || echo "spoor install: warning: could not write $CONF" >&2

if [ $os = linux ]; then
	command -v systemctl >/dev/null 2>&1 || die "systemd is required"
	UNIT=$ROOT/etc/systemd/system/spoor.service
	mkdir -p "$(dirname "$UNIT")"
	cat >"$tmp/unit" <<'EOF'
[Unit]
Description=spoor AI agent detection sensor
Documentation=https://github.com/thomastysong/thomastysong/tree/main/spoor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/spoor run --config /etc/spoor/spoor.yaml
Restart=always
RestartSec=5s
TimeoutStopSec=20s
StateDirectory=spoor
StateDirectoryMode=0750
RuntimeDirectory=spoor
RuntimeDirectoryMode=0755
UMask=0027
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/spoor /run/spoor
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
	changed=0
	put "$tmp/unit" "$UNIT" 0644
	[ $changed = 1 ] && systemctl daemon-reload
	systemctl enable spoor >/dev/null 2>&1 || true
	if [ $changed = 1 ] || [ $bin_changed = 1 ]; then systemctl restart spoor; else systemctl start spoor; fi
else
	LABEL=com.github.thomastysong.spoor
	PLIST=$ROOT/Library/LaunchDaemons/$LABEL.plist
	cat >"$tmp/plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.github.thomastysong.spoor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/spoor</string>
    <string>run</string>
    <string>--config</string>
    <string>/Library/Application Support/spoor/spoor.yaml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>5</integer>
  <key>Umask</key><integer>23</integer>
  <key>ExitTimeOut</key><integer>20</integer>
  <key>StandardErrorPath</key><string>/Library/Logs/spoor/spoor.log</string>
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

# osquery loads an extension only from a root-owned path that others cannot
# write, named *.ext. A copy, not a link: osquery checks the file it opens.
changed=0
load_changed=0
if [ "$TIER" = extension ]; then
	put "$BIN" "$EXT" 0755
	install -d -m 0755 "$(dirname "$LOAD")"
	if ! grep -qxF "$EXT" "$LOAD" 2>/dev/null; then
		printf '%s\n' "$EXT" >>"$LOAD"
		load_changed=1
	fi
	chown 0:0 "$LOAD" && chmod 0644 "$LOAD"
elif [ -f "$LOAD" ] && grep -qxF "$EXT" "$LOAD"; then
	grep -vxF "$EXT" "$LOAD" >"$tmp/load" || true
	cat "$tmp/load" >"$LOAD"
	load_changed=1
fi

# Restart osquery so it loads the extension: detached and delayed, because
# this script usually runs under orbit and a synchronous restart would kill
# it before Fleet gets its result.
if [ $changed = 1 ] || [ $load_changed = 1 ]; then
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
	echo "spoor install: osquery ($svc) restarts in 10 s to load $EXT"
fi
echo "spoor install: $("$BIN" version 2>/dev/null || echo spoor) installed at $BIN (tier $TIER)"
