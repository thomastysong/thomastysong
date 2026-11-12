#!/usr/bin/env bash
# Live verification of the Fleet content in deploy/fleet against a running
# Fleet server and one enrolled osquery host. deploy/fleet/VERIFIED.md is
# the captured output of a run.
#
# What it does, and what it never does:
#   - validates deploy/fleet/gitops/default.yml with `fleetctl gitops
#     --dry-run` only. It never runs gitops for real: gitops resets or
#     deletes everything its files omit, on a shared server too;
#   - saves the server's agent options (`fleetctl get config --yaml` and
#     --json), applies them with spoor's ATC tables merged in
#     (fleetgen.MergeAgentOptions), and restores the saved copy on exit,
#     then checks the restored copy is identical;
#   - applies the stock profile's labels, policies and reports one by one
#     with `fleetctl apply -f`, every name prefixed with $PREFIX, and deletes
#     exactly those on exit;
#   - for each scenario (healthy, planted finding, heartbeat 2 h old,
#     heartbeat 25 h old, state database removed) writes the state database
#     the host's osquery reads, runs every spoor_* table and every policy as
#     a live query, triggers a host refetch and compares Fleet's own policy
#     results and label membership with the expected ones;
#   - optionally (EXT_LOAD, EXT_BIN, OSQUERY_RESTART set) repeats the checks
#     with the spoor osquery extension instead of ATC, then unregisters it.
#
# The state database comes from the Fleet harness in test/e2e/fleet_test.go
# (state.Store.Apply with real-shaped events), or, when SPOOR_BIN names a
# spoor binary, the healthy one from `spoor scan --state` and `spoor run`.
#
# Environment:
#   FLEETCTL         fleetctl, logged in to the server (default: fleetctl)
#   FLEET_HOST       hostname of the enrolled host (default: vm)
#   WORK             artifact directory, the state database lives here
#                    (default: a new temporary directory)
#   PREFIX           name prefix of every object applied (default: spoor-c5-)
#   SPOOR_BIN        optional spoor binary, see above
#   EXT_LOAD         the host osqueryd's --extensions_autoload file
#   EXT_BIN          an extension binary (*.ext) serving $WORK/data/state.db
#   OSQUERY_RESTART  shell command that restarts the host's osqueryd
#   FLEET_URL        server URL for the dry run (default: https://localhost:8412)
#   POLL             seconds between polls of the host (default: 3)
#   SPOOR_VERIFY_LIB=1 with `source`: define the functions only (unit tests)
set -euo pipefail

FLEETCTL=${FLEETCTL:-fleetctl}
FLEET_HOST=${FLEET_HOST:-vm}
PREFIX=${PREFIX:-spoor-c5-}
POLL=${POLL:-3}
WORK=${WORK:-$(mktemp -d)}
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DB=$WORK/data/state.db
BIN=$WORK/bin/spoor

ts() { date -u +%H:%M:%S; }
log() { echo "[$(ts)] $*"; }
fc() { "$FLEETCTL" "$@"; }
api() { "$FLEETCTL" api "$@"; }
die() {
	log "FAILED: $*"
	exit 1
}
FAILURES=0
check() { # check NAME GOT WANT
	if [ "$2" = "$3" ]; then
		printf '  ok    %-70s %s\n' "$1" "$2"
	else
		printf '  FAIL  %-70s got %s, want %s\n' "$1" "$2" "$3"
		FAILURES=$((FAILURES + 1))
	fi
}

# live SQL -> prints the JSON result line ({"host","rows","error"}). A poll
# that returns nothing (host slow to answer, fleetctl error) prints an error
# line instead of failing, so pipefail and set -e do not end the run.
live() {
	local out
	out=$(fc report --hosts "$FLEET_HOST" --query "$1" --exit --quiet --timeout 90s 2>/dev/null | grep '^{' | head -n 1) || true
	if [ -z "$out" ]; then out='{"rows":[],"error":"no result from the host"}'; fi
	printf '%s\n' "$out"
}

# append_line FILE LINE: add LINE unless present, never gluing it to a last
# line that has no newline.
append_line() {
	if grep -qxF "$2" "$1" 2>/dev/null; then return 0; fi
	if [ -s "$1" ] && [ -n "$(tail -c 1 "$1")" ]; then echo >>"$1"; fi
	printf '%s\n' "$2" >>"$1"
}

harness() { # harness TEST [SCENARIO]
	(cd "$REPO" && SPOOR_E2E_FLEET=1 SPOOR_FLEET_OUT="$WORK" SPOOR_FLEET_DB="$DB" SPOOR_FLEET_BIN="$BIN" \
		SPOOR_FLEET_PREFIX="$PREFIX" SPOOR_FLEET_AGENT_OPTIONS="$WORK/agent-options.before.json" \
		SPOOR_FLEET_SCENARIO="${2:-}" go test -tags e2e ./test/e2e -run "^$1\$" -count=1) >"$WORK/harness.out" 2>&1 ||
		{
			cat "$WORK/harness.out"
			die "harness $1 $2"
		}
}

build_db() { # build_db SCENARIO
	if [ -n "${SPOOR_BIN:-}" ] && [ "$1" = healthy ]; then
		rm -f "$DB" "$DB-wal" "$DB-shm"
		printf 'data_dir: %s\n' "$WORK/data" >"$WORK/spoor.yaml"
		"$SPOOR_BIN" scan --state --config "$WORK/spoor.yaml" >/dev/null
		timeout 20 "$SPOOR_BIN" run --config "$WORK/spoor.yaml" >/dev/null 2>&1 || true
	else
		harness TestFleetStateDB "$1"
	fi
}

prefixed_policy_ids() {
	api /api/v1/fleet/global/policies | jq -r --arg p "$PREFIX" '[.policies // [] | .[] | select(.name | startswith($p)) | .id] | join(",")'
}

cleanup() {
	set +e
	log "cleanup"
	if [ -f "$WORK/specs.yml" ]; then fc delete -f "$WORK/specs.yml" >/dev/null 2>&1; fi
	ids=$(prefixed_policy_ids)
	if [ -n "$ids" ]; then api -X POST -F "ids=[$ids]" /api/v1/fleet/global/policies/delete >/dev/null; fi
	fc apply -f "$WORK/agent-options.restore.yml" >/dev/null
	if [ "$EXT_REGISTERED" = 1 ]; then
		grep -vxF "$EXT_BIN" "$EXT_LOAD" >"$WORK/load.tmp" || true
		cat "$WORK/load.tmp" >"$EXT_LOAD"
		sh -c "$OSQUERY_RESTART"
		log "extension unregistered from $EXT_LOAD, osqueryd restarted"
	fi
	fc get config --json | jq '.spec.agent_options' >"$WORK/agent-options.after.json"
	if diff <(jq -S . "$WORK/agent-options.before.json") <(jq -S . "$WORK/agent-options.after.json") >/dev/null; then
		log "agent options restored: identical to the saved copy"
	else
		log "AGENT OPTIONS DIFFER FROM THE SAVED COPY:"
		diff <(jq -S . "$WORK/agent-options.before.json") <(jq -S . "$WORK/agent-options.after.json")
	fi
	left_labels=$(fc get labels --yaml 2>/dev/null | grep -c "name: $PREFIX" || true)
	left_reports=$(api /api/v1/fleet/reports | jq --arg p "$PREFIX" '[.queries // .reports // [] | .[] | select(.name | startswith($p))] | length')
	left_policies=$(prefixed_policy_ids)
	log "objects named $PREFIX* left on the server: labels $left_labels, reports $left_reports, policies [${left_policies}]"
	log "done: $FAILURES failed checks"
}

wait_tables() { # wait_tables N: until N spoor tables are registered
	local n=0
	for _ in $(seq 1 40); do
		n=$(live "SELECT count(*) AS n FROM osquery_registry WHERE registry = 'table' AND name LIKE 'spoor\_%' ESCAPE '\\' AND active = 1" | jq -r '.rows[0].n // 0' 2>/dev/null) || n=0
		if [ "$n" = "$1" ]; then return 0; fi
		sleep "$POLL"
	done
	die "spoor tables registered: $n, want $1"
}

refetch() { # refetch: wait until Fleet has fresh policy and label results
	local t0 h p l
	t0=$(date -u +%s)
	api -X POST "/api/v1/fleet/hosts/$HOST_ID/refetch" >/dev/null
	for _ in $(seq 1 60); do
		sleep "$POLL"
		# A failed or partial poll is retried, not fatal.
		h=$(api "/api/v1/fleet/hosts/$HOST_ID" 2>/dev/null) || continue
		p=$(echo "$h" | jq -r '(.host.policy_updated_at // "1970-01-01T00:00:00Z") | sub("\\.[0-9]+"; "") | fromdateiso8601' 2>/dev/null) || p=0
		l=$(echo "$h" | jq -r '(.host.label_updated_at // "1970-01-01T00:00:00Z") | sub("\\.[0-9]+"; "") | fromdateiso8601' 2>/dev/null) || l=0
		if [ "${p:-0}" -gt "$t0" ] && [ "${l:-0}" -gt "$t0" ]; then
			echo "$h" >"$WORK/host.json"
			return 0
		fi
	done
	die "host did not report policy and label results after refetch"
}

tables() {
	echo "  live query of every spoor table:"
	while read -r t; do
		r=$(live "SELECT * FROM $t")
		err=$(echo "$r" | jq -r '.error // empty')
		if [ -n "$err" ]; then
			printf '  FAIL  %-28s error: %s\n' "$t" "$err"
			FAILURES=$((FAILURES + 1))
		else
			printf '        %-28s %s rows; columns: %s\n' "$t" "$(echo "$r" | jq '.rows | length')" \
				"$(echo "$r" | jq -r '.rows[0] // {} | keys | join(",")' | cut -c1-90)"
		fi
	done <"$WORK/tables.txt"
}

scenario() { # scenario NAME TIER
	local sc=$1 tier=$2
	log "== scenario $sc ($tier)"
	build_db "$sc"
	if [ "$sc" = removed ]; then echo "  state database removed: $(ls "$DB" 2>&1 | head -n 1)"; fi
	if [ "$sc" = healthy ]; then tables; fi
	echo "  policies evaluated as live queries (a row = pass):"
	while IFS=$'\t' read -r name sql; do
		r=$(live "$sql")
		err=$(echo "$r" | jq -r '.error // empty')
		got=fail
		if [ "$(echo "$r" | jq '.rows | length')" -gt 0 ]; then got=pass; fi
		if [ -n "$err" ]; then got="error: $err"; fi
		check "$name" "$got" "$(jq -r --arg s "$sc" --arg n "$name" '.[$s].policies[$n]' "$WORK/expected.json")"
	done <"$WORK/policies.tsv"
	refetch
	echo "  Fleet policy results after refetch:"
	# Process substitution, not a pipe: check counts failures in this shell.
	while IFS=$'\t' read -r name resp; do
		check "$name" "${resp:-no response}" "$(jq -r --arg s "$sc" --arg n "$name" '.[$s].policies[$n]' "$WORK/expected.json")"
	done < <(jq -r --arg p "$PREFIX" '.host.policies[] | select(.name | startswith($p)) | "\(.name)\t\(.response)"' "$WORK/host.json")
	echo "  label membership after refetch:"
	while read -r name; do
		got="not member"
		if jq -e --arg n "$name" '.host.labels[] | select(.name == $n)' "$WORK/host.json" >/dev/null; then got=member; fi
		check "$name" "$got" "$(jq -r --arg s "$sc" --arg n "$name" '.[$s].labels[$n]' "$WORK/expected.json")"
	done < <(jq -r --arg s "$sc" '.[$s].labels | keys[]' "$WORK/expected.json")
}

if [ "${SPOOR_VERIFY_LIB:-}" = 1 ]; then return 0; fi

# ---- main ----
mkdir -p "$WORK/data" "$WORK/bin"
exec > >(tee "$WORK/verify.log") 2>&1

HOST_ID=$(api /api/v1/fleet/hosts | jq -r --arg h "$FLEET_HOST" '.hosts[] | select(.hostname == $h) | .id')
[ -n "$HOST_ID" ] || die "host $FLEET_HOST not enrolled"
log "Fleet $(api /api/v1/fleet/version | jq -r .version), host $FLEET_HOST (id $HOST_ID), work dir $WORK"
log "osquery $(live 'SELECT version FROM osquery_info' | jq -r '.rows[0].version')"

# ---- save state, and restore it whatever happens ----
fc get config --yaml >"$WORK/config.before.yml"
fc get config --json | jq '.spec.agent_options' >"$WORK/agent-options.before.json"
jq '{apiVersion: "v1", kind: "config", spec: {agent_options: .}}' "$WORK/agent-options.before.json" >"$WORK/agent-options.restore.yml"
log "saved agent options ($(wc -c <"$WORK/agent-options.before.json") bytes) to $WORK/agent-options.before.json"
EXT_REGISTERED=0
trap cleanup EXIT

# ---- GitOps files: validation only ----
log "fleetctl gitops --dry-run deploy/fleet/gitops/default.yml"
(cd "$REPO/deploy/fleet/gitops" && FLEET_URL=${FLEET_URL:-https://localhost:8412} \
	FLEET_GLOBAL_ENROLL_SECRET=dry-run-only-not-a-secret fc gitops --dry-run -f default.yml) | sed 's/^/  /'

# ---- generated content for this host's paths ----
harness TestFleetContent
log "harness wrote specs, merged agent options and expectations for DB $DB"
fc apply -f "$WORK/atc-apply.yml" | sed 's/^/  /'
fc apply -f "$WORK/specs.yml" | sed 's/^/  /'

log "== tier 2: ATC"
wait_tables "$(wc -l <"$WORK/tables.txt")"
log "all $(wc -l <"$WORK/tables.txt") spoor tables registered through ATC"
for sc in healthy planted stale stale25h removed; do scenario "$sc" ATC; done

log "== reports (stock profile and opt-in exec reports) as live queries on the healthy database"
build_db healthy
while IFS=$'\t' read -r name platform sql; do
	r=$(live "$sql")
	res="$(echo "$r" | jq '.rows | length') rows"
	err=$(echo "$r" | jq -r '.error // empty')
	if [ -n "$err" ]; then res="error: $err"; fi
	printf '        %-62s [%s] %s\n' "$name" "$platform" "$res"
done <"$WORK/reports.tsv"

if [ -n "${EXT_LOAD:-}" ] && [ -n "${EXT_BIN:-}" ] && [ -n "${OSQUERY_RESTART:-}" ]; then
	log "== tier 3: osquery extension $EXT_BIN"
	# ATC and the extension provide the same table names: take ATC away first.
	fc apply -f "$WORK/agent-options.restore.yml" | sed 's/^/  /'
	wait_tables 0
	log "ATC tables gone; registering the extension in $EXT_LOAD"
	append_line "$EXT_LOAD" "$EXT_BIN"
	EXT_REGISTERED=1
	sh -c "$OSQUERY_RESTART"
	wait_tables "$(wc -l <"$WORK/tables.txt")"
	echo "  $(live "SELECT name, version, type, path FROM osquery_extensions WHERE name = 'spoor'" | jq -c '.rows')"
	for sc in healthy planted removed; do scenario "$sc" extension; done
fi
