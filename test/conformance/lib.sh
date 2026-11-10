#!/bin/sh
# What the conformance scripts share: counting checks, and running a command expecting it to work
# or to be refused by YorvoGate.

passed=0
failed=0

say() { printf '%s\n' "$*"; }
ok() { passed=$((passed + 1)); say "  ok   $1"; }
ko() {
	failed=$((failed + 1))
	say "  FAIL $1"
	[ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /' | head -5
	# On GitHub, each failure is an annotation too: readable without the job's log.
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		printf '::error title=Conformance::%s: %s\n' "$1" "$(printf '%s' "${2:-}" | tr '\n' ' ' | cut -c1-300)"
	fi
}

# The real Docker, straight (to set up and to check what exists)
direct() { env -u DOCKER_HOST -u DOCKER_CONFIG docker "$@"; }

# without_lsm adds to a configuration that it accepts a Docker with neither AppArmor nor SELinux,
# when this one has neither (Docker Desktop): a test's setting, never a host's.
without_lsm() {
	if ! direct info --format '{{json .SecurityOptions}}' | grep -q 'name=apparmor\|name=selinux'; then
		printf 'daemon: {without_lsm: true}\n' >> "$1"
	fi
}

# works NAME COMMAND…: it must succeed.
works() {
	name=$1
	shift
	if output=$("$@" 2>&1); then ok "$name"; else ko "$name" "$output"; fi
}

# refused NAME WORDS COMMAND…: it must fail, with YorvoGate's words.
refused() {
	name=$1
	words=$2
	shift 2
	if output=$("$@" 2>&1); then
		ko "$name (it was allowed)" "$output"
	elif printf '%s' "$output" | grep -q "yorvogate: .*$words"; then
		ok "$name"
	else
		ko "$name (not refused by YorvoGate as expected)" "$output"
	fi
}

