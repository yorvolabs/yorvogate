#!/bin/sh
# S1 (0.3-g): one scope socket for an untrusted client on a throwaway Docker. The scaffolding an
# agent runs behind: a scoped listener with per-scope unix sockets, started and stopped, leaving
# nothing the caller didn't create. The conformance suite (agents.sh, escapes.sh) and the research
# build's Inspect sandbox stand up the gate the same way, so the gate they measure is the one shipped.
#
# Source it after lib.sh (it uses without_lsm). Usage:
#   sandbox_scope DIR NAME JSON        # a scope file, once per scope, before sandbox_start
#   sandbox_start DIR SOCKETS GROUP NAME...   # write the config, serve, wait for each NAME.sock
#   ... talk to "$SOCKETS/NAME.sock" ...
#   sandbox_stop                       # kill serve (trap it)
# YORVOGATE overrides the binary (default /yorvogate/yorvogate, as the suite mounts it).

# sandbox_scope writes a scope file (mode 600, as a real one is).
sandbox_scope() {
	mkdir -p "$1/scopes"
	printf '%s\n' "$3" > "$1/scopes/$2.json"
	chmod 600 "$1/scopes/$2.json"
}

# sandbox_start writes the scoped-listener config and starts `yorvogate serve`, then waits (up to 10s)
# for each named scope socket to appear. Sets sandbox_gate to the serve pid.
sandbox_start() {
	_dir=$1 _sockets=$2 _group=$3
	shift 3
	cat > "$_dir/yorvogate.yaml" <<EOF
upstream: unix:///var/run/docker.sock
listeners:
  - name: sandbox
    scope_sockets: $_sockets
    socket_group: "$_group"
    mode: scoped
    scopes: $_dir/scopes
EOF
	without_lsm "$_dir/yorvogate.yaml"

	${YORVOGATE:-/yorvogate/yorvogate} serve --config "$_dir/yorvogate.yaml" 2> "$_dir/yorvogate.log" &
	sandbox_gate=$!

	for _ in $(seq 20); do
		_ready=1
		for _n in "$@"; do [ -S "$_sockets/$_n.sock" ] || _ready=0; done
		[ "$_ready" = 1 ] && return 0
		sleep 0.5
	done

	say "sandbox: the scope sockets never appeared"
	sed 's/^/       /' "$_dir/yorvogate.log" | head -5
	return 1
}

# sandbox_stop ends serve. The caller removes the Docker objects it made.
sandbox_stop() {
	[ -n "${sandbox_gate:-}" ] && kill "$sandbox_gate" 2>/dev/null
	sandbox_gate=
}
