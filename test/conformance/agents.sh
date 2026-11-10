#!/bin/sh
# An AI agent's socket, as docs/agents.md sets it up, end to end on a real Docker:
#   - agents are scopes on a listener with scope sockets, in a group of their own;
#   - an agent runs in a container, as a user in that group, its socket alone mounted at
#     /var/run/docker.sock: the Docker CLI and Compose use it with no configuration;
#   - its typical calls work (run, exec, logs, rm, Compose), escapes and others' objects don't.
# The sockets' folder is the volume ygc-agents (run.sh mounts it at /agents): an agent's container
# mounts its one socket from it (volume-subpath). Names start with ygca-. Run it through run.sh.
set -u

dir=/tmp/agents
sockets=/agents
group=2100
cli=docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb
label=com.docker.compose.project
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"

# What an agent runs, in its container
ana() { direct exec ygca-agent-ana "$@"; }
# Agent bob, straight through its socket (from here)
bob() { env -u DOCKER_HOST -u DOCKER_CONFIG docker -H "unix://$sockets/ygca-bob.sock" "$@"; }

cleanup() {
	for agent in ygca-ana ygca-bob; do
		direct ps -aq --filter "label=$label=$agent" | xargs -r docker rm -f >/dev/null 2>&1
		direct network ls -q --filter "label=$label=$agent" | xargs -r docker network rm >/dev/null 2>&1
	done
	direct rm -f ygca-agent-ana ygca-agent-nogroup >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== Docker $(direct version --format '{{.Server.Version}}'): an agent's socket (docs/agents.md)"
mkdir -p "$dir/scopes"
for agent in ygca-ana ygca-bob; do
	printf '{"owner": {"label": "%s", "value": "%s"}, "prefixes": ["%s-", "%s_"], "images": ["agents/%s/"]}\n' \
		"$label" "$agent" "$agent" "$agent" "$agent" > "$dir/scopes/$agent.json"
done
chmod 600 "$dir/scopes/"*.json

cat > "$dir/yorvogate.yaml" <<EOF
upstream: unix:///var/run/docker.sock
listeners:
  - name: agents
    scope_sockets: $sockets
    socket_group: "$group"
    mode: scoped
    scopes: $dir/scopes
EOF
without_lsm "$dir/yorvogate.yaml"

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
for _ in $(seq 20); do
	[ -S "$sockets/ygca-ana.sock" ] && [ -S "$sockets/ygca-bob.sock" ] && break
	sleep 0.5
done

direct image inspect alpine:3.22 >/dev/null 2>&1 || direct pull -q alpine:3.22 >/dev/null
direct image inspect "$cli" >/dev/null 2>&1 || direct pull -q "$cli" >/dev/null

if [ "$(stat -c '%a %g' "$sockets/ygca-ana.sock")" = "660 $group" ]; then ok "the socket: mode 660, the agents' group"; else ko "the socket's mode and group" "$(stat -c '%a %g' "$sockets/ygca-ana.sock")"; fi

# Agent ana, as the docs run it: a user in the socket's group, its socket alone
works "the agent's container starts" direct run -d --name ygca-agent-ana --user 1000:1000 --group-add "$group" -e HOME=/tmp \
	--mount type=volume,src=ygc-agents,dst=/var/run/docker.sock,volume-subpath=ygca-ana.sock --entrypoint sleep "$cli" 900

say "== The agent's typical calls, with no configuration"
works "docker version" ana docker version
works "network create (its own)" ana docker network create --label "$label=ygca-ana" ygca-ana-net
works "docker run" ana docker run -d --name ygca-ana-web --label "$label=ygca-ana" --network ygca-ana-net alpine:3.22 sh -c 'echo started; sleep 600'
works "docker exec" ana docker exec ygca-ana-web sh -c 'echo hi > /tmp/hi'
if ana docker logs ygca-ana-web 2>&1 | grep -q started; then ok "docker logs"; else ko "docker logs" "$(ana docker logs ygca-ana-web 2>&1)"; fi
works "docker run --rm (a one-off)" ana docker run --rm --name ygca-ana-once --label "$label=ygca-ana" --network none alpine:3.22 true
works "docker rm -f" ana docker rm -f ygca-ana-web

ana sh -c 'mkdir -p /tmp/app && printf "services:\n  web:\n    image: alpine:3.22\n    command: [sleep, \"600\"]\n" > /tmp/app/compose.yaml'
works "compose up --wait (project = its owner)" ana docker compose -p ygca-ana -f /tmp/app/compose.yaml up -d --wait
works "compose ps" ana docker compose -p ygca-ana -f /tmp/app/compose.yaml ps
works "compose down" ana docker compose -p ygca-ana -f /tmp/app/compose.yaml down

say "== What the socket can't do"
refused "the host's / mounted" "never a host path" ana docker run --rm --name ygca-ana-x --label "$label=ygca-ana" --network none -v /:/host alpine:3.22 true
refused "a privileged container" "privileged" ana docker run --rm --name ygca-ana-x --label "$label=ygca-ana" --network none --privileged alpine:3.22 true
refused "the host's PID namespace" "namespaces" ana docker run --rm --name ygca-ana-x --label "$label=ygca-ana" --network none --pid host alpine:3.22 true
refused "the default bridge" "NetworkMode" ana docker run --rm --name ygca-ana-x --label "$label=ygca-ana" alpine:3.22 true
refused "a name not its own" "isn't one of scope ygca-ana's" ana docker run --rm --name web --label "$label=ygca-ana" --network none alpine:3.22 true
refused "another agent's label" "must carry the label" ana docker run --rm --name ygca-ana-x --label "$label=ygca-bob" --network none alpine:3.22 true

works "bob's container (through bob's socket)" bob run -d --name ygca-bob-web --label "$label=ygca-bob" --network none alpine:3.22 sleep 600
works "a container of its own, to list" ana docker run -d --name ygca-ana-web --label "$label=ygca-ana" --network none alpine:3.22 sleep 600
if ! seen=$(ana docker ps -a --format '{{.Names}}' 2>&1); then ko "ps" "$seen"; elif [ "$seen" = ygca-ana-web ]; then ok "ps lists only its own (not bob's, not the host's)"; else ko "ps lists only its own" "$seen"; fi
refused "exec in bob's container" "No such container" ana docker exec ygca-bob-web true
refused "remove bob's container" "No such container" ana docker rm ygca-bob-web
# rm -f says nothing of a container that doesn't exist: what counts is that bob's is still there.
ana docker rm -f ygca-bob-web >/dev/null 2>&1
if [ "$(direct inspect -f '{{.State.Running}}' ygca-bob-web 2>&1)" = true ]; then ok "rm -f of bob's container: still running"; else ko "rm -f of bob's container" "$(direct ps -a --filter name=ygca-bob 2>&1)"; fi
refused "its own agent container (the host's)" "No such container" ana docker container inspect ygca-agent-ana

say "== The socket is the agent's only"
direct run -d --name ygca-agent-nogroup --user 1000:1000 -e HOME=/tmp \
	--mount type=volume,src=ygc-agents,dst=/var/run/docker.sock,volume-subpath=ygca-ana.sock --entrypoint sleep "$cli" 900 >/dev/null
if output=$(direct exec ygca-agent-nogroup docker version 2>&1); then ko "a user outside the group can't connect" "$output"; elif printf '%s' "$output" | grep -q 'permission denied'; then ok "a user outside the group can't connect"; else ko "a user outside the group can't connect (not for its mode)" "$output"; fi
if ana sh -c 'ls /var/run; test ! -e /var/run/ygca-bob.sock' >/dev/null 2>&1; then ok "no other agent's socket in its container"; else ko "no other agent's socket in its container" "$(ana ls -la /var/run 2>&1)"; fi

say "$passed passed, $failed failed"
[ "$failed" = 0 ]
