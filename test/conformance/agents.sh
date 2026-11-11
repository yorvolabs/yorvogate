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
# shellcheck source-path=SCRIPTDIR source=scope_sandbox.sh
. "$(dirname "$0")/scope_sandbox.sh"

# What an agent runs, in its container
ana() { direct exec ygca-agent-ana "$@"; }
# Agent bob, straight through its socket (from here)
bob() { env -u DOCKER_HOST -u DOCKER_CONFIG docker -H "unix://$sockets/ygca-bob.sock" "$@"; }
# Agent eve, kept off the internet (egress: none), straight through its socket
eve() { env -u DOCKER_HOST -u DOCKER_CONFIG docker -H "unix://$sockets/ygca-eve.sock" "$@"; }

cleanup() {
	for agent in ygca-ana ygca-bob ygca-eve; do
		direct ps -aq --filter "label=$label=$agent" | xargs -r docker rm -f >/dev/null 2>&1
		direct network ls -q --filter "label=$label=$agent" | xargs -r docker network rm >/dev/null 2>&1
	done
	direct rm -f ygca-agent-ana ygca-agent-nogroup ygca-proxy >/dev/null 2>&1
	direct network rm ygca-egress ygca-out >/dev/null 2>&1
	sandbox_stop
}
trap cleanup EXIT
cleanup

say "== Docker $(direct version --format '{{.Server.Version}}'): an agent's socket (docs/agents.md)"
for agent in ygca-ana ygca-bob; do
	sandbox_scope "$dir" "$agent" "$(printf '{"owner": {"label": "%s", "value": "%s"}, "prefixes": ["%s-", "%s_"], "images": ["agents/%s/"]}' "$label" "$agent" "$agent" "$agent" "$agent")"
done
# Eve: no way out but the proxy on the shared internal network ygca-egress (ygca-out has one)
sandbox_scope "$dir" ygca-eve "$(printf '{"owner": {"label": "%s", "value": "ygca-eve"}, "prefixes": ["ygca-eve-", "ygca-eve_"], "networks": {"ygca-egress": {}, "ygca-out": {}}, "egress": "none"}' "$label")"

sandbox_start "$dir" "$sockets" "$group" ygca-ana ygca-bob ygca-eve

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

say "== An agent kept off the internet (egress: none), its way out a proxy"
# The orchestrator's: a shared internal network with the proxy on it, the proxy's own way out, and
# a shared network with one
direct network create --internal ygca-egress >/dev/null
direct network create ygca-out >/dev/null
direct image inspect busybox:1.37 >/dev/null 2>&1 || direct pull -q busybox:1.37 >/dev/null
direct run -d --name ygca-proxy --network ygca-egress busybox:1.37 sh -c 'mkdir -p /www && echo ok > /www/ok && exec httpd -f -p 8080 -h /www' >/dev/null
direct network connect bridge ygca-proxy
if [ "$(direct inspect -f '{{.State.Running}}' ygca-proxy 2>&1)" != true ]; then ko "the orchestrator's proxy runs" "$(direct logs ygca-proxy 2>&1)"; fi
works "eve: an internal network of its own" eve network create --internal --label "$label=ygca-eve" ygca-eve-net
refused "eve: a network with a way out" "may create only internal networks (egress: none)" eve network create --label "$label=ygca-eve" ygca-eve-out
works "eve: a container on its internal network" eve run -d --name ygca-eve-web --label "$label=ygca-eve" --network ygca-eve-net alpine:3.22 sleep 600
refused "eve: a container on a shared network with a way out" "isn't internal (egress: none)" eve run -d --name ygca-eve-x --label "$label=ygca-eve" --network ygca-out alpine:3.22 sleep 600
works "eve: it joins the proxy's network" eve network connect ygca-egress ygca-eve-web
refused "eve: it joins a shared network with a way out" "isn't internal (egress: none)" eve network connect ygca-out ygca-eve-web
if eve exec ygca-eve-web wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1; then ko "eve: no way out to an outside address"; else ok "eve: no way out to an outside address"; fi
if eve exec ygca-eve-web timeout 5 nslookup example.com >/dev/null 2>&1; then ko "eve: an outside name doesn't resolve"; else ok "eve: an outside name doesn't resolve"; fi
if [ "$(eve exec ygca-eve-web wget -q -T 5 -O- http://ygca-proxy:8080/ok 2>&1)" = ok ]; then ok "eve: it reaches the proxy"; else ko "eve: it reaches the proxy" "$(eve exec ygca-eve-web wget -T 5 -O- http://ygca-proxy:8080/ok 2>&1)"; fi
works "bob: a network with a way out (bob isn't egress-free)" bob network create --label "$label=ygca-bob" ygca-bob-out

say "== The socket is the agent's only"
direct run -d --name ygca-agent-nogroup --user 1000:1000 -e HOME=/tmp \
	--mount type=volume,src=ygc-agents,dst=/var/run/docker.sock,volume-subpath=ygca-ana.sock --entrypoint sleep "$cli" 900 >/dev/null
if output=$(direct exec ygca-agent-nogroup docker version 2>&1); then ko "a user outside the group can't connect" "$output"; elif printf '%s' "$output" | grep -q 'permission denied'; then ok "a user outside the group can't connect"; else ko "a user outside the group can't connect (not for its mode)" "$output"; fi
if ana sh -c 'ls /var/run; test ! -e /var/run/ygca-bob.sock' >/dev/null 2>&1; then ok "no other agent's socket in its container"; else ko "no other agent's socket in its container" "$(ana ls -la /var/run 2>&1)"; fi

say "$passed passed, $failed failed"
[ "$failed" = 0 ]
