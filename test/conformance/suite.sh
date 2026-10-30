#!/bin/sh
# YorvoGate's conformance: YorvoGate in front of a real Docker, driven by the real Docker CLI and
# Compose and by raw HTTP. Two scopes, jane and blog: what each does as a tenant must work; what would
# reach the host or the other must be refused, saying why, and leave nothing behind.
#
# Every attack is a create (or a read): even one that got through would run nothing. Run it through
# run.sh, which gives it a container with Docker's CLI, Compose, Docker's socket and the binary.
set -u

dir=/tmp/conformance
passed=0
failed=0

say() { printf '%s\n' "$*"; }
ok() { passed=$((passed + 1)); say "  ok   $1"; }
ko() { failed=$((failed + 1)); say "  FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /' | head -5; }

# The real Docker, straight (to set up and to check what exists)
direct() { env -u DOCKER_HOST -u DOCKER_CONFIG docker "$@"; }

# A command as a scope, through YorvoGate
as() {
	scope=$1
	shift
	DOCKER_HOST=tcp://127.0.0.1:2376 DOCKER_CONFIG="$dir/$scope" "$@"
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

# raw SCOPE METHOD PATH [BODY]: the status of a hand-written request, as it's written.
request() {
	token=$(cat "$dir/$1.token" 2>/dev/null || echo not-a-token)
	body=${4:-}
	printf '%s %s HTTP/1.1\r\nHost: docker\r\nX-YorvoGate-Scope: %s\r\nX-YorvoGate-Token: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
		"$2" "$3" "$1" "$token" "$(printf '%s' "$body" | wc -c)" "$body"
	# Kept open until YorvoGate answers: a client that half-closes is one that went away.
	sleep 2
}

raw() {
	request "$@" | nc 127.0.0.1 2376 | head -1 | cut -d' ' -f2
}

# status NAME WANT SCOPE METHOD PATH [BODY]: a raw request must get that status.
status() {
	name=$1
	want=$2
	shift 2
	got=$(raw "$@")
	if [ "$got" = "$want" ]; then ok "$name"; else ko "$name (status $got, want $want)"; fi
}

cleanup() {
	for project in ygc-jane ygc-blog; do
		direct ps -aq --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f >/dev/null 2>&1
		direct network ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
		direct volume ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
	done
	direct rmi ygc-jane/app:1 ygc-blog/app:1 >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== Setting up: YorvoGate, scopes jane and blog"
mkdir -p "$dir/scopes"
for scope in jane blog; do
	token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	printf '%s' "$token" > "$dir/$scope.token"
	mkdir -p "$dir/$scope"
	printf '{"HttpHeaders":{"X-YorvoGate-Scope":"%s","X-YorvoGate-Token":"%s"}}\n' "$scope" "$token" > "$dir/$scope/config.json"
	printf '{"token_sha256":"%s","owner":{"label":"com.docker.compose.project","value":"ygc-%s"},"prefixes":["ygc-%s-","ygc-%s_"],"images":["ygc-%s/"]}\n' \
		"$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)" "$scope" "$scope" "$scope" "$scope" > "$dir/scopes/$scope.json"
	chmod 600 "$dir/scopes/$scope.json"
done

cat > "$dir/yorvogate.yaml" <<EOF
upstream: unix:///var/run/docker.sock
listeners:
  - name: tenants
    address: tcp://127.0.0.1:2376
    mode: scoped
    scopes: $dir/scopes
    containers:
      capabilities: [NET_BIND_SERVICE]
      drop_all_capabilities: true
      no_new_privileges: true
      max_memory: 268435456
      max_pids: 128
      protected_images: [ygc-jane/, ygc-blog/]
EOF

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
sleep 1

direct image inspect alpine:3.22 >/dev/null 2>&1 || direct pull -q alpine:3.22 >/dev/null

# A tenant's project: hardened, its own network and volume
project() {
	mkdir -p "$dir/project-$1"
	cat > "$dir/project-$1/compose.yaml" <<EOF
services:
  app:
    image: alpine:3.22
    command: [sleep, "600"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 64
    volumes: [data:/data]
volumes:
  data:
EOF
	printf '%s' "$dir/project-$1/compose.yaml"
}

# A hostile service: hardened as the tenant's, with one thing added (lines under the service, or
# after it). It's a service of its own ("evil"), so Compose leaves jane's running one alone; without a
# network unless the case is about networks ($4 = net).
hostile() {
	file="$dir/hostile-$1.yaml"
	{
		printf 'services:\n  evil:\n    image: %s\n    command: [sleep, "600"]\n' "${3:-alpine:3.22}"
		printf '    cap_drop: [ALL]\n    mem_limit: 64m\n    pids_limit: 64\n'
		case "${4:-}" in *sec*) ;; *) printf '    security_opt: [no-new-privileges:true]\n' ;; esac
		case "${4:-}" in *net*) ;; *) printf '    network_mode: none\n' ;; esac
		printf '%b\n' "$2"
	} > "$file"
	printf '%s' "$file"
}

jane=$(project jane)
blog=$(project blog)

say "== What a tenant does works"
works "jane: compose up (network, volume)" as jane docker compose -p ygc-jane -f "$jane" up -d
works "blog: compose up" as blog docker compose -p ygc-blog -f "$blog" up -d
works "jane: exec, writing to its volume" as jane docker compose -p ygc-jane -f "$jane" exec -T app sh -c 'echo kept > /data/x && cat /data/x'
works "jane: exec -d" as jane docker compose -p ygc-jane -f "$jane" exec -d app true
works "jane: logs" as jane docker compose -p ygc-jane -f "$jane" logs
works "jane: restart" as jane docker compose -p ygc-jane -f "$jane" restart
works "jane: pull" as jane docker pull -q alpine:3.22
works "jane: tag into its namespace" as jane docker tag alpine:3.22 ygc-jane/app:1
works "blog: tag into its namespace" as blog docker tag alpine:3.22 ygc-blog/app:1
works "jane: inspect its image" as jane docker image inspect ygc-jane/app:1

say "== It sees only its own"
if [ "$(as jane docker ps --format '{{.Names}}')" = "ygc-jane-app-1" ]; then ok "docker ps: its container only"; else ko "docker ps" "$(as jane docker ps --format '{{.Names}}')"; fi
if [ "$(as jane docker network ls --format '{{.Name}}')" = "ygc-jane_default" ]; then ok "docker network ls: its network only"; else ko "docker network ls" "$(as jane docker network ls --format '{{.Name}}')"; fi
if [ "$(as jane docker volume ls --format '{{.Name}}')" = "ygc-jane_data" ]; then ok "docker volume ls: its volume only"; else ko "docker volume ls" "$(as jane docker volume ls --format '{{.Name}}')"; fi
if as jane docker image ls --format '{{.Repository}}' | grep -q ygc-blog; then ko "docker image ls: another's image listed"; else ok "docker image ls: not another's"; fi

say "== Another tenant's things are out of reach"
refused "inspect blog's container" "No such container" as jane docker container inspect ygc-blog-app-1
refused "exec in blog's container" "No such container" as jane docker exec ygc-blog-app-1 cat /data/x
refused "kill blog's container" "No such container" as jane docker kill ygc-blog-app-1
refused "remove blog's container" "No such container" as jane docker rm ygc-blog-app-1
# ("docker rm -f" says nothing of a container it doesn't find: it's still there either way.)
as jane docker rm -f ygc-blog-app-1 >/dev/null 2>&1
if direct container inspect ygc-blog-app-1 >/dev/null 2>&1; then ok "blog's container is still there"; else ko "blog's container was removed"; fi
refused "blog's volume" "no such volume" as jane docker volume rm ygc-blog_data
refused "join blog's network" "not found" as jane docker network connect ygc-blog_default ygc-jane-app-1
refused "read blog's image" "No such image" as jane docker image inspect ygc-blog/app:1
refused "tag blog's image" "No such image" as jane docker tag ygc-blog/app:1 ygc-jane/stolen:1
refused "retag a shared name" "image namespaces" as jane docker tag alpine:3.22 alpine:yorvogate-hijack
refused "remove a shared image" "image namespaces" as jane docker rmi alpine:3.22
refused "push" "isn't allowed" as jane docker push ygc-jane/app:1

say "== What reaches the host is refused (Compose)"
refused "privileged" "Privileged isn't allowed" as jane docker compose -p ygc-jane -f "$(hostile privileged '    privileged: true')" up -d
refused "the host's root, bound" "never a host path" as jane docker compose -p ygc-jane -f "$(hostile bind '    volumes: ["/:/host"]')" up -d
refused "the host's network" 'NetworkMode "host"' as jane docker compose -p ygc-jane -f "$(hostile hostnet '    network_mode: host' '' net)" up -d
refused "blog's network namespace" "isn't one of its own" as jane docker compose -p ygc-jane -f "$(hostile netns '    network_mode: container:ygc-blog-app-1' '' net)" up -d
refused "the host's PIDs" "namespaces" as jane docker compose -p ygc-jane -f "$(hostile pid '    pid: host')" up -d
refused "the host's IPC" "namespaces" as jane docker compose -p ygc-jane -f "$(hostile ipc '    ipc: host')" up -d
refused "a capability" "SYS_ADMIN" as jane docker compose -p ygc-jane -f "$(hostile cap '    cap_add: [SYS_ADMIN]')" up -d
refused "no seccomp" "seccomp=unconfined" as jane docker compose -p ygc-jane -f "$(hostile seccomp '    security_opt: [no-new-privileges:true, seccomp=unconfined]' '' sec)" up -d
refused "kernel parameters" "Sysctls" as jane docker compose -p ygc-jane -f "$(hostile sysctl '    sysctls: [net.ipv4.ip_forward=1]')" up -d
refused "a published port" "published ports" as jane docker compose -p ygc-jane -f "$(hostile port '    ports: ["127.0.0.1:18081:80"]' '' net)" up -d
refused "blog's image" "protected namespace" as jane docker compose -p ygc-jane -f "$(hostile image '' ygc-blog/app:1)" up -d
refused "a volume bound to /" "DriverOpts" as jane docker compose -p ygc-jane -f "$(hostile volopts '    volumes: [root:/host]\nvolumes:\n  root:\n    driver_opts: {type: none, o: bind, device: /}')" up -d
refused "a bridge onto the host's" "Options" as jane docker compose -p ygc-jane -f "$(hostile netopts '    networks: [evil]\nnetworks:\n  evil:\n    driver_opts: {com.docker.network.bridge.name: docker0}' '' net)" up -d

say "== Requests written to slip past (raw HTTP)"
create='{"Image":"alpine:3.22","Labels":{"com.docker.compose.project":"ygc-jane"},"HostConfig":{"NetworkMode":"none","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":67108864,"PidsLimit":64%s}}'
# shellcheck disable=SC2059
status "a lowercase key" 403 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" ',"privileged":true')"
# shellcheck disable=SC2059
status "duplicate keys, the last one on" 403 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" ',"Privileged":false,"Privileged":true')"
# shellcheck disable=SC2059
status "/proc unmasked" 403 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" ',"MaskedPaths":[]')"
# shellcheck disable=SC2059
status "a field Docker doesn't have yet" 400 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" ',"SomeFutureField":true')"
# shellcheck disable=SC2059
status "a name given twice" 400 jane POST "/v1.56/containers/create?name=ygc-jane-evil-1&name=ygc-blog-evil-1" "$(printf "$create" '')"
status "no version in the path" 400 jane GET /containers/json
status "a version YorvoGate doesn't know" 400 jane GET /v1.99/containers/json
status "an encoded slash" 400 jane GET /v1.56/containers%2Fjson
status "a dot segment" 400 jane GET /v1.56/volumes/../containers/json
status "an endpoint YorvoGate doesn't know" 403 jane GET /v1.56/containers/ygc-jane-app-1/some-new-endpoint
status "BuildKit's gRPC" 403 jane POST /v1.56/grpc
status "a build" 403 jane POST /v1.56/build
status "the swarm" 403 jane GET /v1.56/swarm
status "a privileged exec" 403 jane POST /v1.56/containers/ygc-jane-app-1/exec '{"Cmd":["true"],"Privileged":true}'
status "no token" 401 nobody GET /v1.56/version

say "== Nothing was left behind"
if [ "$(direct ps -aq --filter label=com.docker.compose.project=ygc-jane | wc -l)" = 1 ]; then ok "jane has its one container"; else ko "jane's containers" "$(direct ps -a --filter label=com.docker.compose.project=ygc-jane --format '{{.Names}}')"; fi
if direct image inspect alpine:yorvogate-hijack >/dev/null 2>&1; then ko "a shared name was retagged"; else ok "no shared name retagged"; fi
works "jane: compose down -v" as jane docker compose -p ygc-jane -f "$jane" down -v
works "blog: compose down -v" as blog docker compose -p ygc-blog -f "$blog" down -v

say ""
say "$passed passed, $failed failed"
grep "\"refused\"" "$dir/yorvogate.log" | grep -i "status\":5" | tail -3
[ "$failed" = 0 ]
