#!/bin/sh
# YorvoGate's conformance: YorvoGate in front of a real Docker, driven by the real Docker CLI and
# Compose and by raw HTTP. Two scopes, jane and blog: what each does as a tenant must work; what would
# reach the host or the other must be refused, saying why, and leave nothing behind.
#
# It runs twice (run.sh): with each scope's token sent in a header (YGC_LISTENER=tokens), and with
# each scope on a socket of its own (YGC_LISTENER=sockets), where the CLI and Compose send no header.
# Raw requests go to the token listener either way (BusyBox's nc has no unix sockets).
#
# Every attack is a create (or a read): even one that got through would run nothing. Run it through
# run.sh, which gives it a container with Docker's CLI, Compose, Docker's socket and the binary.
set -u

dir=/tmp/conformance
listener=${YGC_LISTENER:-tokens}
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"

# A command as a scope, through YorvoGate: its token in a header, or on its own socket with none
as() {
	scope=$1
	shift
	if [ "$listener" = sockets ]; then
		DOCKER_HOST="unix://$dir/sockets/$scope.sock" DOCKER_CONFIG="$dir/bare" "$@"
	else
		DOCKER_HOST=tcp://127.0.0.1:2376 DOCKER_CONFIG="$dir/$scope" "$@"
	fi
}

# raw SCOPE METHOD PATH [BODY]: the status of a hand-written request, as it's written. Its
# Content-Type is application/json, or $ctype when that's set.
request() {
	token=$(cat "$dir/$1.token" 2>/dev/null || echo not-a-token)
	body=${4:-}
	printf '%s %s HTTP/1.1\r\nHost: docker\r\nX-YorvoGate-Scope: %s\r\nX-YorvoGate-Token: %s\r\nContent-Type: %s\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
		"$2" "$3" "$1" "$token" "${ctype:-application/json}" "$(printf '%s' "$body" | wc -c)" "$body"
	# Kept open until YorvoGate answers: a client that half-closes is one that went away.
	sleep 2
}

# raw SCOPE METHOD PATH [BODY]: the answer's status, then YorvoGate's message if there's one.
raw() {
	answer=$(request "$@" | nc 127.0.0.1 2376)
	printf '%s' "$answer" | head -1 | cut -d' ' -f2
	printf '%s' "$answer" | grep -o '"message":"[^"]*"' | head -1
}

# status NAME WANT SCOPE METHOD PATH [BODY]: a raw request must get that status.
status() {
	name=$1
	want=$2
	shift 2
	answer=$(raw "$@")
	got=$(printf '%s\n' "$answer" | head -1)
	if [ "$got" = "$want" ]; then ok "$name"; else ko "$name (status $got, want $want)" "$(printf '%s\n' "$answer" | tail -n +2)"; fi
}

cleanup() {
	for project in ygc-jane ygc-blog; do
		direct ps -aq --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f >/dev/null 2>&1
		direct network ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
		direct volume ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
	done
	direct rmi ygc-jane/app:1 ygc-blog/app:1 ygc-blog/only:1 ygc-jane/hello:1 hello-world:linux >/dev/null 2>&1
	direct rm -f ygc-builder-privileged ygc-builder-rootless >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== Docker $(direct version --format '{{.Server.Version}} (API {{.Server.APIVersion}})'), Compose $(docker compose version --short)"
say "== Setting up: YorvoGate, scopes jane and blog ($listener)"
mkdir -p "$dir/scopes" "$dir/sockets" "$dir/bare"
for scope in jane blog; do
	token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	printf '%s' "$token" > "$dir/$scope.token"
	mkdir -p "$dir/$scope"
	printf '{"HttpHeaders":{"X-YorvoGate-Scope":"%s","X-YorvoGate-Token":"%s"}}\n' "$scope" "$token" > "$dir/$scope/config.json"
	builders='[]'
	[ "$scope" = jane ] && builders='["ygc-builder-privileged","ygc-builder-rootless"]'
	printf '{"token_sha256":"%s","owner":{"label":"com.docker.compose.project","value":"ygc-%s"},"prefixes":["ygc-%s-","ygc-%s_"],"images":["ygc-%s/"],"builders":%s}\n' \
		"$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)" "$scope" "$scope" "$scope" "$scope" "$builders" > "$dir/scopes/$scope.json"
	chmod 600 "$dir/scopes/$scope.json"
done

# jane-blog, nested in jane's names and image namespace, on a listener of its own: its names and
# images are its own, not jane's, whichever listener each is on.
mkdir -p "$dir/nested"
nested='{"token_sha256":"'"$(head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)"'","owner":{"label":"com.docker.compose.project","value":"ygc-jane-blog"},"prefixes":["ygc-jane-blog-","ygc-jane-blog_"],"images":["ygc-jane/blog/"]}'
printf '%s\n' "$nested" > "$dir/nested/jane-blog.json"
chmod 600 "$dir/nested/jane-blog.json"

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
  - name: nested
    address: tcp://127.0.0.1:2377
    mode: scoped
    scopes: $dir/nested
  - name: orchestrator
    address: tcp://127.0.0.1:2380
    mode: trusted
    allow: {system: read}
EOF
if [ "$listener" = sockets ]; then
	cat >> "$dir/yorvogate.yaml" <<EOF
  - name: tenant-sockets
    scope_sockets: $dir/sockets
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
fi

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
sleep 1

direct image inspect alpine:3.22 >/dev/null 2>&1 || direct pull -q alpine:3.22 >/dev/null

# jane's builders, as an orchestrator would run them: buildx's docker-container driver's (privileged),
# and one configured as a builder must be (rootless, unprivileged; alpine stands in for BuildKit)
direct run -d --name ygc-builder-privileged --privileged alpine:3.22 sleep 600 >/dev/null
direct run -d --name ygc-builder-rootless --user 1000:1000 --security-opt seccomp=unconfined alpine:3.22 sleep 600 >/dev/null

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

say "== Image archives, named as Docker names them"
# docker save's own archive of jane's image, then the same archive renamed: in index.json only by a
# bare ref.name (containerd names the image by it as it is), and in manifest.json as blog's (the
# classic store reads that one).
direct save -o "$dir/own.tar" ygc-jane/app:1
works "jane: load its own archive" as jane docker load -q -i "$dir/own.tar"
rm -rf "$dir/archive" && mkdir -p "$dir/archive" && tar -xf "$dir/own.tar" -C "$dir/archive"
if grep -q '"org.opencontainers.image.ref.name"' "$dir/archive/index.json"; then
	sed -e 's/"io.containerd.image.name":"[^"]*",//' -e 's/"org.opencontainers.image.ref.name":"[^"]*"/"org.opencontainers.image.ref.name":"ygc-bare"/' \
		"$dir/archive/index.json" > "$dir/index.json" && mv "$dir/index.json" "$dir/archive/index.json"
	mv "$dir/archive/manifest.json" "$dir/manifest.json"
	tar -cf "$dir/bare.tar" -C "$dir/archive" .
	refused "jane: an archive named only by a bare ref.name" "ygc-bare isn't in one of scope jane's image namespaces" \
		as jane docker load -q -i "$dir/bare.tar"
	tar -xf "$dir/own.tar" -C "$dir/archive" index.json
	sed 's|"RepoTags":\["[^"]*"\]|"RepoTags":["ygc-blog/app:9"]|' "$dir/manifest.json" > "$dir/archive/manifest.json"
	tar -cf "$dir/foreign.tar" -C "$dir/archive" .
	refused "jane: its own name in index.json, blog's in manifest.json" "ygc-blog/app:9 isn't in one of scope jane's image namespaces" \
		as jane docker load -q -i "$dir/foreign.tar"
else
	ko "docker save writes ref.name annotations in index.json" "$(cat "$dir/archive/index.json")"
fi

say "== Query parameters: only those YorvoGate lists"
status "a parameter YorvoGate doesn't list" 403 jane GET "/v1.56/containers/json?yorvogate-unknown=1"
# Docker refuses it too (403), so it's YorvoGate's message that tells
answer=$(raw jane POST "/v1.56/containers/ygc-jane-app-1/start?checkpoint-dir=/tmp")
if printf '%s' "$answer" | grep -q 'yorvogate: container.start: the parameter'; then ok "a checkpoint restored from a host path"; else ko "a checkpoint restored from a host path (not refused by YorvoGate)" "$answer"; fi
# A shared image tagged into jane's namespace: deleting a platform's content through jane's name
# would delete it from the shared image too, for every scope.
direct pull -q hello-world:linux >/dev/null
works "jane: tag a shared image into its namespace" as jane docker tag hello-world:linux ygc-jane/hello:1
platform=$(printf '%%7B%%22os%%22%%3A%%22linux%%22%%2C%%22architecture%%22%%3A%%22%s%%22%%7D' "$(direct version -f '{{.Server.Arch}}')")
status "jane: delete a platform's content through its own name" 403 jane DELETE "/v1.56/images/ygc-jane/hello:1?force=1&platforms=$platform"
works "the shared image still runs" direct run --rm hello-world:linux
works "jane: delete its own name" as jane docker rmi ygc-jane/hello:1

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
refused "a privileged exec" "a privileged exec isn't allowed" as jane docker exec --privileged ygc-jane-app-1 true

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

say "== A builder is reached only by buildctl dial-stdio"
# The assessment's C-2: an ordinary exec in the privileged builder was root on the host.
refused "an exec in a privileged builder" "it's privileged" as jane docker exec ygc-builder-privileged id
refused "dial-stdio in a privileged builder" "it's privileged" as jane docker exec -i ygc-builder-privileged buildctl dial-stdio
refused "a shell in a rootless builder" "only buildctl dial-stdio" as jane docker exec ygc-builder-rootless id
refused "dial-stdio as root" "User" as jane docker exec -u 0 ygc-builder-rootless buildctl dial-stdio
refused "stopping a builder" "isn't allowed on builder" as jane docker stop ygc-builder-rootless
refused "a builder's files" "isn't allowed on builder" as jane docker cp ygc-builder-rootless:/etc/passwd -
refused "joining a builder's namespaces" "ygc-builder-rootless" as jane docker compose -p ygc-jane -f "$(hostile joinbuilder '    pid: container:ygc-builder-rootless')" up -d
# dial-stdio itself gets past YorvoGate: created and started, Docker runs it (alpine has no buildctl,
# so Docker says so). The CLI then asks for the exec's exit code, which a builder's exec doesn't give.
output=$(as jane docker exec -i ygc-builder-rootless buildctl dial-stdio </dev/null 2>&1)
if printf '%s' "$output" | grep -q '"buildctl": executable file not found'; then ok "dial-stdio in a rootless builder"; else ko "dial-stdio in a rootless builder" "$output"; fi
if [ "$(as jane docker ps -a --format '{{.Names}}' | grep -c ygc-builder)" = 0 ]; then ok "builders aren't listed as its own"; else ko "builders listed as its own"; fi
blog_builder=$(as blog docker container inspect ygc-builder-rootless 2>&1)
if printf '%s' "$blog_builder" | grep -q "No such container"; then ok "another scope's builder doesn't exist for blog"; else ko "blog sees jane's builder" "$blog_builder"; fi

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
# An image all of whose names are blog's, run by its ID: by a few of its digits (Docker takes 4), or whole
printf 'FROM alpine:3.22\nLABEL ygc=blog-only\n' | direct build -q -t ygc-blog/only:1 - >/dev/null
only=$(direct image inspect ygc-blog/only:1 --format '{{.Id}}' | sed 's/^sha256://')
short=$(printf '%.6s' "$only")
# shellcheck disable=SC2059
status "a container of blog's image, by a short ID" 404 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" '' | sed "s|alpine:3.22|$short|")"
# shellcheck disable=SC2059
status "a container of blog's image, by its ID" 404 jane POST /v1.56/containers/create?name=ygc-jane-evil-1 "$(printf "$create" '' | sed "s|alpine:3.22|sha256:$only|")"
shared=$(direct image inspect alpine:3.22 --format '{{.Id}}' | sed 's/^sha256://')
# shellcheck disable=SC2059
status "a container of a shared image, by a short ID" 201 jane POST /v1.56/containers/create?name=ygc-jane-short-1 "$(printf "$create" '' | sed "s|alpine:3.22|$(printf '%.6s' "$shared")|")"
direct rm -f ygc-jane-short-1 >/dev/null 2>&1
status "no version in the path" 400 jane GET /containers/json
status "a version YorvoGate doesn't know" 400 jane GET /v1.99/containers/json
status "an encoded slash" 400 jane GET /v1.56/containers%2Fjson
status "a dot segment" 400 jane GET /v1.56/volumes/../containers/json
status "an endpoint YorvoGate doesn't know" 403 jane GET /v1.56/containers/ygc-jane-app-1/some-new-endpoint
status "BuildKit's gRPC" 403 jane POST /v1.56/grpc
status "a build" 403 jane POST /v1.56/build
status "the swarm" 403 jane GET /v1.56/swarm
# C-1 (the assessment of 0.1.0): Docker reads a form body's parameters over the query YorvoGate checked.
# The query is a pull of jane's own; the body an import named as a shared image, and a pull into blog's.
ctype=application/x-www-form-urlencoded
status "an import smuggled in a form body" 415 jane POST "/v1.56/images/create?fromImage=ygc-jane/app&tag=1" "fromImage=&fromSrc=http://127.0.0.1:9/rootfs.tar&repo=alpine&tag=yorvogate-import"
status "a pull into blog's namespace smuggled in a form body" 415 jane POST "/v1.56/images/create?fromImage=ygc-jane/app&tag=1" "fromImage=ygc-blog/app&tag=1"
ctype=text/plain
status "a pull with a body" 400 jane POST "/v1.56/images/create?fromImage=ygc-jane/app&tag=1" "fromImage=&fromSrc=http://127.0.0.1:9/rootfs.tar&repo=alpine&tag=yorvogate-import"
ctype=
status "no token" 401 nobody GET /v1.56/version

say "== Nested scopes on two listeners"
yorvogate=${YORVOGATE:-/yorvogate/yorvogate}
works "check: jane and jane-blog on two listeners" "$yorvogate" check --config "$dir/yorvogate.yaml"
refused "jane: a container name of jane-blog's (another listener)" "isn't one of scope jane's" \
	as jane docker create --name ygc-jane-blog-php-1 --label com.docker.compose.project=ygc-jane --network none alpine:3.22
refused "jane: a tag in jane-blog's namespace (another listener)" "image namespaces" \
	as jane docker tag alpine:3.22 ygc-jane/blog/php:1
# jane-blog's file caught half-written: its names are still no one else's
printf '%s' "$nested" | head -c 60 > "$dir/nested/jane-blog.json"
kill -HUP "$gate"
sleep 1
refused "jane: jane-blog's name while its file is half-written" "isn't one of scope jane's" \
	as jane docker create --name ygc-jane-blog-php-1 --label com.docker.compose.project=ygc-jane --network none alpine:3.22
refused "jane: jane-blog's namespace while its file is half-written" "image namespaces" \
	as jane docker tag alpine:3.22 ygc-jane/blog/php:1
refused "check: names the half-written file" "jane-blog.json" "$yorvogate" check --config "$dir/yorvogate.yaml"
printf '%s\n' "$nested" > "$dir/nested/jane-blog.json"
kill -HUP "$gate"
sleep 1

say "== Scope status (the orchestrator waits on a fact)"
# scopestatus PORT PATH: YorvoGate's answer, as raw HTTP (kept open while it waits and answers)
scopestatus() {
	{ printf 'GET %s HTTP/1.1\r\nHost: yorvogate\r\nConnection: close\r\n\r\n' "$2"; sleep 3; } | nc 127.0.0.1 "$1"
}
rewritten='{"version":1,'"${nested#\{}"
printf '%s\n' "$rewritten" > "$dir/nested/jane-blog.json.new"
mv "$dir/nested/jane-blog.json.new" "$dir/nested/jane-blog.json"
sum=$(sha256sum "$dir/nested/jane-blog.json" | cut -d' ' -f1)
answer=$(scopestatus 2380 "/_yorvogate/v1/scopes/jane-blog?listener=nested&sha256=$sum")
if printf '%s' "$answer" | grep -q '"state":"loaded"' && printf '%s' "$answer" | grep -q "\"file_sha256\":\"$sum\"" && printf '%s' "$answer" | grep -q '"matched":true'; then
	ok "a file just written: loaded, by its SHA-256"
else
	ko "a file just written: loaded, by its SHA-256" "$answer"
fi
mv "$dir/nested/jane-blog.json" "$dir/jane-blog.json.away"
answer=$(scopestatus 2380 "/_yorvogate/v1/scopes/jane-blog?listener=nested&absent")
if printf '%s' "$answer" | grep -q '"state":"unknown"' && printf '%s' "$answer" | grep -q '"matched":true'; then ok "a file just removed: unknown"; else ko "a file just removed: unknown" "$answer"; fi
mv "$dir/jane-blog.json.away" "$dir/nested/jane-blog.json"
answer=$(scopestatus 2376 "/_yorvogate/v1/scopes/jane-blog?listener=nested")
if printf '%s' "$answer" | grep -q "a trusted listener's only"; then ok "a scoped listener doesn't answer it"; else ko "a scoped listener doesn't answer it" "$answer"; fi
kill -HUP "$gate"
sleep 1

say "== A scope removed ends its streams"
# An exec's stream begun before blog's file goes ends when it goes; jane's goes on. On a token
# listener as on a scope's socket.
# alive PID: running (an exited one not yet reaped is a zombie, and kill -0 still finds it)
alive() {
	[ -r "/proc/$1/stat" ] && ! sed 's/^.*) //' "/proc/$1/stat" | grep -q '^Z'
}
# gone PID: it ends within 10 seconds
gone() {
	i=0
	while alive "$1" && [ $i -lt 10 ]; do
		sleep 1
		i=$((i + 1))
	done
	! alive "$1"
}
blogs=$(direct ps --filter label=com.docker.compose.project=ygc-blog --format '{{.Names}}' | head -1)
janes=$(direct ps --filter label=com.docker.compose.project=ygc-jane --format '{{.Names}}' | head -1)
# Started from this shell, so it reaps them (a pid in a $(…) would be left a zombie)
sleep 60 | as blog docker exec -i "$blogs" cat >/dev/null 2>&1 &
blogstream=$!
sleep 60 | as jane docker exec -i "$janes" cat >/dev/null 2>&1 &
janestream=$!
sleep 2
if alive "$blogstream" && alive "$janestream"; then ok "blog's and jane's execs stream"; else ko "blog's and jane's execs stream"; fi
mv "$dir/scopes/blog.json" "$dir/blog.json.away"
kill -HUP "$gate"
if gone "$blogstream"; then ok "blog's stream ends when its file is removed"; else ko "blog's stream ends when its file is removed"; fi
if alive "$janestream"; then ok "jane's stream goes on"; else ko "jane's stream goes on"; fi
kill "$janestream" "$blogstream" 2>/dev/null
mv "$dir/blog.json.away" "$dir/scopes/blog.json"
kill -HUP "$gate"
sleep 1
works "blog's file back: blog works again" as blog docker ps

say "== Nothing was left behind"
if [ "$(direct ps -aq --filter label=com.docker.compose.project=ygc-jane | wc -l)" = 1 ]; then ok "jane has its one container"; else ko "jane's containers" "$(direct ps -a --filter label=com.docker.compose.project=ygc-jane --format '{{.Names}}')"; fi
if direct image inspect alpine:yorvogate-hijack >/dev/null 2>&1; then ko "a shared name was retagged"; else ok "no shared name retagged"; fi
if direct image inspect alpine:yorvogate-import >/dev/null 2>&1; then ko "an import was named as a shared image"; else ok "no import named as a shared image"; fi
works "jane: compose down -v" as jane docker compose -p ygc-jane -f "$jane" down -v
works "blog: compose down -v" as blog docker compose -p ygc-blog -f "$blog" down -v

if [ "$listener" = sockets ]; then
	say "== A scope's socket is that scope only"
	refused "naming blog on jane's socket" "this socket is scope jane's" \
		env DOCKER_HOST="unix://$dir/sockets/jane.sock" DOCKER_CONFIG="$dir/blog" docker ps
	mv "$dir/scopes/blog.json" "$dir/blog.json.removed"
	kill -HUP "$gate"
	sleep 1
	if [ -e "$dir/sockets/blog.sock" ]; then ko "a removed scope's socket is gone"; else ok "a removed scope's socket is gone"; fi
	if as blog docker version >/dev/null 2>&1; then ko "a removed scope still answers"; else ok "a removed scope no longer answers"; fi
	works "jane's socket is still open" as jane docker version
fi

say "== A Docker newer than the gate"
# A gate that accepts at most API 1.50, in front of a Docker with a newer one: the CLI negotiates the
# version the gate advertises, and works. Without the clamp it would ask for Docker's and be refused.
sed -e 's|^upstream: .*|&\napi: {max: "1.50"}|' -e 's|127.0.0.1:2376|127.0.0.1:2386|' -e 's|127.0.0.1:2377|127.0.0.1:2387|' -e 's|127.0.0.1:2380|127.0.0.1:2390|' \
	-e "s|scope_sockets: $dir/sockets|scope_sockets: $dir/sockets-old|" "$dir/yorvogate.yaml" > "$dir/yorvogate-old.yaml"
mkdir -p "$dir/sockets-old"
"$yorvogate" serve --config "$dir/yorvogate-old.yaml" 2> "$dir/yorvogate-old.log" &
old=$!
sleep 1
negotiated=$(DOCKER_HOST=tcp://127.0.0.1:2386 DOCKER_CONFIG="$dir/jane" docker version --format '{{.Client.APIVersion}}' 2>&1)
if [ "$negotiated" = 1.50 ]; then ok "the CLI negotiates the gate's 1.50"; else ko "the CLI negotiates the gate's 1.50" "$negotiated"; fi
works "jane: docker ps, at the gate's version" env DOCKER_HOST=tcp://127.0.0.1:2386 DOCKER_CONFIG="$dir/jane" docker ps
kill "$old" 2>/dev/null

say ""
say "$passed passed, $failed failed"
grep "\"refused\"" "$dir/yorvogate.log" | grep -i "status\":5" | tail -3
[ "$failed" = 0 ]
