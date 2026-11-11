#!/bin/sh
# YorvoGate's conformance: YorvoGate in front of a real Docker, driven by the real Docker CLI and
# Compose and by raw HTTP. Two scopes, jane and blog: what each does as a tenant must work; what would
# reach the host or the other must be refused, saying why, and leave nothing behind.
#
# It runs three times (run.sh): with each scope's token sent in a header (YGC_LISTENER=tokens), with
# each scope on a socket of its own (YGC_LISTENER=sockets), where the CLI and Compose send no header,
# and with each scope's client certificate its scope (YGC_LISTENER=mtls), over TLS with --tlsverify.
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
	elif [ "$listener" = mtls ]; then
		DOCKER_HOST=tcp://127.0.0.1:2378 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH="$dir/certs/$scope" DOCKER_CONFIG="$dir/bare" "$@"
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
	direct rmi ygc-jane/app:1 ygc-blog/app:1 ygc-blog/only:1 ygc-jane/hello:1 ygc-jane/built:1 ygc-jane/attested:1 hello-world:linux >/dev/null 2>&1
	direct rm -f ygc-builder-privileged ygc-builder-rootless ygc-builder-nnp >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== Docker $(direct version --format '{{.Server.Version}} (API {{.Server.APIVersion}})'), Compose $(docker compose version --short)"
say "== Setting up: YorvoGate, scopes jane and blog ($listener)"
mkdir -p "$dir/scopes" "$dir/sockets" "$dir/bare"

# mtls: the gate's CA and certificate, the scopes' CA, a certificate for each scope (and one for a
# scope that isn't there), each client's folder as DOCKER_CERT_PATH has it (ca.pem is the gate's CA).
# jane pins its certificate's key; blog pins none.
pin() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1; }
issue() { # issue CA NAME FOLDER [EXTENSIONS]
	mkdir -p "$3"
	printf '%s\n' "${4:-extendedKeyUsage=clientAuth}" > "$3/ext"
	openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj "/CN=$2" -keyout "$3/key.pem" -out "$3/csr" 2>/dev/null
	openssl x509 -req -in "$3/csr" -CA "$dir/certs/$1.pem" -CAkey "$dir/certs/$1.key" -days 1 -extfile "$3/ext" -out "$3/cert.pem" 2>/dev/null
	cp "$dir/certs/gate-ca.pem" "$3/ca.pem"
}
if [ "$listener" = mtls ]; then
	apk add -q --no-cache openssl >/dev/null
	mkdir -p "$dir/certs"
	for ca in gate-ca scopes-ca other-ca; do
		openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 1 -subj "/CN=ygc $ca" -keyout "$dir/certs/$ca.key" -out "$dir/certs/$ca.pem" 2>/dev/null
	done
	issue gate-ca 127.0.0.1 "$dir/certs/gate" 'subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth'
	for scope in jane blog nobody; do issue scopes-ca "$scope" "$dir/certs/$scope"; done
	issue scopes-ca jane "$dir/certs/jane-unpinned"
	issue other-ca jane "$dir/certs/jane-other-ca"
	issue scopes-ca jane "$dir/certs/jane-server" 'extendedKeyUsage=serverAuth'
fi

for scope in jane blog; do
	token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	printf '%s' "$token" > "$dir/$scope.token"
	mkdir -p "$dir/$scope"
	printf '{"HttpHeaders":{"X-YorvoGate-Scope":"%s","X-YorvoGate-Token":"%s"}}\n' "$scope" "$token" > "$dir/$scope/config.json"
	builders='[]'
	[ "$scope" = jane ] && builders='["ygc-builder-privileged","ygc-builder-rootless","ygc-builder-nnp"]'
	[ "$listener" = mtls ] && [ "$scope" = jane ] && builders="$builders,\"certificates\":[{\"sha256\":\"$(pin "$dir/certs/jane/cert.pem")\"}]"
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
if [ "$listener" = mtls ]; then
	cat >> "$dir/yorvogate.yaml" <<EOF
  - name: tenant-mtls
    address: tcp://127.0.0.1:2378
    mode: scoped
    scopes: $dir/scopes
    tls: {certificate: $dir/certs/gate/cert.pem, key: $dir/certs/gate/key.pem, client_ca: $dir/certs/scopes-ca.pem}
    containers:
      capabilities: [NET_BIND_SERVICE]
      drop_all_capabilities: true
      no_new_privileges: true
      max_memory: 268435456
      max_pids: 128
      protected_images: [ygc-jane/, ygc-blog/]
EOF
fi
without_lsm "$dir/yorvogate.yaml"

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
sleep 1

direct image inspect alpine:3.22 >/dev/null 2>&1 || direct pull -q alpine:3.22 >/dev/null

# jane's builders, as an orchestrator would run them: buildx's docker-container driver's (privileged),
# one configured as a builder must be (rootless, unprivileged, out of a hardened daemon's
# no-new-privileges; alpine stands in for BuildKit), and one under no-new-privileges, which rootless
# BuildKit can't run under
direct run -d --name ygc-builder-privileged --privileged alpine:3.22 sleep 600 >/dev/null
direct run -d --name ygc-builder-rootless --user 1000:1000 --security-opt seccomp=unconfined --security-opt no-new-privileges=false alpine:3.22 sleep 600 >/dev/null
direct run -d --name ygc-builder-nnp --user 1000:1000 --security-opt seccomp=unconfined --security-opt no-new-privileges alpine:3.22 sleep 600 >/dev/null

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
# What Compose left unset, YorvoGate stated: a private cgroup namespace, Docker's built-in seccomp
# profile, the default runtime
stated=$(direct inspect ygc-jane-app-1 --format '{{.HostConfig.CgroupnsMode}} {{.HostConfig.Runtime}} {{json .HostConfig.SecurityOpt}}')
case "$stated" in "private runc "*'"seccomp=builtin"'*) ok "jane: its container's cgroup namespace, runtime and seccomp profile, as YorvoGate stated them" ;; *) ko "jane: its container's stated defaults" "$stated" ;; esac
# Its docker info: its own containers, not the host's name, and no swarm (Compose reads it)
info=$(as jane docker info --format '{{.Name}}|{{.Containers}}|{{.Swarm.LocalNodeState}}|{{.DockerRootDir}}' 2>&1)
own=$(as jane docker ps -aq | wc -l | tr -d ' ')
if [ "$info" = "|$own|inactive|" ]; then ok "jane: docker info, its own"; else ko "jane: docker info, its own" "$info (its containers: $own)"; fi
if as jane docker version --format '{{.Server.KernelVersion}}' 2>&1 | grep -q .; then ko "jane: docker version, without the kernel's" "$(as jane docker version 2>&1)"; else ok "jane: docker version, without the kernel's"; fi
refused "jane: a log option of another driver" "isn't one of the json-file driver's" as jane docker run --rm --name ygc-jane-log --label com.docker.compose.project=ygc-jane --network ygc-jane_default --cap-drop ALL --security-opt no-new-privileges --memory 64m --pids-limit 64 --log-driver json-file --log-opt syslog-address=udp://169.254.169.254:514 alpine:3.22 true
works "jane: exec, writing to its volume" as jane docker compose -p ygc-jane -f "$jane" exec -T app sh -c 'echo kept > /data/x && cat /data/x'
works "jane: exec -d" as jane docker compose -p ygc-jane -f "$jane" exec -d app true
works "jane: logs" as jane docker compose -p ygc-jane -f "$jane" logs
works "jane: restart" as jane docker compose -p ygc-jane -f "$jane" restart
works "jane: pull" as jane docker pull -q alpine:3.22
# A pull's platform is the host's (as containerd writes it), and its registry one the listener lists
host=$(direct version -f '{{.Server.Arch}}')
if [ "$host" = arm64 ]; then other=linux/amd64; else other=linux/arm64; fi
works "jane: pull, naming the host's platform" as jane docker pull -q --platform "linux/$host" alpine:3.22
refused "jane: pull of another platform" "isn't the host's" as jane docker pull -q --platform "$other" alpine:3.22
refused "jane: pull from a registry on loopback" "isn't one this listener's scopes may pull from" as jane docker pull -q localhost:5000/ygc/x
refused "jane: pull from a private address" "isn't one this listener's scopes may pull from" as jane docker pull -q 127.0.0.1:5000/ygc/x
refused "jane: pull from the metadata address" "isn't one this listener's scopes may pull from" as jane docker pull -q 169.254.169.254/ygc/x
refused "jane: pull from another registry" "isn't one this listener's scopes may pull from" as jane docker pull -q ghcr.io/yorvolabs/yorvogate:0.2.2
refused "jane: search on another registry" "isn't one this listener's scopes may pull from" as jane docker search localhost:5000/ygc
works "jane: tag into its namespace" as jane docker tag alpine:3.22 ygc-jane/app:1
works "blog: tag into its namespace" as blog docker tag alpine:3.22 ygc-blog/app:1
works "jane: inspect its image" as jane docker image inspect ygc-jane/app:1

say "== Image archives, named as Docker names them, holding what they refer to"
if direct info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter; then containerd=1; else containerd=; fi
arch=$(direct version -f '{{.Server.Arch}}')
# docker save's archive of an image jane built: it holds every blob it refers to
printf 'FROM alpine:3.22\nLABEL ygc=jane-built\n' | direct build -q -t ygc-jane/built:1 - >/dev/null
direct save -o "$dir/own.tar" ygc-jane/built:1
works "jane: load its own archive" as jane docker load -q -i "$dir/own.tar"
# A pulled multi-platform image's archive: on the containerd store its index names platforms it
# doesn't hold (refused: a manifest it lacks); on the classic store it holds the one it has
direct save -o "$dir/pulled.tar" ygc-jane/app:1
if [ -n "$containerd" ]; then
	refused "jane: a pulled image's archive naming platforms it lacks" "the archive lacks sha256:" as jane docker load -q -i "$dir/pulled.tar"
else
	works "jane: a pulled image's archive" as jane docker load -q -i "$dir/pulled.tar"
fi
# With --platform: recorded, either way (which one loads is what the docs say)
if direct save --platform "linux/$arch" -o "$dir/platform.tar" ygc-jane/app:1 2>/dev/null; then
	if output=$(as jane docker load -q -i "$dir/platform.tar" 2>&1); then say "  note a pulled image saved with --platform loads"; else say "  note a pulled image saved with --platform is refused: $output"; fi
fi
# buildx --load with an attestation (the containerd store keeps attestations; the classic one doesn't)
if [ -n "$containerd" ]; then
	printf 'FROM alpine:3.22\nLABEL ygc=jane-attested\n' | direct buildx build -q --provenance=mode=min --load -t ygc-jane/attested:1 - >/dev/null
	direct save -o "$dir/attested.tar" ygc-jane/attested:1
	rm -rf "$dir/attested" && mkdir -p "$dir/attested" && tar -xf "$dir/attested.tar" -C "$dir/attested"
	if grep -rqsE 'attestation-manifest|vnd\.docker\.attestation\.manifest' "$dir/attested/index.json" "$dir/attested/blobs"; then ok "buildx's archive holds an attestation"; else ko "buildx's archive holds an attestation" "$(cat "$dir/attested/index.json")"; fi
	works "jane: load a buildx archive with its attestation" as jane docker load -q -i "$dir/attested.tar"
fi
# The archive with one layer's bytes replaced, its name kept; then with that layer gone
rm -rf "$dir/archive" && mkdir -p "$dir/archive" && tar -xf "$dir/own.tar" -C "$dir/archive"
# The largest blob is a layer (blob names are hex digests)
layer=$(find "$dir/archive/blobs/sha256" -type f -exec wc -c {} + | grep -v ' total$' | sort -rn | head -1 | sed 's|.*/||')
cp "$dir/archive/index.json" "$dir/archive/blobs/sha256/$layer"
tar -cf "$dir/junk.tar" -C "$dir/archive" .
refused "jane: an archive whose blob isn't what its digest says" "isn't what its digest says" as jane docker load -q -i "$dir/junk.tar"
rm "$dir/archive/blobs/sha256/$layer"
tar -cf "$dir/missing.tar" -C "$dir/archive" .
refused "jane: an archive that lacks a blob it refers to" "the archive lacks" as jane docker load -q -i "$dir/missing.tar"
# The same archive renamed: in index.json only by a bare ref.name (containerd names the image by it as
# it is), and in manifest.json as blog's (the classic store reads that one).
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
refused "taking back a hardened daemon's no-new-privileges" "no-new-privileges:false" as jane docker compose -p ygc-jane -f "$(hostile nnp '    security_opt: [no-new-privileges:false]' '' sec)" up -d
refused "kernel parameters" "Sysctls" as jane docker compose -p ygc-jane -f "$(hostile sysctl '    sysctls: [net.ipv4.ip_forward=1]')" up -d
refused "a published port" "published ports" as jane docker compose -p ygc-jane -f "$(hostile port '    ports: ["127.0.0.1:18081:80"]' '' net)" up -d
refused "blog's image" "protected namespace" as jane docker compose -p ygc-jane -f "$(hostile image '' ygc-blog/app:1)" up -d
refused "a volume bound to /" "DriverOpts" as jane docker compose -p ygc-jane -f "$(hostile volopts '    volumes: [root:/host]\nvolumes:\n  root:\n    driver_opts: {type: none, o: bind, device: /}')" up -d
refused "a bridge onto the host's" "Options" as jane docker compose -p ygc-jane -f "$(hostile netopts '    networks: [evil]\nnetworks:\n  evil:\n    driver_opts: {com.docker.network.bridge.name: docker0}' '' net)" up -d

say "== A builder is reached only by buildctl dial-stdio"
# The assessment's C-2: an ordinary exec in the privileged builder was root on the host.
refused "an exec in a privileged builder" "it's privileged" as jane docker exec ygc-builder-privileged id
refused "dial-stdio in a privileged builder" "it's privileged" as jane docker exec -i ygc-builder-privileged buildctl dial-stdio
refused "dial-stdio in a builder under no-new-privileges" 'option "no-new-privileges" isn' as jane docker exec -i ygc-builder-nnp buildctl dial-stdio
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
# What a container runs is the image checked, named by what Docker answered: "name@ID" on the
# containerd store, the ID on the classic one (the store as Docker's /info says it, not as YorvoGate
# guesses it)
if direct info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter; then pin="alpine@sha256:$shared"; else pin="sha256:$shared"; fi
# shellcheck disable=SC2059
status "a container of a shared image, by name" 201 jane POST /v1.56/containers/create?name=ygc-jane-pin-1 "$(printf "$create" '')"
if [ "$(direct inspect --format '{{.Config.Image}}' ygc-jane-pin-1 2>&1)" = "$pin" ]; then ok "it runs the image checked ($pin)"; else ko "it runs the image checked" "$(direct inspect --format '{{.Config.Image}}' ygc-jane-pin-1 2>&1), not $pin"; fi
direct rm -f ygc-jane-pin-1 >/dev/null 2>&1
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

if [ "$listener" = mtls ]; then
	say "== A client certificate is that scope only"
	# tlsas CERTS COMMAND…: a command with a client's certificate folder, and no header
	tlsas() {
		certs=$1
		shift
		DOCKER_HOST=tcp://127.0.0.1:2378 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH="$dir/certs/$certs" DOCKER_CONFIG="$dir/bare" "$@"
	}
	mkdir -p "$dir/naming-jane"
	printf '{"HttpHeaders":{"X-YorvoGate-Scope":"jane"}}\n' > "$dir/naming-jane/config.json"
	refused "naming jane with blog's certificate" "this client certificate is scope blog's" \
		env DOCKER_HOST=tcp://127.0.0.1:2378 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH="$dir/certs/blog" DOCKER_CONFIG="$dir/naming-jane" docker ps
	refused "a token on the mTLS listener" "takes a client certificate, not a token" \
		env DOCKER_HOST=tcp://127.0.0.1:2378 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH="$dir/certs/jane" DOCKER_CONFIG="$dir/jane" docker ps
	refused "a certificate of a scope that isn't there" "no such scope, or not its certificate" tlsas nobody docker ps
	refused "jane's name, a key jane doesn't pin" "no such scope, or not its certificate" tlsas jane-unpinned docker ps
	for certs in jane-other-ca jane-server; do
		if output=$(tlsas "$certs" docker ps 2>&1); then ko "a certificate the handshake refuses ($certs) was allowed" "$output"; else ok "a certificate the handshake refuses ($certs)"; fi
	done
	if output=$(DOCKER_HOST=tcp://127.0.0.1:2378 DOCKER_CONFIG="$dir/bare" docker ps 2>&1); then ko "no TLS at all was allowed" "$output"; else ok "no TLS at all"; fi
	works "blog: its own containers, with its certificate" as blog docker ps

	# buildx's own connections, through a Docker context with jane's certificate: its dial-stdio gets
	# past YorvoGate to the builder, as jane (alpine has no buildctl, so buildx then waits in vain)
	DOCKER_CONFIG="$dir/bare" docker context create ygc-mtls-jane --docker "host=tcp://127.0.0.1:2378,ca=$dir/certs/jane/ca.pem,cert=$dir/certs/jane/cert.pem,key=$dir/certs/jane/key.pem" >/dev/null
	# (a builder can't take a context's name: buildx counts contexts as builders)
	works "buildx create --driver remote, over the mTLS context" env DOCKER_CONFIG="$dir/bare" docker buildx create --name ygc-mtls-builder --driver remote 'docker-container://ygc-builder-rootless?context=ygc-mtls-jane'
	DOCKER_CONFIG="$dir/bare" timeout 20 docker buildx inspect --bootstrap ygc-mtls-builder >/dev/null 2>&1
	if grep '"listener":"tenant-mtls"' "$dir/yorvogate.log" | grep '"msg":"allowed"' | grep '"scope":"ygc-jane"\|"scope":"jane"' | grep -q '"endpoint":"exec.start"'; then
		ok "buildx over the mTLS context dials the builder, as jane"
	else
		ko "buildx over the mTLS context dials the builder, as jane" "$(grep '"listener":"tenant-mtls"' "$dir/yorvogate.log" | grep exec | tail -3)"
	fi
	DOCKER_CONFIG="$dir/bare" docker buildx rm ygc-mtls-builder >/dev/null 2>&1

	# A scope no longer pinning a certificate: it's refused at once, and its stream ends
	tlsas jane docker run -d --name ygc-jane-mtls --label com.docker.compose.project=ygc-jane --network none --cap-drop ALL --security-opt no-new-privileges --memory 64m --pids-limit 64 alpine:3.22 sleep 600 >/dev/null
	tlsas jane docker logs -f ygc-jane-mtls > "$dir/mtls-logs.out" 2>&1 &
	follower=$!
	sleep 1
	sed "s|\"certificates\":\[{\"sha256\":\"[0-9a-f]*\"}\]|\"certificates\":[{\"sha256\":\"$(pin "$dir/certs/jane-unpinned/cert.pem")\"}]|" "$dir/scopes/jane.json" > "$dir/jane.json.new"
	chmod 600 "$dir/jane.json.new"
	mv "$dir/jane.json.new" "$dir/scopes/jane.json"
	kill -HUP "$gate"
	sleep 2
	if kill -0 "$follower" 2>/dev/null; then
		ko "a certificate no longer pinned keeps its stream"
		kill "$follower"
	else
		ok "a certificate no longer pinned ends its stream"
	fi
	refused "a certificate no longer pinned" "no such scope, or not its certificate" tlsas jane docker ps
	works "the newly pinned one" tlsas jane-unpinned docker rm -f ygc-jane-mtls
fi

say "== A Docker newer than the gate"
# A gate that accepts at most API 1.50, in front of a Docker with a newer one: the CLI negotiates the
# version the gate advertises, and works. Without the clamp it would ask for Docker's and be refused.
sed -e 's|^upstream: .*|&\napi: {max: "1.50"}|' -e 's|127.0.0.1:2376|127.0.0.1:2386|' -e 's|127.0.0.1:2377|127.0.0.1:2387|' -e 's|127.0.0.1:2380|127.0.0.1:2390|' -e 's|127.0.0.1:2378|127.0.0.1:2388|' \
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
