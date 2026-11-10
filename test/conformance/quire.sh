#!/bin/sh
# Quire Server's real use of YorvoGate (a site host's orchestrator and its tenants), end to end on a
# real Docker:
#   - the orchestrator on a trusted listener on a unix socket: networks, a database container, a
#     tenant's rootless BuildKit builder (docker run, buildx's remote driver);
#   - each site a scope on a socket of its own, with Quire's settings: a Compose project with build:
#     built on its builder, on two shared networks with Compose's aliases, up --wait, exec, cp,
#     logs, down; image tag and rm in its namespace; sites nested in each other's names.
# Names start with ygq- so nothing of a real Quire on the machine is touched. Run it through run.sh.
# YGC_APPARMOR names the host's AppArmor profile for rootless BuildKit, where the host has AppArmor
# (the CI workflow loads examples/apparmor/yorvogate-buildkit-rootless).
set -u

dir=/tmp/quire
apparmor=${YGC_APPARMOR:-}
buildkit=moby/buildkit:v0.34.0-rootless@sha256:65eca3c01cd1180c8f64565c4e3c5983af5145818b0e6fa863385d099eb73855
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"

# The orchestrator, on its trusted listener, through its "quire" context
orchestrator() { env -u DOCKER_HOST DOCKER_CONFIG="$dir/orchestrator" docker --context quire "$@"; }

# A site, on its own socket: its DOCKER_CONFIG's current context ("quire") is that socket. (The CLI
# image sets DOCKER_HOST, which would win over the context.)
as() {
	site=$1
	shift
	env -u DOCKER_HOST DOCKER_CONFIG="$dir/$site/docker" "$@"
}

cleanup() {
	for project in ygq-jane ygq-jane-blog ygq-jane_shop; do
		direct ps -aq --filter "label=com.docker.compose.project=$project" | xargs -r docker rm -f >/dev/null 2>&1
		direct network ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker network rm >/dev/null 2>&1
		direct volume ls -q --filter "label=com.docker.compose.project=$project" | xargs -r docker volume rm >/dev/null 2>&1
	done
	direct rm -f ygq-buildkit-jane ygq-db-jane >/dev/null 2>&1
	direct volume rm ygq-buildkit-jane-state >/dev/null 2>&1
	direct network rm ygq-edge ygq-link-jane ygq-db >/dev/null 2>&1
	direct rmi quire-sites/ygq-jane/web:1 quire-sites/ygq-jane/web:2 quire-sites/ygq-jane/web:before-update quire-sites/ygq-jane/web:late ygq-base:1 >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== Docker $(direct version --format '{{.Server.Version}}'), Compose $(docker compose version --short), buildx $(docker buildx version | cut -d' ' -f2), AppArmor profile: ${apparmor:-none}"
say "== Setting up: YorvoGate with an orchestrator's listener and sites' sockets"
mkdir -p "$dir/scopes" "$dir/sockets" "$dir/orchestrator"

# Sites jane and jane-blog, as Quire writes their scope files: each its Compose project, its images in
# quire-sites/<project>/; jane with its builder and the shared networks, with Compose's aliases
cat > "$dir/scopes/jane.json" <<EOF
{"owner": {"label": "com.docker.compose.project", "value": "ygq-jane"}, "prefixes": ["ygq-jane-", "ygq-jane_"],
 "images": ["quire-sites/ygq-jane/"], "builders": ["ygq-buildkit-jane"],
 "networks": {"ygq-edge": {"aliases": ["web", "ygq-jane-web-1", "jane.quire.internal"]}, "ygq-link-jane": {"aliases": ["web", "ygq-jane-web-1"]}}}
EOF
cat > "$dir/scopes/jane-blog.json" <<EOF
{"owner": {"label": "com.docker.compose.project", "value": "ygq-jane-blog"}, "prefixes": ["ygq-jane-blog-", "ygq-jane-blog_"],
 "images": ["quire-sites/ygq-jane-blog/"]}
EOF
# jane_shop, a project with "_" (nested in jane's ygq-jane_), on the shared network with the aliases
# Compose gives it: its service's name, its container's, and its site's
cat > "$dir/scopes/jane_shop.json" <<EOF
{"owner": {"label": "com.docker.compose.project", "value": "ygq-jane_shop"}, "prefixes": ["ygq-jane_shop-", "ygq-jane_shop_"],
 "networks": {"ygq-edge": {"aliases": ["web", "ygq-jane_shop-web-1", "shop.quire.internal"]}}}
EOF
chmod 600 "$dir/scopes/"*.json

# Quire Server's own configuration (test/conformance/quire, pinned to the commit it's from), with
# only its paths moved to this test's: the policy under test is the one Quire runs.
sed -e "s|unix:///run/yorvogate/trusted/trusted.sock|unix://$dir/orchestrator.sock|" \
	-e "s|scope_sockets: /run/yorvogate/sites|scope_sockets: $dir/sockets|" \
	-e "s|scopes: /etc/yorvogate/sites|scopes: $dir/scopes|" \
	"$(dirname "$0")/quire/yorvogate.yaml" > "$dir/yorvogate.yaml"
if grep -v '^[[:space:]]*#' "$dir/yorvogate.yaml" | grep -q '/run/yorvogate\|/etc/yorvogate'; then
	ko "Quire Server's configuration has a path this test doesn't move" "$(grep -v '^[[:space:]]*#' "$dir/yorvogate.yaml" | grep '/run/yorvogate\|/etc/yorvogate')"
fi

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
sleep 1

direct image inspect alpine:3.22 >/dev/null 2>&1 || direct pull -q alpine:3.22 >/dev/null
direct image inspect "$buildkit" >/dev/null 2>&1 || direct pull -q "$buildkit" >/dev/null

DOCKER_CONFIG="$dir/orchestrator" docker context create quire --docker "host=unix://$dir/orchestrator.sock" >/dev/null

say "== The orchestrator (trusted, on a unix socket)"
works "network create (shared)" orchestrator network create ygq-edge
works "network create (jane's link)" orchestrator network create ygq-link-jane
works "network inspect" orchestrator network inspect ygq-edge
works "network create (the database's own)" orchestrator network create ygq-db
works "docker run (a database, on its own network)" orchestrator run -d --name ygq-db-jane --network ygq-db alpine:3.22 sleep 600
works "exec into the database" orchestrator exec ygq-db-jane sh -c 'echo dump > /tmp/dump.sql'
works "docker cp out of the database" orchestrator cp ygq-db-jane:/tmp/dump.sql "$dir/dump.sql"
works "image tag" orchestrator image tag alpine:3.22 ygq-base:1
works "image inspect" orchestrator image inspect ygq-base:1

# jane's builder, as Quire's agent creates it: rootless BuildKit, not privileged, no capabilities
set -- --security-opt seccomp=unconfined --security-opt systempaths=unconfined
[ -n "$apparmor" ] && set -- "$@" --security-opt "apparmor=$apparmor"
works "docker run (jane's rootless builder)" orchestrator run -d --name ygq-buildkit-jane "$@" \
	-v ygq-buildkit-jane-state:/home/user/.local/share/buildkit "$buildkit"

# jane's DOCKER_CONFIG: its "quire" context is its socket, current, and the builder's context
mkdir -p "$dir/jane/docker" "$dir/jane-blog/docker" "$dir/jane_shop/docker"
for site in jane jane-blog jane_shop; do
	as "$site" docker context create quire --docker "host=unix://$dir/sockets/$site.sock" >/dev/null
	as "$site" docker context use quire >/dev/null
done
works "buildx create --driver remote (jane's builder)" as jane docker buildx create --name ygq-jane --driver remote 'docker-container://ygq-buildkit-jane?context=quire'

# The builder takes a moment to start: BuildKit answers once it's up.
for _ in $(seq 30); do
	as jane timeout 10 docker buildx inspect --bootstrap ygq-jane >/dev/null 2>&1 && break
	sleep 1
done
works "the builder answers (through jane's socket)" as jane timeout 30 docker buildx inspect --bootstrap ygq-jane

say "== A site (a scope on its own socket, Quire's settings)"
mkdir -p "$dir/jane/site"
cat > "$dir/jane/site/Dockerfile" <<'EOF'
FROM alpine:3.22
RUN echo built > /built && ln -s /built /link
EOF
cat > "$dir/jane/site/compose.yaml" <<'EOF'
services:
  web:
    build: .
    image: quire-sites/ygq-jane/web:1
    command: [sleep, "600"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 64
    healthcheck: {test: [CMD, test, -f, /built], interval: 1s, retries: 30}
    networks:
      default: {}
      ygq-edge: {aliases: [jane.quire.internal]}
      ygq-link-jane: {}
    volumes: [data:/data]
networks:
  ygq-edge: {external: true}
  ygq-link-jane: {external: true}
volumes:
  data:
EOF
jane="$dir/jane/site/compose.yaml"

works "compose build --builder (rootless BuildKit)" as jane timeout 300 docker compose -p ygq-jane -f "$jane" build --builder ygq-jane
works "the image is jane's (inspect through its socket)" as jane docker image inspect quire-sites/ygq-jane/web:1
works "compose up --wait (two shared networks, Compose's aliases)" as jane docker compose -p ygq-jane -f "$jane" up -d --wait
works "exec -T" as jane docker compose -p ygq-jane -f "$jane" exec -T web sh -c 'echo kept > /data/x && cat /data/x'
rm -f "$dir/out"
works "cp --follow-link out of its container" as jane docker compose -p ygq-jane -f "$jane" cp -L web:/link "$dir/out"
if [ "$(cat "$dir/out" 2>/dev/null)" = built ]; then ok "the copied file is the link's target"; else ko "the copied file" "$(cat "$dir/out" 2>&1)"; fi
if [ "$(as jane docker compose -p ygq-jane -f "$jane" ps --format '{{.Name}}')" = ygq-jane-web-1 ]; then ok "ps"; else ko "ps" "$(as jane docker compose -p ygq-jane -f "$jane" ps 2>&1)"; fi
works "logs" as jane docker compose -p ygq-jane -f "$jane" logs
# shellcheck disable=SC2016 # a Go template, not the shell's
aliases=$(direct inspect ygq-jane-web-1 --format '{{range $n, $e := .NetworkSettings.Networks}}{{$n}}={{join $e.Aliases ","}} {{end}}')
case "$aliases" in *ygq-edge=*jane.quire.internal*) ok "its alias on the shared network" ;; *) ko "its aliases" "$aliases" ;; esac
works "image tag (in its namespace)" as jane docker image tag quire-sites/ygq-jane/web:1 quire-sites/ygq-jane/web:2
works "image rm (in its namespace)" as jane docker image rm quire-sites/ygq-jane/web:2
refused "image tag (in another site's namespace)" "namespace" as jane docker image tag quire-sites/ygq-jane/web:1 quire-sites/ygq-jane-blog/web:1

# Quire Server's rollback: the image a rebuild replaces is tagged while it still has its name. An
# image with no name left is no one's: by its ID, the scope doesn't see it.
old=$(as jane docker image inspect --format '{{.Id}}' quire-sites/ygq-jane/web:1)
works "image tag before a rebuild (the rollback's tag)" as jane docker image tag quire-sites/ygq-jane/web:1 quire-sites/ygq-jane/web:before-update
echo 'RUN echo 2 > /version' >> "$dir/jane/site/Dockerfile"
works "compose build (a rebuild)" as jane timeout 300 docker compose -p ygq-jane -f "$jane" build --builder ygq-jane
new=$(as jane docker image inspect --format '{{.Id}}' quire-sites/ygq-jane/web:1)
kept=$(as jane docker image inspect --format '{{.Id}}' quire-sites/ygq-jane/web:before-update)
if [ -n "$old" ] && [ "$new" != "$old" ] && [ "$kept" = "$old" ]; then ok "the rollback's tag keeps the replaced image"; else ko "the rollback's tag" "old=$old new=$new kept=$kept"; fi
works "image rm of the rollback's tag (the image is in use: -f, which removes the name only)" as jane docker image rm -f quire-sites/ygq-jane/web:before-update
works "the replaced image still exists, nameless" direct image inspect "$old"
refused "image tag by ID of an image with no name" "No such image" as jane docker image tag "$old" quire-sites/ygq-jane/web:late

# The build's traffic: the dial on jane's socket (only dial-stdio), the result loaded through it
if grep '"listener":"sites"' "$dir/yorvogate.log" | grep '"scope":"jane"' | grep -q '"endpoint":"image.load"'; then ok "the build's image was loaded through jane's socket"; else ko "no image.load through jane's socket" "$(grep image.load "$dir/yorvogate.log" | tail -2)"; fi
if grep '"listener":"sites"' "$dir/yorvogate.log" | grep '"scope":"jane"' | grep -q '"endpoint":"exec.create"'; then ok "the builder was dialled through jane's socket"; else ko "no dial through jane's socket"; fi
refused "a shell in the builder" "only buildctl dial-stdio" as jane docker exec ygq-buildkit-jane id

say "== Sites nested in each other's names (jane, jane-blog)"
mkdir -p "$dir/jane-blog/site"
cat > "$dir/jane-blog/site/compose.yaml" <<'EOF'
services:
  app:
    image: alpine:3.22
    command: [sleep, "600"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 64
EOF
blog="$dir/jane-blog/site/compose.yaml"
works "jane-blog: compose up" as jane-blog docker compose -p ygq-jane-blog -f "$blog" up -d
if [ "$(as jane docker ps --format '{{.Names}}')" = ygq-jane-web-1 ]; then ok "jane sees only its own"; else ko "jane's ps" "$(as jane docker ps --format '{{.Names}}')"; fi
if [ "$(as jane-blog docker ps --format '{{.Names}}')" = ygq-jane-blog-app-1 ]; then ok "jane-blog sees only its own"; else ko "jane-blog's ps" "$(as jane-blog docker ps --format '{{.Names}}')"; fi
refused "jane: jane-blog's container" "No such container" as jane docker container inspect ygq-jane-blog-app-1
# A changed service is recreated: Compose creates <12 hex of the old ID>_<name>, removes the old one,
# and renames the new one to the old name.
before="$(as jane-blog docker container inspect -f '{{.Id}}' ygq-jane-blog-app-1)"
printf '    environment: [RELEASE=2]\n' >> "$blog"
works "jane-blog: compose up (recreate)" as jane-blog docker compose -p ygq-jane-blog -f "$blog" up -d
after="$(as jane-blog docker container inspect -f '{{.Id}} {{.Name}} {{range .Config.Env}}{{.}} {{end}}' ygq-jane-blog-app-1)"
case "$after" in
"$before "*) ko "jane-blog: recreated" "still the old container" ;;
*" /ygq-jane-blog-app-1 "*"RELEASE=2 "*) ok "jane-blog: recreated under its name" ;;
*) ko "jane-blog: recreated" "$after" ;;
esac
if [ "$(as jane-blog docker ps -a --format '{{.Names}}')" = ygq-jane-blog-app-1 ]; then ok "jane-blog: one container after the recreate"; else ko "jane-blog's ps -a" "$(as jane-blog docker ps -a --format '{{.Names}}')"; fi
refused "jane: a name of jane-blog's" "isn't one of scope jane's" as jane docker compose -p ygq-jane-blog -f "$blog" up -d
works "jane-blog: compose down" as jane-blog docker compose -p ygq-jane-blog -f "$blog" down --remove-orphans --volumes

say "== A project with _ in its name, on a shared network"
mkdir -p "$dir/jane_shop/site"
cat > "$dir/jane_shop/site/compose.yaml" <<'EOF'
services:
  web:
    image: alpine:3.22
    command: [sleep, "600"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 64
    networks:
      ygq-edge: {aliases: [shop.quire.internal]}
networks:
  ygq-edge: {external: true}
EOF
shop="$dir/jane_shop/site/compose.yaml"
works "jane_shop: compose up --wait (Compose's aliases for a project with _)" as jane_shop docker compose -p ygq-jane_shop -f "$shop" up -d --wait
# shellcheck disable=SC2016 # a Go template, not the shell's
aliases=$(direct inspect ygq-jane_shop-web-1 --format '{{range $n, $e := .NetworkSettings.Networks}}{{$n}}={{join $e.Aliases ","}} {{end}}')
case "$aliases" in
*ygq-edge=*ygq-jane_shop-web-1*shop.quire.internal* | *ygq-edge=*shop.quire.internal*ygq-jane_shop-web-1*) ok "jane_shop: its aliases on the shared network" ;;
*) ko "jane_shop: its aliases" "$aliases" ;;
esac
works "jane_shop: compose down" as jane_shop docker compose -p ygq-jane_shop -f "$shop" down --remove-orphans
# Another site's name on the shared network isn't its own
sed 's/shop.quire.internal/jane.quire.internal/' "$shop" > "$dir/jane_shop/site/other.yaml"
refused "jane_shop: jane's site's alias" "isn't one of its own" as jane_shop docker compose -p ygq-jane_shop -f "$dir/jane_shop/site/other.yaml" up -d
as jane_shop docker compose -p ygq-jane_shop -f "$dir/jane_shop/site/other.yaml" down --remove-orphans >/dev/null 2>&1
# jane's file listing jane_shop's container's name (under jane's ygq-jane_ too, but jane_shop's
# prefix is longer): check refuses it. On a copy of the scopes, so the running gate keeps jane's.
mkdir -p "$dir/check/scopes"
cp -p "$dir/scopes/"*.json "$dir/check/scopes/"
sed -i 's/"ygq-jane-web-1"/"ygq-jane-web-1", "ygq-jane_shop-web-1"/' "$dir/check/scopes/jane.json"
sed "s|scopes: $dir/scopes|scopes: $dir/check/scopes|" "$dir/yorvogate.yaml" > "$dir/check/yorvogate.yaml"
# (Its error is on several lines, one for each file refused: both, as neither held it before.)
if output=$("${YORVOGATE:-/yorvogate/yorvogate}" check --config "$dir/check/yorvogate.yaml" 2>&1); then
	ko "check: jane listing jane_shop's container's name as an alias (it was allowed)" "$output"
elif printf '%s' "$output" | grep -q "jane.json: aliases: scope jane's alias \"ygq-jane_shop-web-1\" on ygq-edge is under scope jane_shop's prefix"; then
	ok "check: jane listing jane_shop's container's name as an alias"
else
	ko "check: jane listing jane_shop's container's name as an alias" "$output"
fi

say "== Taking a site down"
works "compose down --remove-orphans --volumes" as jane docker compose -p ygq-jane -f "$jane" down --remove-orphans --volumes
works "buildx rm (jane's builder)" as jane docker buildx rm ygq-jane
works "the orchestrator removes the builder" orchestrator rm -f ygq-buildkit-jane
works "and its volume" orchestrator volume rm ygq-buildkit-jane-state
works "the orchestrator removes the database" orchestrator rm -f ygq-db-jane
if [ -z "$(direct ps -aq --filter label=com.docker.compose.project=ygq-jane)" ]; then ok "nothing of jane's is left"; else ko "jane's containers are left"; fi

say ""
say "$passed passed, $failed failed"
grep '"refused"' "$dir/yorvogate.log" | grep -i 'status":5' | tail -3
[ "$failed" = 0 ]
