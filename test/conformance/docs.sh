#!/bin/sh
# A rootless build from docs/configuration.md alone: the listener, the scope file, the builder and
# the buildx commands are the docs' own, taken from the file as it is. Only paths move to this
# test's, the scope jane becomes ygd-jane and its builder ygd-buildkit, so nothing of a real setup on
# the machine is touched.
# If the docs drift from what works, this fails. Run it through run.sh.
# YGC_APPARMOR names the host's AppArmor profile for rootless BuildKit, where the host has AppArmor.
set -u

dir=/tmp/docs
docs=$(dirname "$0")/../../docs/configuration.md
apparmor=${YGC_APPARMOR:-}
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"

# block HEADING LANG N: the Nth fenced LANG block under the "## HEADING" section of the docs ("" for
# the part before the first section)
block() {
	awk -v heading="## $1" -v lang="$2" -v n="$3" '
		BEGIN { in_section = (heading == "## ") }
		/^## / { in_section = ($0 == heading) }
		in_section && $0 == "```" lang { count++; if (count == n) { inside = 1; next } }
		inside && /^```$/ { exit }
		inside { print }
	' "$docs"
}

# What the docs name, moved to this test's paths and names
moved() {
	sed -e "s|/run/yorvogate/sites|$dir/sockets|g" -e "s|/etc/yorvogate/sites|$dir/scopes|g" \
		-e "s|/var/lib/yorvogate|$dir|g" -e "s|/srv/scopes/jane|$dir/jane|g" -e 's|buildkit-jane|ygd-buildkit|g' \
		-e 's|jane|ygd-jane|g'
}

cleanup() {
	direct rm -f ygd-buildkit >/dev/null 2>&1
	direct volume rm ygd-buildkit-state >/dev/null 2>&1
	direct rmi registry.example.com/tenants/ygd-jane/app:1 >/dev/null 2>&1
	[ -n "${gate:-}" ] && kill "$gate" 2>/dev/null
}
trap cleanup EXIT
cleanup

say "== A rootless build from docs/configuration.md alone (AppArmor profile: ${apparmor:-none})"
mkdir -p "$dir/scopes" "$dir/sockets" "$dir/ygd-jane/docker" "$dir/app"

# The configuration: the reference's top-level settings and its "sites" listener (its socket group
# is a host's, so it's left out: the sockets are this process's group's)
block "" yaml 1 | awk '
	/^listeners:/ { print; listeners = 1; next }
	!listeners { print; next }
	/^  - name: / { sites = ($3 == "sites") }
	sites
' | grep -v '^    socket_group:' | moved > "$dir/yorvogate.yaml"
without_lsm "$dir/yorvogate.yaml"
# The scope file: the docs' example, which names the builder and the image namespace the build uses
block "Scope files (scoped listeners)" json 1 | moved > "$dir/scopes/ygd-jane.json"
chmod 600 "$dir/scopes/ygd-jane.json"

if grep -q '^  - name: sites' "$dir/yorvogate.yaml" && grep -q '"builders"' "$dir/scopes/ygd-jane.json"; then
	ok "the docs give a listener with scope sockets, and a scope with a builder"
else
	ko "the docs give a listener with scope sockets, and a scope with a builder" "$(cat "$dir/yorvogate.yaml" "$dir/scopes/ygd-jane.json")"
fi
if grep -v '^[[:space:]]*#' "$dir/yorvogate.yaml" | grep -q '/run/yorvogate\|/etc/yorvogate'; then
	ko "the docs' configuration has a path this test doesn't move" "$(grep '/run/yorvogate\|/etc/yorvogate' "$dir/yorvogate.yaml")"
fi
works "yorvogate check: the docs' listener and scope" "${YORVOGATE:-/yorvogate/yorvogate}" check --config "$dir/yorvogate.yaml"

${YORVOGATE:-/yorvogate/yorvogate} serve --config "$dir/yorvogate.yaml" 2> "$dir/yorvogate.log" &
gate=$!
sleep 1

# The builder, as the docs run it (on the orchestrator's side: Docker itself here). Where the host
# has no AppArmor, its profile option goes; elsewhere it's the profile the host loaded.
block Builders sh 1 | moved | if [ -n "$apparmor" ]; then
	sed "s|apparmor=yorvogate-buildkit-rootless|apparmor=$apparmor|"
else
	grep -v 'apparmor='
fi > "$dir/builder.sh"
works "the docs' builder: docker run" env -u DOCKER_HOST sh "$dir/builder.sh"

# The scope's side, line by line as the docs give it: its DOCKER_CONFIG, a context on its socket,
# the builder registered with buildx, the build
cat > "$dir/app/Dockerfile" <<'EOF'
FROM busybox:1.37
RUN echo built > /built
EOF
block Builders sh 3 | moved > "$dir/scope.sh"
while IFS= read -r line; do
	case "$line" in
	'' | '#'*) continue ;;
	export\ *)
		eval "$line"
		continue
		;;
	*'buildx build'*)
		# BuildKit takes a moment to start: it answers once it's up
		for _ in $(seq 30); do
			env -u DOCKER_HOST timeout 10 docker buildx inspect --bootstrap ygd-jane >/dev/null 2>&1 && break
			sleep 1
		done
		;;
	esac
	works "the docs: $(printf '%s' "$line" | cut -c1-70)" env -u DOCKER_HOST sh -c "cd '$dir/app' && $line"
done < "$dir/scope.sh"

if direct image inspect registry.example.com/tenants/ygd-jane/app:1 >/dev/null 2>&1; then ok "the image is built, in the scope's namespace"; else ko "the image is built, in the scope's namespace" "$(tail -5 "$dir/yorvogate.log")"; fi
if grep -q '"scope":"ygd-jane".*"endpoint":"image.load"' "$dir/yorvogate.log"; then ok "it was loaded through the scope's socket"; else ko "it was loaded through the scope's socket" "$(grep image.load "$dir/yorvogate.log" | tail -3)"; fi

say "$passed passed, $failed failed"
[ "$failed" = 0 ]
