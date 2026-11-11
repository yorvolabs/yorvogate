#!/bin/sh
# YorvoGate's conformance suite (suite.sh) against the Docker this machine's CLI uses: in a container
# with Docker's CLI and Compose (pinned), Docker's socket, and the binary "make build" made.
#   make build && test/conformance/run.sh
set -eu
cd "$(dirname "$0")/../.."

if [ ! -x bin/yorvogate ]; then
	echo 'Build it first: make build' >&2
	exit 1
fi

# Three times: scopes by token (in a header), each on its own socket, and each by its client certificate (mTLS)
status=0
for listener in tokens sockets mtls; do
	docker run --rm -e GITHUB_ACTIONS -e YGC_LISTENER=$listener \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$PWD/bin:/yorvogate:ro" \
		-v "$PWD/test/conformance:/conformance:ro" \
		docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb \
		sh /conformance/suite.sh || status=1
done
# Then Quire Server's real use: an orchestrator, sites on their own sockets, builds on rootless
# BuildKit (YGC_APPARMOR: the host's AppArmor profile for it, where it has AppArmor)
docker run --rm -e GITHUB_ACTIONS -e YGC_APPARMOR \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v "$PWD/bin:/yorvogate:ro" \
	-v "$PWD/test/conformance:/conformance:ro" \
	docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb \
	sh /conformance/quire.sh || status=1
# Then a rootless build from docs/configuration.md alone: its listener, scope file and commands
docker run --rm -e GITHUB_ACTIONS -e YGC_APPARMOR \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v "$PWD/bin:/yorvogate:ro" \
	-v "$PWD/test/conformance:/conformance:ro" \
	-v "$PWD/docs:/docs:ro" \
	docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb \
	sh /conformance/docs.sh || status=1
# Then an AI agent's socket, as docs/agents.md sets it up: the sockets' folder a volume, so an agent's
# container can mount its one socket
docker run --rm -e GITHUB_ACTIONS \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v ygc-agents:/agents \
	-v "$PWD/bin:/yorvogate:ro" \
	-v "$PWD/test/conformance:/conformance:ro" \
	docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb \
	sh /conformance/agents.sh || status=1
docker volume rm ygc-agents >/dev/null 2>&1
exit $status
