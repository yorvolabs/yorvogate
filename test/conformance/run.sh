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

exec docker run --rm -e GITHUB_ACTIONS \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v "$PWD/bin:/yorvogate:ro" \
	-v "$PWD/test/conformance:/conformance:ro" \
	docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb \
	sh /conformance/suite.sh
