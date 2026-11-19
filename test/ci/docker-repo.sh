#!/bin/sh
# Docker Engine from Docker's own repository for this Ubuntu, its signing key checked by fingerprint:
# what CI's conformance runs against (a runner's own Docker could be any version).
#
#   docker-repo.sh setup             add the repository (once, before the others)
#   docker-repo.sh newest [MAJOR]    the newest version it has (29.9.3), of MAJOR if given
#   docker-repo.sh newer-major M...  the newest version of a major newer than every M, if one exists
#   docker-repo.sh install VERSION   install that version (Engine, CLI, containerd)
set -eu

# Docker's release key (download.docker.com/linux/ubuntu/gpg)
fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88

# Every docker-ce version the repository has, newest first: 29.9.3, 29.9.2, …
versions() {
	apt-cache madison docker-ce | awk -F'|' '{ gsub(/ /, "", $2); print $2 }' | sed -E 's/^[0-9]+://; s/-.*$//' | sort -uVr
}

case ${1:-} in
setup)
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o docker.asc
	gpg --show-keys --with-colons docker.asc | grep -q "^fpr:::::::::$fingerprint:\$"
	sudo install -m 0755 -d /etc/apt/keyrings
	sudo install -m 0644 docker.asc /etc/apt/keyrings/docker.asc
	rm docker.asc
	# shellcheck source=/dev/null # the runner's
	. /etc/os-release
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
	sudo apt-get update -q
	;;
newest)
	if [ -n "${2:-}" ]; then
		versions | grep -E "^$2\." | head -n 1
	else
		versions | head -n 1
	fi
	;;
newer-major)
	shift
	highest=$(printf '%s\n' "$@" | sort -n | tail -n 1)
	versions | awk -F. -v h="$highest" '$1 > h { print; exit }'
	;;
install)
	version=$2
	echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "::error::$version isn't a Docker Engine version."; exit 1; }
	# shellcheck source=/dev/null # the runner's
	. /etc/os-release
	full="5:$version-1~ubuntu.$VERSION_ID~$VERSION_CODENAME"
	sudo apt-get install -y -q --allow-downgrades "docker-ce=$full" "docker-ce-cli=$full" containerd.io
	;;
*)
	echo "usage: docker-repo.sh setup | newest [MAJOR] | newer-major MAJOR... | install VERSION" >&2
	exit 2
	;;
esac
