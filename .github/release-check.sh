#!/bin/sh
# Whether a version tag may be released: a release tag's form (vX.Y.Z or vX.Y.Z-rc.N), annotated and
# signed by a key in .github/release-signers as main lists them (a tag's own commit can't add its
# signer), on a commit of main, with the changelog's section for its version. Whether CI passed on it
# is the Release workflow's next step.
# Usage: .github/release-check.sh v0.4.0
set -eu

tag=$1

if ! echo "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
	echo "::error::$tag isn't a release tag: vX.Y.Z or vX.Y.Z-rc.N, nothing else (other tags go under a namespace, never v)."
	exit 1
fi

signers=$(mktemp)
trap 'rm -f "$signers"' EXIT
git show origin/main:.github/release-signers >"$signers"

if ! grep -Eqv '^(#|[[:space:]]*$)' "$signers"; then
	echo "::error::.github/release-signers on main lists no key: no tag can be released until the maintainer's is added."
	exit 1
fi

# The tag object itself, which a checkout may not have fetched
git fetch --quiet --no-tags --force origin "refs/tags/$tag:refs/tags/$tag"

if [ "$(git cat-file -t "refs/tags/$tag")" != tag ]; then
	echo "::error::The tag $tag isn't annotated, so it isn't signed: make it with git tag -s."
	exit 1
fi

if ! git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" tag -v "$tag"; then
	echo "::error::The tag $tag isn't signed by a key in .github/release-signers."
	exit 1
fi

commit=$(git rev-parse "refs/tags/$tag^{commit}")

if ! git merge-base --is-ancestor "$commit" origin/main; then
	echo "::error::The tag's commit $commit isn't on main."
	exit 1
fi

version=${tag#v}

if ! git show "$commit:CHANGELOG.md" | grep -q "^## \[$version\] - [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\$"; then
	echo "::error::CHANGELOG.md has no section for $version: move [Unreleased] under it, as \"## [$version] - YYYY-MM-DD\", before tagging."
	exit 1
fi
