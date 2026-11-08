#!/bin/sh
# Checks a release's files: make dist's output (CI), or a published release downloaded (the release
# workflow, after publishing). Every file a release carries is there, SHA256SUMS lists each one and
# they check out, and the files copied from the repo (the schemas, the AppArmor profile) are the
# repo's at this checkout.
#   test/dist.sh <directory> <version>
set -eu

dir=$1
version=$2
repo=$(cd "$(dirname "$0")/.." && pwd)
fail=0

bad() {
	echo "  FAIL $*"
	fail=1
}

[ -f "$dir/SHA256SUMS" ] || { echo "no SHA256SUMS in $dir"; exit 1; }

# What a release carries, and where each copied file comes from in the repo
expected="yorvogate-$version-linux-amd64.tar.gz yorvogate-$version-linux-arm64.tar.gz yorvogate-buildkit-rootless"
for s in "$repo"/schemas/*.schema.json; do
	expected="$expected $(basename "$s")"
done

for f in $expected; do
	[ -f "$dir/$f" ] || bad "$f: not in the release"
	grep -q "^[0-9a-f]\{64\}  $f\$" "$dir/SHA256SUMS" || bad "$f: not in SHA256SUMS"
done

# Nothing listed that isn't expected
unexpected=$(cut -c67- "$dir/SHA256SUMS" | while read -r f; do
	case " $expected " in
	*" $f "*) ;;
	*) echo "$f" ;;
	esac
done)
[ -z "$unexpected" ] || bad "in SHA256SUMS, not files a release carries: $(echo "$unexpected" | tr '\n' ' ')"

(cd "$dir" && sha256sum --quiet --check SHA256SUMS) || bad "SHA256SUMS doesn't check out"

cmp -s "$dir/yorvogate-buildkit-rootless" "$repo/examples/apparmor/yorvogate-buildkit-rootless" ||
	bad "yorvogate-buildkit-rootless: not the repo's examples/apparmor/yorvogate-buildkit-rootless"
for s in "$repo"/schemas/*.schema.json; do
	cmp -s "$dir/$(basename "$s")" "$s" || bad "$(basename "$s"): not the repo's schemas/$(basename "$s")"
done

if [ $fail -ne 0 ]; then
	exit 1
fi
echo "ok   the release's files: $(echo "$expected" | wc -w) files, each in SHA256SUMS and checking out"
