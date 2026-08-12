#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
	printf '%s\n' 'usage: apk-userns-fakeroot.sh <apk-tool> [apk arguments...]' >&2
	exit 2
fi

apk_tool=$1
shift

[ -x "$apk_tool" ] || {
	printf '%s\n' "apk user namespace wrapper: executable not found: $apk_tool" >&2
	exit 1
}

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/lanspeed-apk-root.XXXXXX")
cleanup() {
	rm -rf -- "${tmp_root:?}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$tmp_root/etc"
printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' > "$tmp_root/etc/passwd"
printf '%s\n' 'root:x:0:' > "$tmp_root/etc/group"

status=0
unshare -Ur -m sh -c '
	root=$1
	mount --bind "$root/etc/passwd" /etc/passwd
	mount --bind "$root/etc/group" /etc/group
	shift
	apk=$1
	shift
	exec "$apk" --root "$root" "$@"' sh "$tmp_root" "$apk_tool" "$@" || status=$?
exit "$status"
