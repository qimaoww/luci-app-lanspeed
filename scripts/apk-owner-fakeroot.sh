#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
	printf '%s\n' 'usage: apk-owner-fakeroot.sh <apk-tool> [apk arguments...]' >&2
	exit 2
fi

[ "$(id -u)" -ne 0 ] || {
	printf '%s\n' 'apk owner fakeroot: refusing to run as root' >&2
	exit 1
}

apk_tool=$1
shift

[ -x "$apk_tool" ] || {
	printf '%s\n' "apk owner fakeroot: executable not found: $apk_tool" >&2
	exit 1
}

host_bin=$(CDPATH= cd -- "$(dirname -- "$apk_tool")" && pwd -P)
host_root=$(CDPATH= cd -- "$host_bin/.." && pwd -P)
fakeroot_tool="$host_bin/fakeroot"

[ -x "$fakeroot_tool" ] || {
	printf '%s\n' "apk owner fakeroot: SDK fakeroot not found: $fakeroot_tool" >&2
	exit 1
}

files=
read_files=0
for arg in "$@"; do
	if [ "$read_files" = 1 ]; then
		files=$arg
		read_files=0
		continue
	fi
	case "$arg" in
		--files|-F) read_files=1 ;;
	esac
done

[ -n "$files" ] && [ -d "$files" ] || {
	printf '%s\n' 'apk owner fakeroot: mkpkg --files directory is missing' >&2
	exit 1
}

STAGING_DIR_HOST=${STAGING_DIR_HOST:-$host_root}
export STAGING_DIR_HOST

exec "$fakeroot_tool" sh -eu -c '
	files=$1
	apk=$2
	shift 2
	chown -R 0:0 "$files"
	exec "$apk" "$@"
' sh "$files" "$apk_tool" "$@"
