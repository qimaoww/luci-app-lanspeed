#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

read_make_var() {
	file=$1
	name=$2
	sed -n "s/^${name}:=//p" "$file" | head -n 1
}

daemon_makefile="$ROOT/net/lanspeedd/Makefile"
luci_makefile="$ROOT/applications/luci-app-lanspeed/Makefile"

daemon_version=$(read_make_var "$daemon_makefile" PKG_VERSION)
daemon_release=$(read_make_var "$daemon_makefile" PKG_RELEASE)
luci_version=$(read_make_var "$luci_makefile" PKG_VERSION)
luci_release=$(read_make_var "$luci_makefile" PKG_RELEASE)

[ -n "$daemon_version" ] || {
	printf '%s\n' "error: missing PKG_VERSION in $daemon_makefile" >&2
	exit 1
}
[ -n "$daemon_release" ] || {
	printf '%s\n' "error: missing PKG_RELEASE in $daemon_makefile" >&2
	exit 1
}
[ "$daemon_version" = "$luci_version" ] || {
	printf '%s\n' "error: daemon and LuCI PKG_VERSION do not match" >&2
	exit 1
}
[ "$daemon_release" = "$luci_release" ] || {
	printf '%s\n' "error: daemon and LuCI PKG_RELEASE do not match" >&2
	exit 1
}

printf '%s\n' "${daemon_version}-r${daemon_release}"
