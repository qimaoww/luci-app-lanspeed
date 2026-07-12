#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s <immortalwrt-root> <output>\n' "$0" >&2
	exit 2
fi

sdk_root=$1
output=$2
target_root="$sdk_root/staging_dir/target-x86_64_musl"
include_root="$target_root/usr/include"
toolchain_root=$(find "$sdk_root/staging_dir" -maxdepth 1 -type d \
	-name 'toolchain-x86_64_gcc-*_musl' -print | LC_ALL=C sort)
bindgen_bin=${BINDGEN:-$sdk_root/staging_dir/hostpkg/bin/bindgen}

if [ ! -d "$include_root" ]; then
	printf 'missing ImmortalWrt target headers: %s\n' "$include_root" >&2
	exit 1
fi

if [ -z "$toolchain_root" ] || [ "$(printf '%s\n' "$toolchain_root" | wc -l)" -ne 1 ]; then
	printf 'expected exactly one x86_64 musl toolchain sysroot under %s/staging_dir\n' "$sdk_root" >&2
	exit 1
fi

if ! bindgen_version=$($bindgen_bin --version 2>/dev/null); then
	printf 'bindgen CLI 0.72.1 is required (set BINDGEN to its path)\n' >&2
	exit 1
fi

if [ "$bindgen_version" != 'bindgen 0.72.1' ]; then
	printf 'bindgen CLI 0.72.1 is required, found: %s\n' "$bindgen_version" >&2
	exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
wrapper="$tmp_dir/openwrt-bindings.h"

cat >"$wrapper" <<'EOF'
#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <uci.h>
EOF

mkdir -p "$(dirname "$output")"

"$bindgen_bin" "$wrapper" \
	--output "$output" \
	--use-core \
	--ctypes-prefix libc \
	--no-doc-comments \
	--default-enum-style newtype_global \
	--with-derive-default \
	--allowlist-type '^(blob_attr|blob_buf|blobmsg_policy|uloop_fd|uloop_timeout|uloop_signal|ubus_context|ubus_method|ubus_msg_status|ubus_object|ubus_object_type|ubus_request_data|uci_context|uci_element|uci_list|uci_option|uci_option_type|uci_package|uci_section|uci_type)$' \
	--allowlist-function '^(blob_buf_init|blob_buf_free|blobmsg_add_json_from_string|uloop_init|uloop_run_timeout|uloop_done|uloop_fd_add|uloop_fd_delete|uloop_timeout_set|uloop_timeout_cancel|uloop_signal_add|uloop_signal_delete|ubus_connect|ubus_reconnect|ubus_free|ubus_add_object|ubus_remove_object|ubus_lookup_id|ubus_send_reply|uci_alloc_context|uci_free_context|uci_set_confdir|uci_load|uci_unload|uci_lookup_ptr|uci_lookup_next)$' \
	--allowlist-var '^(uloop_cancelled|ULOOP_READ|ULOOP_BLOCKING|UBUS_STATUS_OK|UBUS_STATUS_UNKNOWN_ERROR)$' \
	--opaque-type '^uci_context$' \
	-- \
	--target=x86_64-openwrt-linux-musl \
	--sysroot="$toolchain_root" \
	-I"$include_root"
