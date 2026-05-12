#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

FEED_NAME=lanspeed
TARGET=${1:-all}
DRY_RUN=${DRY_RUN:-0}
ENABLE_BPF=${ENABLE_BPF:-0}
TARGET_ARCH=${TARGET_ARCH:-}

die() {
	printf '%s\n' "error: $*" >&2
	exit 1
}

warn() {
	printf '%s\n' "warning: $*" >&2
}

info() {
	printf '%s\n' "$*"
}

usage() {
	cat >&2 <<'EOF'
Usage: SDK_DIR=/path/to/immortalwrt-sdk [DRY_RUN=1] [TARGET_ARCH=x86_64] [ENABLE_BPF=0|1] ./scripts/build-sdk.sh <target>

Targets:
  luci-app-lanspeed  build only the LuCI package target
  lanspeedd          build only the daemon package target
  all                build both package targets

This helper requires an existing ImmortalWrt 25.12 SDK for real builds.
It never downloads SDKs or toolchains.
EOF
}

quote() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\''/g")"
}

validate_flag() {
	name=$1
	value=$2
	case "$value" in
		0|1) ;;
		*) die "$name must be 0 or 1, got '$value'" ;;
	esac
}

validate_target() {
	case "$TARGET" in
		luci-app-lanspeed|lanspeedd|all) ;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage
			die "unsupported package target '$TARGET'"
			;;
	esac
}

metadata_has() {
	pattern=$1
	shift
	for file in "$@"; do
		if [ -f "$file" ] && grep -Eiq "$pattern" "$file"; then
			return 0
		fi
	done
	return 1
}

metadata_any_file_exists() {
	for file in "$@"; do
		if [ -f "$file" ]; then
			return 0
		fi
	done
	return 1
}

check_release_guardrails() {
	metadata_files="$SDK_PATH/version.buildinfo $SDK_PATH/.vermagic $SDK_PATH/feeds.conf.default $SDK_PATH/include/version.mk $SDK_PATH/package/base-files/files/etc/openwrt_release"

	if [ "$DRY_RUN" = 1 ]; then
		info "# dry-run: would check SDK release metadata for ImmortalWrt/OpenWrt 25.12 before compiling"
		return 0
	fi

	# shellcheck disable=SC2086
	if ! metadata_any_file_exists $metadata_files; then
		warn "SDK_DIR has no common release metadata files; cannot prove it is ImmortalWrt 25.12"
		return 0
	fi

	# shellcheck disable=SC2086
	if metadata_has '(^|[^0-9])25\.12([^0-9]|$)|packages-25\.12|openwrt-25\.12|immortalwrt-25\.12|releases/25\.12' $metadata_files; then
		:
	else
		die "SDK_DIR release metadata exists but does not mention ImmortalWrt/OpenWrt 25.12; refusing to risk master/25.12 ABI mixing"
	fi

	# shellcheck disable=SC2086
	if metadata_has '(^|[^[:alnum:]_-])(master|main|trunk|snapshot)([^[:alnum:]_-]|$)' $metadata_files; then
		warn "SDK_DIR metadata contains master/main/trunk/SNAPSHOT markers; verify this is a 25.12 SDK before using produced packages"
	fi

	if [ -n "$TARGET_ARCH" ]; then
		base=$(basename -- "$SDK_PATH")
		case "$base" in
			*"$TARGET_ARCH"*) return 0 ;;
		esac
		# shellcheck disable=SC2086
		if ! metadata_has "$TARGET_ARCH" $metadata_files; then
			warn "TARGET_ARCH=$TARGET_ARCH was not found in SDK_DIR metadata; continuing because OpenWrt SDK targets are often named by target/subtarget"
		fi
	fi
}

select_packages() {
	FEED_PACKAGES=
	COMPILE_PACKAGES=

	case "$TARGET" in
		luci-app-lanspeed)
			FEED_PACKAGES="lanspeedd luci-app-lanspeed"
			COMPILE_PACKAGES="luci-app-lanspeed"
			;;
		lanspeedd)
			FEED_PACKAGES="lanspeedd"
			COMPILE_PACKAGES="lanspeedd"
			;;
		all)
			FEED_PACKAGES="lanspeedd luci-app-lanspeed"
			COMPILE_PACKAGES="lanspeedd luci-app-lanspeed"
			;;
	esac

	if [ "$ENABLE_BPF" = 1 ]; then
		case " $FEED_PACKAGES " in
			*" lanspeedd "*) FEED_PACKAGES="$FEED_PACKAGES lanspeedd-bpf" ;;
		esac
		case " $COMPILE_PACKAGES " in
			*" lanspeedd "*) : ;;
			*) COMPILE_PACKAGES="lanspeedd $COMPILE_PACKAGES" ;;
		esac
	fi
}

resolve_sdk_path() {
	[ -n "${SDK_DIR:-}" ] || die "SDK_DIR is required and must point to an existing ImmortalWrt 25.12 SDK"

	if [ "$DRY_RUN" = 1 ]; then
		if [ -d "$SDK_DIR" ]; then
			SDK_PATH=$(CDPATH= cd -- "$SDK_DIR" && pwd -P) || die "cannot resolve SDK_DIR '$SDK_DIR'"
		else
			SDK_PATH=$SDK_DIR
		fi
		[ "$SDK_PATH" != "$REPO_ROOT" ] || die "SDK_DIR points to this local feed repository; provide an ImmortalWrt 25.12 SDK instead"
		return 0
	fi

	[ -d "$SDK_DIR" ] || die "SDK_DIR '$SDK_DIR' does not exist or is not an ImmortalWrt 25.12 SDK directory"

	SDK_PATH=$(CDPATH= cd -- "$SDK_DIR" && pwd -P) || die "cannot resolve SDK_DIR '$SDK_DIR'"
	[ "$SDK_PATH" != "$REPO_ROOT" ] || die "SDK_DIR points to this local feed repository; provide an ImmortalWrt 25.12 SDK instead"
	[ -f "$SDK_PATH/Makefile" ] || die "SDK_DIR '$SDK_PATH' is missing Makefile and does not look like an SDK"
	[ -x "$SDK_PATH/scripts/feeds" ] || die "SDK_DIR '$SDK_PATH' is missing executable scripts/feeds"
}

print_summary() {
	info "SDK_DIR: $SDK_PATH"
	info "repo feed: src-link $FEED_NAME $REPO_ROOT"
	info "target: $TARGET"
	info "TARGET_ARCH: ${TARGET_ARCH:-not set}"
	info "ENABLE_BPF: $ENABLE_BPF"
	info "DRY_RUN: $DRY_RUN"
	info "feed packages: $FEED_PACKAGES"
	info "compile packages: $COMPILE_PACKAGES"
}

inject_feed() {
	line="src-link $FEED_NAME $REPO_ROOT"
	feeds_conf="$SDK_PATH/feeds.conf"

	if [ "$DRY_RUN" = 1 ]; then
		printf '+ ensure %s contains: %s\n' "$(quote "$feeds_conf")" "$line"
		return 0
	fi

	tmp="$feeds_conf.tmp.$$"
	if [ -f "$feeds_conf" ]; then
		grep -Ev "^[[:space:]]*src-link[[:space:]]+$FEED_NAME[[:space:]]" "$feeds_conf" > "$tmp" || true
	elif [ -f "$SDK_PATH/feeds.conf.default" ]; then
		grep -Ev "^[[:space:]]*src-link[[:space:]]+$FEED_NAME[[:space:]]" "$SDK_PATH/feeds.conf.default" > "$tmp" || true
	else
		: > "$tmp"
	fi
	printf '%s\n' "$line" >> "$tmp"
	mv "$tmp" "$feeds_conf"
}

select_optional_packages() {
	[ "$ENABLE_BPF" = 1 ] || return 0

	if [ "$DRY_RUN" = 1 ]; then
		printf '+ select CONFIG_PACKAGE_lanspeedd-bpf=m before compiling package/lanspeedd/compile\n'
		return 0
	fi

	if [ -x "$SDK_PATH/scripts/config" ] && [ ! -d "$SDK_PATH/scripts/config" ]; then
		run_in_sdk ./scripts/config --module PACKAGE_lanspeedd-bpf
	else
		set_config_module PACKAGE_lanspeedd-bpf
	fi
	run_in_sdk make defconfig
}

set_config_module() {
	symbol=$1
	config_file="$SDK_PATH/.config"
	tmp="$config_file.tmp.$$"

	if [ -f "$config_file" ]; then
		grep -Ev "^(# )?CONFIG_${symbol}(=| is not set)" "$config_file" > "$tmp" || true
	else
		: > "$tmp"
	fi
	printf '%s\n' "CONFIG_${symbol}=m" >> "$tmp"
	mv "$tmp" "$config_file"
}

run_in_sdk() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '+ cd %s &&' "$(quote "$SDK_PATH")"
		for arg in "$@"; do
			case "$arg" in
				*[!A-Za-z0-9_./=:-]*) printf ' %s' "$(quote "$arg")" ;;
				*) printf ' %s' "$arg" ;;
			esac
		done
		printf '\n'
		return 0
	fi

	(cd "$SDK_PATH" && "$@")
}

main() {
	[ "$#" -le 1 ] || die "expected one package target, got $# arguments"
	validate_flag DRY_RUN "$DRY_RUN"
	validate_flag ENABLE_BPF "$ENABLE_BPF"
	validate_target
	select_packages
	resolve_sdk_path
	check_release_guardrails
	print_summary

	info "# local feed injection preview"
	inject_feed
	run_in_sdk ./scripts/feeds update -a
	for package in $FEED_PACKAGES; do
		run_in_sdk ./scripts/feeds install -p "$FEED_NAME" "$package"
	done
	select_optional_packages
	for package in $COMPILE_PACKAGES; do
		run_in_sdk make "package/$package/compile" V=s
	done
}

main "$@"
