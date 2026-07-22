#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

FEED_NAME=lanspeed
TARGET=${1:-all}
DRY_RUN=${DRY_RUN:-0}
ENABLE_BPF=${ENABLE_BPF:-1}
TARGET_ARCH=${TARGET_ARCH:-}
SDK_RELEASE=${SDK_RELEASE:-25.12}
SDK_BASE_FEED_REF=${SDK_BASE_FEED_REF:-}
SDK_FEEDS_PREPARED=${SDK_FEEDS_PREPARED:-0}
SDK_FEEDS_HASH=${SDK_FEEDS_HASH:-}
SDK_RUST_VERSION=${SDK_RUST_VERSION:-}
SDK_RUST_RECIPE_HASH=${SDK_RUST_RECIPE_HASH:-}
SDK_RUST_IDENTITY_SCRIPT="$REPO_ROOT/scripts/sdk-rust-identity.sh"

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
Usage: SDK_DIR=/path/to/immortalwrt-sdk [DRY_RUN=1] [TARGET_ARCH=x86_64] [ENABLE_BPF=0|1] [SDK_RELEASE=25.12] [SDK_FEEDS_PREPARED=0|1] [SDK_FEEDS_HASH=sha256] [SDK_RUST_VERSION=x.y.z] [SDK_RUST_RECIPE_HASH=sha256] ./scripts/build-sdk.sh <target>

Targets:
  prepare-feeds       inject and update feeds without installing or compiling packages
  luci-app-lanspeed  build only the LuCI package target
  lanspeedd          build only the daemon package target
  all                build both package targets

This helper requires an existing ImmortalWrt/OpenWrt SDK matching SDK_RELEASE for real builds.
It never downloads SDKs or toolchains.
ENABLE_BPF defaults to 1. ENABLE_BPF=0 is only supported with the lanspeedd target
for the release workflow's split base-package pass.
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
		prepare-feeds|luci-app-lanspeed|lanspeedd|all) ;;
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

validate_bpf_target() {
	[ "$TARGET" != prepare-feeds ] || return 0
	if [ "$ENABLE_BPF" = 0 ] && [ "$TARGET" != lanspeedd ]; then
		die "ENABLE_BPF=0 is only supported with the lanspeedd target; LuCI builds require lanspeedd-bpf"
	fi
}

validate_sdk_release() {
	case "$SDK_RELEASE" in
		''|*[!0-9.]*)
			die "SDK_RELEASE must contain only digits and dots, got '$SDK_RELEASE'"
			;;
	esac
}

validate_optional_sha() {
	name=$1
	value=$2
	[ -n "$value" ] || return 0
	case "$value" in
		*[!0-9a-fA-F]*)
			die "$name must be a git commit hash, got '$value'"
			;;
	esac
	len=${#value}
	if [ "$len" -lt 7 ] || [ "$len" -gt 64 ]; then
		die "$name must be between 7 and 64 hex characters, got '$value'"
	fi
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
	sdk_release_re=$(printf '%s' "$SDK_RELEASE" | sed 's/\./\\./g')

	if [ "$DRY_RUN" = 1 ]; then
		info "# dry-run: would check SDK release metadata for ImmortalWrt/OpenWrt $SDK_RELEASE before compiling"
		return 0
	fi

	# shellcheck disable=SC2086
	if ! metadata_any_file_exists $metadata_files; then
		warn "SDK_DIR has no common release metadata files; cannot prove it is ImmortalWrt/OpenWrt $SDK_RELEASE"
		return 0
	fi

	# shellcheck disable=SC2086
	if metadata_has "(^|[^0-9])$sdk_release_re([^0-9]|$)|packages-$sdk_release_re|openwrt-$sdk_release_re|immortalwrt-$sdk_release_re|releases/$sdk_release_re" $metadata_files; then
		:
	else
		die "SDK_DIR release metadata exists but does not mention ImmortalWrt/OpenWrt $SDK_RELEASE; refusing to risk SDK ABI mixing"
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
		prepare-feeds)
			return 0
			;;
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
	[ -n "${SDK_DIR:-}" ] || die "SDK_DIR is required and must point to an existing ImmortalWrt/OpenWrt $SDK_RELEASE SDK"

	if [ "$DRY_RUN" = 1 ]; then
		if [ -d "$SDK_DIR" ]; then
			SDK_PATH=$(CDPATH= cd -- "$SDK_DIR" && pwd -P) || die "cannot resolve SDK_DIR '$SDK_DIR'"
		else
			SDK_PATH=$SDK_DIR
		fi
		[ "$SDK_PATH" != "$REPO_ROOT" ] || die "SDK_DIR points to this local feed repository; provide an ImmortalWrt 25.12 SDK instead"
		return 0
	fi

	[ -d "$SDK_DIR" ] || die "SDK_DIR '$SDK_DIR' does not exist or is not an ImmortalWrt/OpenWrt $SDK_RELEASE SDK directory"

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
	info "SDK_RELEASE: $SDK_RELEASE"
	info "SDK_BASE_FEED_REF: ${SDK_BASE_FEED_REF:-not set}"
	info "SDK_FEEDS_PREPARED: $SDK_FEEDS_PREPARED"
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
		if [ -n "$SDK_BASE_FEED_REF" ]; then
			printf '+ pin base feed to commit %s\n' "$SDK_BASE_FEED_REF"
		fi
		return 0
	fi

	tmp="$feeds_conf.tmp.$$"
	if [ -f "$feeds_conf" ]; then
		source_conf=$feeds_conf
	elif [ -f "$SDK_PATH/feeds.conf.default" ]; then
		source_conf=$SDK_PATH/feeds.conf.default
	else
		source_conf=
	fi

	if [ -n "$source_conf" ] && [ -n "$SDK_BASE_FEED_REF" ]; then
		awk -v feed="$FEED_NAME" -v base_ref="$SDK_BASE_FEED_REF" '
			$1 == "src-link" && $2 == feed { next }
			$1 ~ /^src-git/ && $2 == "base" {
				print "src-git base https://github.com/immortalwrt/immortalwrt.git^" base_ref
				pinned = 1
				next
			}
			{ print }
			END {
				if (!pinned) {
					print "error: SDK_BASE_FEED_REF set but no base feed was found" > "/dev/stderr"
					exit 2
				}
			}
		' "$source_conf" > "$tmp"
	elif [ -n "$source_conf" ]; then
		grep -Ev "^[[:space:]]*src-link[[:space:]]+$FEED_NAME[[:space:]]" "$source_conf" > "$tmp" || true
	else
		: > "$tmp"
	fi
	printf '%s\n' "$line" >> "$tmp"
	mv "$tmp" "$feeds_conf"
}

verify_prepared_feeds() {
	if [ "$DRY_RUN" = 1 ]; then
		info "# dry-run: would verify pinned feed indexes and the packages Rust recipe"
		return 0
	fi

	[ -f "$SDK_PATH/feeds/packages/lang/rust/Makefile" ] || \
		die "prepared feeds are missing feeds/packages/lang/rust/Makefile"
	[ -e "$SDK_PATH/feeds/packages.index" ] || \
		die "prepared feeds are missing the packages feed index"
	[ -e "$SDK_PATH/feeds/$FEED_NAME.index" ] || \
		die "prepared feeds are missing the $FEED_NAME feed index"
	if [ "$SDK_FEEDS_PREPARED" = 1 ]; then
		[ -n "$SDK_FEEDS_HASH" ] && [ -n "$SDK_RUST_VERSION" ] && [ -n "$SDK_RUST_RECIPE_HASH" ] || \
			die "SDK_FEEDS_PREPARED=1 requires SDK_FEEDS_HASH, SDK_RUST_VERSION, and SDK_RUST_RECIPE_HASH"
		identity=$(measure_sdk_identity) || die "could not recompute the prepared SDK Rust identity"
		actual_feeds_hash=$(printf '%s\n' "$identity" | sed -n 's/^feeds_hash=//p')
		actual_rust_version=$(printf '%s\n' "$identity" | sed -n 's/^rust_version=//p')
		actual_rust_recipe_hash=$(printf '%s\n' "$identity" | sed -n 's/^rust_recipe_hash=//p')
		[ "$actual_feeds_hash" = "$SDK_FEEDS_HASH" ] || \
			die "prepared SDK feeds changed after identity measurement"
		[ "$actual_rust_version" = "$SDK_RUST_VERSION" ] || \
			die "prepared SDK Rust recipe version changed after identity measurement"
		[ "$actual_rust_recipe_hash" = "$SDK_RUST_RECIPE_HASH" ] || \
			die "prepared SDK Rust recipe changed after identity measurement"
	fi
}

measure_sdk_identity() {
	(
		# TARGET_ARCH is a metadata label and must not alter feed probing.
		unset TARGET_ARCH
		"$SDK_RUST_IDENTITY_SCRIPT" measure "$SDK_PATH"
	)
}

pin_sdk_feeds() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '+ pin prepared SDK feeds to their actual checkout commits\n'
		return 0
	fi
	(
		unset TARGET_ARCH
		"$SDK_RUST_IDENTITY_SCRIPT" pin "$SDK_PATH"
	) || die "could not pin prepared SDK feeds to their actual revisions"
}

update_and_pin_sdk_feeds() {
	run_in_sdk ./scripts/feeds update -a
	pin_sdk_feeds
}

configure_packages() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '+ select CONFIG_PACKAGE_lanspeedd=m before compiling package/lanspeedd/compile\n'
		if [ "$ENABLE_BPF" = 1 ]; then
			printf '+ select CONFIG_PACKAGE_lanspeedd-bpf=m before compiling package/lanspeedd/compile\n'
		else
			printf '+ disable CONFIG_PACKAGE_lanspeedd-bpf before compiling package/lanspeedd/compile\n'
		fi
		return 0
	fi

	if [ -x "$SDK_PATH/scripts/config" ] && [ ! -d "$SDK_PATH/scripts/config" ]; then
		run_in_sdk ./scripts/config --module PACKAGE_lanspeedd
		if [ "$ENABLE_BPF" = 1 ]; then
			run_in_sdk ./scripts/config --module PACKAGE_lanspeedd-bpf
		else
			run_in_sdk ./scripts/config --disable PACKAGE_lanspeedd-bpf
		fi
	else
		set_config_module PACKAGE_lanspeedd
		if [ "$ENABLE_BPF" = 1 ]; then
			set_config_module PACKAGE_lanspeedd-bpf
		else
			set_config_disabled PACKAGE_lanspeedd-bpf
		fi
	fi
}

refresh_sdk_config() {
	run_in_sdk make defconfig
}

compile_package() {
	package=$1
	if [ "$package" = "lanspeedd" ]; then
		if [ "$ENABLE_BPF" = 1 ]; then
			bpf_package_config=m
			base_package_config=
		else
			bpf_package_config=
			base_package_config=m
		fi
		run_in_sdk make "package/$package/compile" V=s "LANSPEED_BUILD_BPF=$ENABLE_BPF" "CONFIG_PACKAGE_lanspeedd=$base_package_config" "CONFIG_PACKAGE_lanspeedd-bpf=$bpf_package_config"
	else
		run_in_sdk make "package/$package/compile" V=s
	fi
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

set_config_disabled() {
	symbol=$1
	config_file="$SDK_PATH/.config"
	tmp="$config_file.tmp.$$"

	if [ -f "$config_file" ]; then
		grep -Ev "^(# )?CONFIG_${symbol}(=| is not set)" "$config_file" > "$tmp" || true
	else
		: > "$tmp"
	fi
	printf '%s\n' "# CONFIG_${symbol} is not set" >> "$tmp"
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

	(
		unset TARGET_ARCH
		cd "$SDK_PATH"
		"$@"
	)
}

main() {
	[ "$#" -le 1 ] || die "expected one package target, got $# arguments"
	validate_flag DRY_RUN "$DRY_RUN"
	validate_flag ENABLE_BPF "$ENABLE_BPF"
	validate_flag SDK_FEEDS_PREPARED "$SDK_FEEDS_PREPARED"
	if [ "$SDK_FEEDS_PREPARED" = 1 ]; then
		case "$SDK_FEEDS_HASH" in
			*[!0-9a-f]*|'') die "SDK_FEEDS_HASH must be a lowercase SHA256 when SDK_FEEDS_PREPARED=1" ;;
		esac
		[ "${#SDK_FEEDS_HASH}" -eq 64 ] || die "SDK_FEEDS_HASH must be 64 hex characters"
		case "$SDK_RUST_RECIPE_HASH" in
			*[!0-9a-f]*|'') die "SDK_RUST_RECIPE_HASH must be a lowercase SHA256 when SDK_FEEDS_PREPARED=1" ;;
		esac
		[ "${#SDK_RUST_RECIPE_HASH}" -eq 64 ] || die "SDK_RUST_RECIPE_HASH must be 64 hex characters"
		printf '%s\n' "$SDK_RUST_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || \
			die "SDK_RUST_VERSION must be a stable x.y.z version when SDK_FEEDS_PREPARED=1"
	fi
	validate_sdk_release
	validate_optional_sha SDK_BASE_FEED_REF "$SDK_BASE_FEED_REF"
	validate_target
	validate_bpf_target
	select_packages
	resolve_sdk_path
	check_release_guardrails
	print_summary

	info "# local feed injection preview"
	inject_feed
	if [ "$TARGET" = prepare-feeds ]; then
		[ "$SDK_FEEDS_PREPARED" = 0 ] || \
			die "prepare-feeds cannot be combined with SDK_FEEDS_PREPARED=1"
		update_and_pin_sdk_feeds
		verify_prepared_feeds
		return 0
	fi
	configure_packages
	if [ "$SDK_FEEDS_PREPARED" = 1 ]; then
		verify_prepared_feeds
		info "# reusing prepared SDK feeds without another network update"
	else
		update_and_pin_sdk_feeds
		verify_prepared_feeds
	fi
	for package in $FEED_PACKAGES; do
		run_in_sdk ./scripts/feeds install -p "$FEED_NAME" "$package"
	done
	configure_packages
	refresh_sdk_config
	for package in $COMPILE_PACKAGES; do
		compile_package "$package"
	done
}

main "$@"
