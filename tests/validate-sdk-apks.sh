#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
	printf 'usage: %s <sdk-root> <expected-package-arch> <daemon.apk> <bpf.apk> <luci.apk>\n' "$0" >&2
}

fail() {
	printf 'SDK APK validation: FAIL: %s\n' "$*" >&2
	exit 1
}

if [[ $# -ne 5 ]]; then
	usage
	exit 2
fi

sdk_root=$1
expected_arch=$2
daemon_apk=$3
bpf_apk=$4
luci_apk=$5
apk_tool="$sdk_root/staging_dir/host/bin/apk"
readelf_tool=${READELF:-readelf}

[[ -d $sdk_root ]] || fail "SDK root is not a directory: $sdk_root"
[[ -x $apk_tool ]] || fail "SDK apk executable is missing: $apk_tool"
command -v -- jq >/dev/null 2>&1 || fail 'jq executable not found'
readelf_tool=$(command -v -- "$readelf_tool" 2>/dev/null || true)
[[ -n $readelf_tool ]] || fail "readelf executable not found: ${READELF:-readelf}"

case "$expected_arch" in
	x86_64)
		expected_machine='Advanced Micro Devices X86-64'
		;;
	aarch64*)
		expected_machine='AArch64'
		;;
	*)
		fail "unsupported LP64 package architecture: $expected_arch"
		;;
esac

for package_path in "$daemon_apk" "$bpf_apk" "$luci_apk"; do
	[[ -s $package_path ]] || fail "APK is missing or empty: $package_path"
done

tmp_base=${TMPDIR:-/tmp}
[[ -d $tmp_base ]] || fail "temporary directory root does not exist: $tmp_base"
work_dir=$(mktemp -d "$tmp_base/validate-sdk-apks.XXXXXX")
cleanup() {
	if [[ -n ${work_dir:-} && -d $work_dir ]]; then
		rm -rf -- "${work_dir:?}"
	fi
}
trap cleanup EXIT HUP INT TERM

dump_metadata() {
	local label=$1
	local package_path=$2
	local output=$3

	if ! "$apk_tool" adbdump --format json "$package_path" >"$output"; then
		fail "$label metadata could not be read with SDK apk adbdump"
	fi
	jq -e '.info | type == "object"' "$output" >/dev/null || \
		fail "$label metadata has no package info object"
}

assert_metadata_field() {
	local label=$1
	local metadata=$2
	local field=$3
	local expected=$4
	local actual

	actual=$(jq -er ".info.$field | select(type == \"string\")" "$metadata" 2>/dev/null || true)
	[[ $actual == "$expected" ]] || \
		fail "$label $field is '$actual', expected '$expected'"
}

dependency_name() {
	local dependency=$1

	dependency=${dependency#!}
	printf '%s\n' "${dependency%%[\<\>\=\~]*}"
}

assert_no_forbidden_dependencies() {
	local label=$1
	local metadata=$2
	local dependency name

	while IFS= read -r dependency; do
		[[ -n $dependency ]] || continue
		name=$(dependency_name "$dependency")
		case "$name" in
			libubus*|libubox*|libuci*|libblobmsg-json*|libblobmsg_json*|uloop*|libuloop*|\
			so:libubus*|so:libubox*|so:libuci*|so:libblobmsg-json*|so:libblobmsg_json*|\
			so:uloop*|so:libuloop*)
				fail "$label has forbidden OpenWrt ABI dependency: $dependency"
				;;
		esac
	done < <(jq -r '.info.depends[]?' "$metadata")
}

assert_dependencies() {
	local label=$1
	local metadata=$2
	shift 2
	local actual expected

	actual=$(jq -r '.info.depends[]?' "$metadata" | while IFS= read -r dependency; do
		dependency_name "$dependency"
	done | LC_ALL=C sort)
	expected=$(printf '%s\n' "$@" | LC_ALL=C sort)
	if [[ $actual != "$expected" ]]; then
		printf 'SDK APK validation: FAIL: %s dependency contract mismatch\n' "$label" >&2
		printf '  expected:\n%s\n' "$expected" >&2
		printf '  actual:\n%s\n' "$actual" >&2
		exit 1
	fi
}

daemon_metadata="$work_dir/daemon.json"
bpf_metadata="$work_dir/bpf.json"
luci_metadata="$work_dir/luci.json"
dump_metadata daemon "$daemon_apk" "$daemon_metadata"
dump_metadata BPF "$bpf_apk" "$bpf_metadata"
dump_metadata LuCI "$luci_apk" "$luci_metadata"

assert_metadata_field daemon "$daemon_metadata" name lanspeedd
assert_metadata_field daemon "$daemon_metadata" arch "$expected_arch"
assert_metadata_field BPF "$bpf_metadata" name lanspeedd-bpf
assert_metadata_field BPF "$bpf_metadata" arch "$expected_arch"
assert_metadata_field LuCI "$luci_metadata" name luci-app-lanspeed
assert_metadata_field LuCI "$luci_metadata" arch noarch

assert_no_forbidden_dependencies daemon "$daemon_metadata"
assert_no_forbidden_dependencies BPF "$bpf_metadata"
assert_no_forbidden_dependencies LuCI "$luci_metadata"

assert_dependencies daemon "$daemon_metadata" \
	kmod-nf-conntrack-netlink libc libgcc1
assert_dependencies BPF "$bpf_metadata" \
	kmod-sched-bpf lanspeedd libc tc-full
assert_dependencies LuCI "$luci_metadata" \
	lanspeedd lanspeedd-bpf libc luci-base

extract_package() {
	local label=$1
	local package_path=$2
	local destination=$3

	mkdir -p -- "$destination"
	if ! "$apk_tool" --allow-untrusted extract --no-chown \
		--destination "$destination" "$package_path" >/dev/null; then
		fail "$label could not be extracted with SDK apk"
	fi
}

daemon_root="$work_dir/daemon-root"
bpf_root="$work_dir/bpf-root"
luci_root="$work_dir/luci-root"
extract_package daemon "$daemon_apk" "$daemon_root"
extract_package BPF "$bpf_apk" "$bpf_root"
extract_package LuCI "$luci_apk" "$luci_root"

daemon="$daemon_root/usr/sbin/lanspeedd"
[[ -s $daemon ]] || fail "daemon APK does not contain usr/sbin/lanspeedd"

daemon_header=$("$readelf_tool" -hW "$daemon")
grep -Eq 'Class:[[:space:]]+ELF64([[:space:]]|$)' <<<"$daemon_header" || \
	fail 'daemon is not ELF64'
daemon_machine=$(awk -F: '/^[[:space:]]*Machine:/ {
	sub(/^[[:space:]]+/, "", $2); sub(/[[:space:]]+$/, "", $2); print $2; exit
}' <<<"$daemon_header")
[[ $daemon_machine == "$expected_machine" ]] || \
	fail "daemon ELF machine is '$daemon_machine', expected '$expected_machine'"

daemon_dynamic=$("$readelf_tool" -dW "$daemon")
needed=$(sed -n 's/.*(NEEDED).*Shared library: \[\([^]]*\)\].*/\1/p' <<<"$daemon_dynamic")
[[ -n $needed ]] || fail 'daemon has no DT_NEEDED entries'
has_libc=false
while IFS= read -r library; do
	[[ -n $library ]] || continue
	case "$library" in
		libc.so|libc.so.*)
			has_libc=true
			;;
		libgcc.so|libgcc.so.*|libgcc_s.so|libgcc_s.so.*)
			;;
		*)
			fail "daemon has forbidden DT_NEEDED library: $library"
			;;
	esac
done <<<"$needed"
[[ $has_libc == true ]] || fail 'daemon DT_NEEDED does not include libc'

READELF="$readelf_tool" LLVM_OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump}" \
	"$script_dir/validate-rust-ebpf-objects.sh" \
	"$bpf_root/usr/lib/bpf/lanspeed-ebpf-kfunc.o" \
	"$bpf_root/usr/lib/bpf/lanspeed-ebpf-fallback.o"

printf 'SDK APK validation: PASS: %s metadata, dependency, ELF, BTF, and atomic contracts\n' \
	"$expected_arch"
