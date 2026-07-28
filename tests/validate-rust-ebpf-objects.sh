#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
	printf 'usage: %s <kfunc-object> <fallback-object> [aarch64-ecm-object]\n' "$0" >&2
	exit 2
fi

kfunc_object=$1
fallback_object=$2
ecm_object=${3:-}
readelf_bin=$(command -v -- "${READELF:-readelf}" 2>/dev/null || true)
objdump_bin=$(command -v -- "${LLVM_OBJDUMP:-llvm-objdump}" 2>/dev/null || true)

fail() {
	printf 'eBPF object validation: FAIL: %s\n' "$*" >&2
	exit 1
}

[[ -n $readelf_bin ]] || fail "readelf executable not found: ${READELF:-readelf}"
[[ -n $objdump_bin ]] || fail "llvm-objdump executable not found: ${LLVM_OBJDUMP:-llvm-objdump}"

has_symbol() {
	local symbols=$1
	local name=$2
	awk -v expected="$name" '$NF == expected { found = 1 } END { exit !found }' <<<"$symbols"
}

validate_common() {
	local label=$1
	local object=$2
	local header sections symbols license_dump license_hex license_size disassembly
	local section program map

	[[ -s $object ]] || fail "$label object is missing or empty: $object"
	header=$("$readelf_bin" -h "$object")
	grep -Eq 'Class:[[:space:]]+ELF64([[:space:]]|$)' <<<"$header" || \
		fail "$label object is not ELF64"
	grep -Eq 'Data:[[:space:]]+2.s complement, little endian' <<<"$header" || \
		fail "$label object is not little-endian"
	grep -Eq 'Machine:[[:space:]]+(Linux BPF|EM_BPF)' <<<"$header" || \
		fail "$label object is not EM_BPF"

	sections=$("$readelf_bin" -SW "$object")
	for section in '\.BTF' '\.BTF\.ext' 'classifier' 'maps' 'license'; do
		grep -Eq "[[:space:]]${section}[[:space:]]" <<<"$sections" || \
			fail "$label object is missing section ${section//\\/}"
	done

	license_size=$(awk '$3 == "license" { print $7; found = 1 } END { if (!found) exit 1 }' <<<"$sections") || \
		fail "$label object license section is missing"
	[[ $license_size == 000004 ]] || \
		fail "$label object license section has unexpected size $license_size"
	license_dump=$("$readelf_bin" -x license "$object")
	license_hex=$(awk '$1 ~ /^0x/ { print tolower($2) }' <<<"$license_dump")
	[[ $license_hex == 47504c00 ]] || \
		fail "$label object license is not exactly GPL\\0"

	symbols=$("$readelf_bin" -sW "$object")
	for program in \
		lanspeed_ingress lanspeed_egress \
		lanspeed_ingress_early lanspeed_egress_early; do
		has_symbol "$symbols" "$program" || \
			fail "$label object is missing classifier program $program"
	done
	for map in lanspeed_clients lanspeed_packet_prefix; do
		has_symbol "$symbols" "$map" || fail "$label object is missing map $map"
	done

	disassembly=$("$objdump_bin" -d "$object")
	grep -Eq 'lock[[:space:]]+\*\(u64 \*\).*\+= r[0-9]+' <<<"$disassembly" || \
		fail "$label object has no 64-bit BPF atomic add instruction"
}

validate_common kfunc "$kfunc_object"
kfunc_symbols=$("$readelf_bin" -sW "$kfunc_object")
for required_map in lanspeed_conntrack_scratch lanspeed_seen_conns; do
	has_symbol "$kfunc_symbols" "$required_map" || \
		fail "kfunc object is missing map $required_map"
done
kfunc_disassembly=$("$objdump_bin" -d "$kfunc_object")
grep -Eq 'lock[[:space:]]+\*\(u32 \*\).*\+= r[0-9]+' <<<"$kfunc_disassembly" || \
	fail 'kfunc object has no 32-bit BPF atomic add instruction'
for forbidden in \
	lanspeed_ecm_update lanspeed_ecm_nss_enter lanspeed_ecm_nss_exit \
	lanspeed_ecm_clients lanspeed_ecm_layout lanspeed_ecm_nss_context lanspeed_ecm_source_stats; do
	if has_symbol "$kfunc_symbols" "$forbidden"; then
		fail "kfunc TC object unexpectedly contains ECM symbol $forbidden"
	fi
done

validate_common fallback "$fallback_object"
fallback_symbols=$("$readelf_bin" -sW "$fallback_object")
for forbidden_map in lanspeed_conntrack_scratch lanspeed_seen_conns; do
	if has_symbol "$fallback_symbols" "$forbidden_map"; then
		fail "fallback object unexpectedly contains map $forbidden_map"
	fi
done
for forbidden in \
	lanspeed_ecm_update lanspeed_ecm_nss_enter lanspeed_ecm_nss_exit \
	lanspeed_ecm_clients lanspeed_ecm_layout lanspeed_ecm_nss_context lanspeed_ecm_source_stats; do
	if has_symbol "$fallback_symbols" "$forbidden"; then
		fail "fallback TC object unexpectedly contains ECM symbol $forbidden"
	fi
done

if [[ -n $ecm_object ]]; then
	[[ -s $ecm_object ]] || fail "ECM object is missing or empty: $ecm_object"
	ecm_header=$("$readelf_bin" -h "$ecm_object")
	grep -Eq 'Class:[[:space:]]+ELF64([[:space:]]|$)' <<<"$ecm_header" || \
		fail 'ECM object is not ELF64'
	grep -Eq 'Data:[[:space:]]+2.s complement, little endian' <<<"$ecm_header" || \
		fail 'ECM object is not little-endian'
	grep -Eq 'Machine:[[:space:]]+(Linux BPF|EM_BPF)' <<<"$ecm_header" || \
		fail 'ECM object is not EM_BPF'

	ecm_sections=$("$readelf_bin" -SW "$ecm_object")
	for section in '\.BTF' '\.BTF\.ext' 'kprobe' 'kretprobe' 'kprobe/ecm_db_connection_data_totals_update' 'maps' 'license'; do
		grep -Eq "[[:space:]]${section}[[:space:]]" <<<"$ecm_sections" || \
			fail "ECM object is missing section ${section//\\/}"
	done
	if grep -Eq '[[:space:]]classifier(/|[[:space:]])' <<<"$ecm_sections"; then
		fail 'ECM object unexpectedly contains a TC classifier section'
	fi
	ecm_license_size=$(awk '$3 == "license" { print $7; found = 1 } END { if (!found) exit 1 }' <<<"$ecm_sections") || \
		fail 'ECM object license section is missing'
	[[ $ecm_license_size == 000004 ]] || \
		fail "ECM object license section has unexpected size $ecm_license_size"
	ecm_license_hex=$("$readelf_bin" -x license "$ecm_object" | \
		awk '$1 ~ /^0x/ { print tolower($2) }')
	[[ $ecm_license_hex == 47504c00 ]] || fail 'ECM object license is not exactly GPL\0'

	ecm_symbols=$("$readelf_bin" -sW "$ecm_object")
	for required in \
		lanspeed_ecm_update lanspeed_ecm_nss_enter lanspeed_ecm_nss_exit \
		lanspeed_ecm_clients lanspeed_ecm_layout lanspeed_ecm_nss_context lanspeed_ecm_source_stats; do
		has_symbol "$ecm_symbols" "$required" || fail "ECM object is missing symbol $required"
	done
	for forbidden in \
		lanspeed_ingress lanspeed_egress lanspeed_ingress_early lanspeed_egress_early \
		lanspeed_clients lanspeed_packet_prefix lanspeed_conntrack_scratch lanspeed_seen_conns; do
		if has_symbol "$ecm_symbols" "$forbidden"; then
			fail "ECM object unexpectedly contains TC symbol $forbidden"
		fi
	done
	ecm_disassembly=$("$objdump_bin" -d "$ecm_object")
	grep -Eq 'lock[[:space:]]+\*\(u64 \*\).*\+= r[0-9]+' <<<"$ecm_disassembly" || \
		fail 'ECM object has no 64-bit BPF atomic add instruction'
fi

printf 'eBPF object validation: PASS: architecture-separated EM_BPF, BTF, programs, maps, GPL, and atomics\n'
