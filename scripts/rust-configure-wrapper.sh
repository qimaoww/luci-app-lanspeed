#!/usr/bin/env bash
set -euo pipefail

real_bash=${LANSPEED_REAL_BASH:-}
if [[ -z "$real_bash" ]]; then
	real_bash=$(command -v bash)
fi
if [[ ! -x "$real_bash" ]]; then
	printf '%s\n' "error: could not resolve the real Bash executable" >&2
	exit 1
fi

rewritten=0
args=()
has_llvm_args=0
llvm_targets_options=0
llvm_experimental_targets_options=0
for arg in "$@"; do
	if [[ "$arg" == '--set=llvm.download-ci-llvm=true' ]]; then
		arg='--set=llvm.download-ci-llvm=false'
		((rewritten += 1))
	fi
	case "$arg" in
		--set=llvm.download-ci-llvm=*|--set=llvm.targets=*|--set=llvm.experimental-targets=*)
			((has_llvm_args += 1))
			;;
	esac
	case "$arg" in
		--set=llvm.targets=*)
			((llvm_targets_options += 1))
			;;
		--set=llvm.experimental-targets=*)
			((llvm_experimental_targets_options += 1))
			;;
	esac
	args+=("$arg")
done

if (( rewritten > 1 )); then
	printf '%s\n' "error: Rust configure contains duplicate llvm.download-ci-llvm options" >&2
	exit 1
fi

is_rust_configure=0
case "${1:-}" in
	./configure|*/configure) is_rust_configure=1 ;;
esac
if ((is_rust_configure == 0)); then
	if (( rewritten > 0 )); then
		printf '%s\n' "error: refusing to rewrite llvm.download-ci-llvm outside Rust configure" >&2
		exit 1
	fi
	exec "$real_bash" "${@}"
fi

# Only configure invocations carrying the rust bootstrap's LLVM options belong
# to the compiler build. A generic host package's ./configure (which OpenWrt
# may also route through $BASH) can still arrive here, and must pass through
# untouched instead of tripping over the missing rust --target below.
if ((has_llvm_args == 0)); then
	exec "$real_bash" "${args[@]}"
fi

# Keep only the code-generation backends used by the compiler host, package
# target, and the eBPF target. Rust's default enables every LLVM backend, and
# the packages feed pins llvm.download-ci-llvm=false, so this is the dominant
# cost of a cold SDK build. Trim it unconditionally on configure invocations.
llvm_arch_targets=()
saw_rust_target=0

add_llvm_arch_target() {
	local triple=$1
	local llvm_arch
	local existing
	case "$triple" in
		x86_64-*) llvm_arch=X86 ;;
		aarch64-*) llvm_arch=AArch64 ;;
		*) return 1 ;;
	esac
	for existing in "${llvm_arch_targets[@]}"; do
		if [[ "$existing" == "$llvm_arch" ]]; then
			return 0
		fi
	done
	llvm_arch_targets+=("$llvm_arch")
}

add_llvm_arch_target_list() {
	local target_list=$1
	local target_kind=$2
	local triple
	local target_triples=()
	IFS=',' read -r -a target_triples <<< "$target_list"
	for triple in "${target_triples[@]}"; do
		if ! add_llvm_arch_target "$triple"; then
			if [[ "$target_kind" == target ]]; then
				printf '%s\n' "error: unsupported Rust target for minimal LLVM backend set: $triple" >&2
				exit 1
			fi
		fi
	done
}

for ((index = 1; index < ${#args[@]}; index += 1)); do
	target_value=
	target_kind=
	switch_arg=${args[index]}
	case "$switch_arg" in
		--target=*|--build=*|--host=*)
			target_kind=${switch_arg%%=*}
			target_kind=${target_kind#--}
			target_value=${switch_arg#*=}
		;;
		--target|--build|--host)
			target_kind=${switch_arg#--}
			((index += 1))
			if ((index >= ${#args[@]})); then
				printf '%s\n' "error: Rust configure --$target_kind is missing its value" >&2
				exit 1
			fi
			target_value=${args[index]}
		;;
		*) continue ;;
	esac
	if [[ -n "$target_value" ]]; then
		add_llvm_arch_target_list "$target_value" "$target_kind"
		if [[ "$target_kind" == target ]]; then
			saw_rust_target=1
		fi
	fi
done
if ((saw_rust_target == 0)); then
	printf '%s\n' 'error: Rust configure has no target; cannot select a minimal LLVM backend set' >&2
	exit 1
fi
llvm_arch_targets+=(BPF)
llvm_target_value=
for llvm_arch_target in "${llvm_arch_targets[@]}"; do
	if [[ -n "$llvm_target_value" ]]; then
		llvm_target_value+=';'
	fi
	llvm_target_value+="$llvm_arch_target"
done

if ((llvm_targets_options > 1)); then
	printf '%s\n' 'error: Rust configure contains duplicate llvm.targets options' >&2
	exit 1
fi
if ((llvm_experimental_targets_options > 1)); then
	printf '%s\n' 'error: Rust configure contains duplicate llvm.experimental-targets options' >&2
	exit 1
fi

policy_args=()
for arg in "${args[@]}"; do
	case "$arg" in
		--set=llvm.targets=*)
			if ((llvm_targets_options == 1)); then
				arg="--set=llvm.targets=${llvm_target_value}"
			fi
			;;
		--set=llvm.experimental-targets=*)
			if ((llvm_experimental_targets_options == 1)); then
				arg='--set=llvm.experimental-targets='
			fi
			;;
	esac
	policy_args+=("$arg")
done
if ((llvm_targets_options == 0)); then
	policy_args+=("--set=llvm.targets=${llvm_target_value}")
fi
if ((llvm_experimental_targets_options == 0)); then
	policy_args+=('--set=llvm.experimental-targets=')
fi
args=("${policy_args[@]}")
printf '%s\n' "# Rust bootstrap will build LLVM from source (targets: $llvm_target_value)" >&2

exec "$real_bash" "${args[@]}"
