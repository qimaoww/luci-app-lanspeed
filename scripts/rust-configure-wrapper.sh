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
for arg in "$@"; do
	if [[ "$arg" == '--set=llvm.download-ci-llvm=true' ]]; then
		arg='--set=llvm.download-ci-llvm=false'
		((rewritten += 1))
	fi
	args+=("$arg")
done

if (( rewritten > 1 )); then
	printf '%s\n' "error: Rust configure contains duplicate llvm.download-ci-llvm options" >&2
	exit 1
fi
if (( rewritten == 1 )); then
	case "${1:-}" in
		./configure|*/configure) ;;
		*)
			printf '%s\n' "error: refusing to rewrite llvm.download-ci-llvm outside Rust configure" >&2
			exit 1
			;;
	esac
	printf '%s\n' "# Rust bootstrap will build LLVM from source" >&2
fi

exec "$real_bash" "${args[@]}"
