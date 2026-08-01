#!/bin/sh

lanspeed_test_output_init() {
	if [ -n "${LANSPEED_TEST_OUTPUT_DIR:-}" ]; then
		LANSPEED_TEST_OUTPUT_OWNED=0
	else
		LANSPEED_TEST_OUTPUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lanspeed-tests.XXXXXX")
		LANSPEED_TEST_OUTPUT_OWNED=1
	fi

	mkdir -p "$LANSPEED_TEST_OUTPUT_DIR"
	export LANSPEED_TEST_OUTPUT_DIR
}

lanspeed_test_output_cleanup() {
	if [ "${LANSPEED_TEST_OUTPUT_OWNED:-0}" -ne 1 ]; then
		return 0
	fi

	case "$LANSPEED_TEST_OUTPUT_DIR" in
		"${TMPDIR:-/tmp}"/lanspeed-tests.*) ;;
		*)
			printf 'refusing to remove unexpected test output directory: %s\n' \
				"$LANSPEED_TEST_OUTPUT_DIR" >&2
			return 1
			;;
	esac

	rm -rf -- "$LANSPEED_TEST_OUTPUT_DIR"
	LANSPEED_TEST_OUTPUT_OWNED=0
}
