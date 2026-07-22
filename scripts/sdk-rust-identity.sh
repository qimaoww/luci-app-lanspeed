#!/bin/sh
set -eu

fail() {
	printf '%s\n' "SDK Rust identity: FAIL: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 <pin|measure> <prepared-sdk-root>"

mode=$1
sdk_root=$2
case "$mode" in
	pin|measure) ;;
	*) fail "unsupported mode $mode; expected pin or measure" ;;
esac

[ -d "$sdk_root" ] || fail "SDK root is not a directory: $sdk_root"
[ -x "$sdk_root/scripts/feeds" ] || fail "SDK feeds helper is missing: $sdk_root/scripts/feeds"
[ -f "$sdk_root/feeds.conf" ] || fail "prepared SDK has no feeds.conf"

tmp_base=${TMPDIR:-/tmp}
[ -d "$tmp_base" ] || fail "temporary directory root does not exist: $tmp_base"
work_dir=$(mktemp -d "$tmp_base/lanspeed-sdk-rust-identity.XXXXXX")
pinned_conf=
cleanup() {
	if [ -n "${pinned_conf:-}" ] && [ -f "$pinned_conf" ]; then
		rm -f -- "$pinned_conf"
	fi
	if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
		rm -rf -- "$work_dir"
	fi
}
trap cleanup EXIT HUP INT TERM

feed_listing="$work_dir/feeds.txt"
feed_manifest="$work_dir/feed-manifest.txt"
config_manifest="$work_dir/config-manifest.txt"
listing_config_manifest="$work_dir/listing-config-manifest.txt"
normalized_conf="$work_dir/feeds.conf"

read_config_manifest() {
	awk '
		{
			line = $0
			sub(/\r$/, "", line)
			sub(/^[[:space:]]+/, "", line)
			sub(/[[:space:]]+$/, "", line)
			if (line == "" || line ~ /^#/) {
				next
			}
			count = split(line, field, /[[:space:]]+/)
			if (count != 3) {
				exit 2
			}
			if (field[1] != "src-git" && field[1] != "src-git-full" && field[1] != "src-link") {
				exit 2
			}
			if (field[2] !~ /^[A-Za-z0-9_]+$/ || field[3] ~ /[|,]/) {
				exit 2
			}
			if (field[1] == "src-link" && field[2] != "lanspeed") {
				exit 2
			}
			printf "%s|%s|%s\n", field[1], field[2], field[3]
		}
	' "$sdk_root/feeds.conf" > "$config_manifest" ||
		fail "feeds.conf contains unsupported flags, includes, fallbacks, or malformed entries"
	[ -s "$config_manifest" ] || fail "feeds.conf has no active feeds"
	LC_ALL=C sort -o "$config_manifest" "$config_manifest"
}

read_feed_listing() {
	accept_branches=$1
	(
		cd "$sdk_root"
		./scripts/feeds list -s -d '|'
	) > "$feed_listing" || fail "could not list prepared SDK feeds"
	: > "$feed_manifest"
	: > "$listing_config_manifest"
	: > "$normalized_conf"

	while IFS='|' read -r feed_name feed_type feed_revision feed_source extra; do
		[ -n "$feed_name" ] || fail "feed listing contains an empty feed name"
		[ -z "$extra" ] || fail "feed $feed_name source contains the identity delimiter"
		case "$feed_name" in
			*[!A-Za-z0-9_]*) fail "feed name is invalid: $feed_name" ;;
		esac
		feed_source=$(printf '%s' "$feed_source" | tr -d '\r')
		case "$feed_source" in
			''|*','*|*'|'*) fail "feed $feed_name has an invalid or fallback source" ;;
		esac

		printf '%s|%s|%s\n' "$feed_type" "$feed_name" "$feed_source" >> "$listing_config_manifest"
		case "$feed_type" in
			src-git|src-git-full)
				case "$feed_revision" in
					''|*[!0-9a-f]*) fail "feed $feed_name has an invalid revision: $feed_revision" ;;
				esac
				[ "${#feed_revision}" -eq 40 ] ||
					fail "feed $feed_name revision is not a 40-character commit: $feed_revision"

				case "$feed_source" in
					*'^'*)
						case "$feed_source" in
							*';'*|*'^'*'^'*) fail "feed $feed_name has an ambiguous commit source" ;;
						esac
						feed_base=${feed_source%%^*}
						configured_revision=${feed_source#*^}
						[ -n "$feed_base" ] && [ "$configured_revision" = "$feed_revision" ] ||
							fail "feed $feed_name checkout does not match its ^commit pin"
						;;
					*';'*)
						[ "$accept_branches" = 1 ] ||
							fail "feed $feed_name must use a ^commit pin; branch sources are not reusable"
						case "$feed_source" in
							*'^'*|*';'*';'*) fail "feed $feed_name has an ambiguous branch source" ;;
						esac
						feed_base=${feed_source%%;*}
						feed_branch=${feed_source#*;}
						[ -n "$feed_base" ] && [ -n "$feed_branch" ] ||
							fail "feed $feed_name has an invalid branch source"
						;;
					*)
						[ "$accept_branches" = 1 ] ||
							fail "feed $feed_name must use a ^commit pin"
						feed_base=$feed_source
						;;
				esac
				case "$feed_base" in
					''|*';'*|*'^'*) fail "feed $feed_name has an invalid repository URL" ;;
				esac
				pinned_source="$feed_base^$feed_revision"
				printf '%s|%s|%s|%s\n' \
					"$feed_name" "$feed_type" "$feed_revision" "$pinned_source" >> "$feed_manifest"
				printf '%s %s %s\n' "$feed_type" "$feed_name" "$pinned_source" >> "$normalized_conf"
				;;
			src-link)
				[ "$feed_name" = lanspeed ] && [ "$feed_revision" = local ] ||
					fail "unexpected local feed $feed_name"
				printf '%s %s %s\n' "$feed_type" "$feed_name" "$feed_source" >> "$normalized_conf"
				;;
			*) fail "unsupported feed type $feed_type for $feed_name" ;;
		esac
	done < "$feed_listing"

	[ -s "$feed_listing" ] || fail "prepared SDK feed listing is empty"
	LC_ALL=C sort -o "$feed_manifest" "$feed_manifest"
	LC_ALL=C sort -o "$listing_config_manifest" "$listing_config_manifest"
	cmp -s "$config_manifest" "$listing_config_manifest" ||
		fail "feeds.conf and the prepared feed listing do not match"
	grep -Eq '^packages\|src-git(-full)?\|' "$feed_manifest" ||
		fail "prepared SDK identity has no pinned packages feed"
	duplicate_feed=$(cut -d'|' -f1 "$feed_manifest" | uniq -d | head -n 1)
	[ -z "$duplicate_feed" ] || fail "duplicate feed identity for $duplicate_feed"
}

measure_identity() {
	read_config_manifest
	read_feed_listing 0

	rust_recipe_dir="$sdk_root/feeds/packages/lang/rust"
	rust_makefile="$rust_recipe_dir/Makefile"
	[ -f "$rust_makefile" ] || fail "prepared packages feed has no Rust host recipe"
	rust_version_lines=$(sed -n 's/^PKG_VERSION:=[[:space:]]*//p' "$rust_makefile")
	[ "$(printf '%s\n' "$rust_version_lines" | sed '/^$/d' | wc -l)" -eq 1 ] ||
		fail "Rust recipe must declare exactly one PKG_VERSION"
	rust_version=$(printf '%s\n' "$rust_version_lines" | sed '/^$/d')
	printf '%s\n' "$rust_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
		fail "invalid SDK Rust recipe version: $rust_version"

	rust_recipe_hash=$(
		cd "$rust_recipe_dir"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
	)
	feeds_hash=$(sha256sum "$feed_manifest" | awk '{print $1}')
	case "$feeds_hash:$rust_recipe_hash" in
		*[!0-9a-f:]*) fail "identity hashing returned invalid output" ;;
	esac
	[ "${#feeds_hash}" -eq 64 ] || fail "feed identity is not SHA256"
	[ "${#rust_recipe_hash}" -eq 64 ] || fail "Rust recipe identity is not SHA256"

	printf 'feeds_hash=%s\n' "$feeds_hash"
	printf 'rust_version=%s\n' "$rust_version"
	printf 'rust_recipe_hash=%s\n' "$rust_recipe_hash"
}

pin_feeds() {
	read_config_manifest
	read_feed_listing 1
	pinned_conf="$sdk_root/feeds.conf.tmp.$$"
	(umask 022 && cp "$normalized_conf" "$pinned_conf") ||
		fail "could not write pinned feeds.conf"
	mv -f -- "$pinned_conf" "$sdk_root/feeds.conf" || fail "could not install pinned feeds.conf"
	pinned_conf=
	measure_identity
}

case "$mode" in
	pin) pin_feeds ;;
	measure) measure_identity ;;
esac
