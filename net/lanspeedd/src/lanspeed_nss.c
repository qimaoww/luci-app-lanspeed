/* SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <libubox/utils.h>

#include "lanspeed_nss.h"

struct nss_ecm_direct_flow {
	char serial[32];
	char sip_address[IP_STR_LEN];
	char dip_address[IP_STR_LEN];
	char sip_address_nat[IP_STR_LEN];
	char dip_address_nat[IP_STR_LEN];
	char snode_address[MAC_STR_LEN];
	char dnode_address[MAC_STR_LEN];
	char snode_address_nat[MAC_STR_LEN];
	char dnode_address_nat[MAC_STR_LEN];
	uint64_t from_data_total;
	uint64_t to_data_total;
	int protocol;
	bool has_sip_address;
	bool has_sip_address_nat;
	bool has_from_data_total;
};

static void nss_add_warning(struct json_object *warnings, const char *warning)
{
	size_t i, n;

	if (!warnings || !warning)
		return;

	n = json_object_array_length(warnings);
	for (i = 0; i < n; i++) {
		struct json_object *item = json_object_array_get_idx(warnings, i);
		if (item && !strcmp(json_object_get_string(item), warning))
			return;
	}

	json_object_array_add(warnings, json_object_new_string(warning));
}

static bool nss_ecm_direct_flow_add_endpoint(struct conntrack_client_sample *samples,
					     size_t *sample_count,
					     size_t max_samples,
					     const struct arp_entry *arp,
					     enum flow_endpoint_role role,
					     const struct nss_ecm_direct_flow *flow,
					     uint64_t now_ms,
					     struct nss_ecm_direct_stats *stats)
{
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	bool source_side = role == FLOW_ENDPOINT_ORIG_SRC;

	if (!flow || !arp)
		return false;

	if (source_side) {
		tx_bytes = flow->from_data_total;
		rx_bytes = flow->to_data_total;
	} else {
		tx_bytes = flow->to_data_total;
		rx_bytes = flow->from_data_total;
	}

	if (!add_endpoint_sample_bytes(samples, sample_count, max_samples, arp,
				       NULL, tx_bytes, rx_bytes, now_ms,
				       (uint32_t)flow->protocol, true))
		return false;

	if (stats) {
		stats->entries_matched++;
		flow_endpoint_stats_add(source_side, arp,
					&stats->src_lan_flows,
					&stats->dst_lan_flows,
					&stats->ipv4_lan_flows,
					&stats->ipv6_lan_flows);
	}
	return true;
}

static void nss_ecm_direct_flow_reset(struct nss_ecm_direct_flow *flow,
				      const char *serial)
{
	memset(flow, 0, sizeof(*flow));
	if (serial)
		snprintf(flow->serial, sizeof(flow->serial), "%s", serial);
}

static bool parse_nss_ecm_state_key(const char *key, char *serial,
				    size_t serial_size, char *field,
				    size_t field_size)
{
	const char *prefix = "conns.conn.";
	const char *p;
	const char *dot;
	size_t serial_len;

	if (!key || strncmp(key, prefix, strlen(prefix)))
		return false;

	p = key + strlen(prefix);
	dot = strchr(p, '.');
	if (!dot || dot == p)
		return false;

	serial_len = (size_t)(dot - p);
	if (serial_len >= serial_size)
		return false;

	memcpy(serial, p, serial_len);
	serial[serial_len] = '\0';
	snprintf(field, field_size, "%s", dot + 1);
	return field[0] != '\0';
}

static void copy_nss_ecm_value(char *dst, size_t dst_size, const char *value)
{
	size_t len;

	if (!dst || dst_size == 0)
		return;

	if (!value)
		value = "";

	len = strnlen(value, dst_size - 1);
	memcpy(dst, value, len);
	dst[len] = '\0';
}

static void nss_ecm_direct_flow_apply_field(struct nss_ecm_direct_flow *flow,
					    const char *field, const char *value)
{
	if (!strcmp(field, "sip_address")) {
		copy_nss_ecm_value(flow->sip_address, sizeof(flow->sip_address), value);
		flow->has_sip_address = true;
	} else if (!strcmp(field, "dip_address")) {
		copy_nss_ecm_value(flow->dip_address, sizeof(flow->dip_address), value);
	} else if (!strcmp(field, "sip_address_nat")) {
		copy_nss_ecm_value(flow->sip_address_nat, sizeof(flow->sip_address_nat), value);
		flow->has_sip_address_nat = true;
	} else if (!strcmp(field, "dip_address_nat")) {
		copy_nss_ecm_value(flow->dip_address_nat, sizeof(flow->dip_address_nat), value);
	} else if (!strcmp(field, "snode_address")) {
		copy_nss_ecm_value(flow->snode_address, sizeof(flow->snode_address), value);
		normalize_mac_address(flow->snode_address);
	} else if (!strcmp(field, "dnode_address")) {
		copy_nss_ecm_value(flow->dnode_address, sizeof(flow->dnode_address), value);
		normalize_mac_address(flow->dnode_address);
	} else if (!strcmp(field, "snode_address_nat")) {
		copy_nss_ecm_value(flow->snode_address_nat, sizeof(flow->snode_address_nat), value);
		normalize_mac_address(flow->snode_address_nat);
	} else if (!strcmp(field, "dnode_address_nat")) {
		copy_nss_ecm_value(flow->dnode_address_nat, sizeof(flow->dnode_address_nat), value);
		normalize_mac_address(flow->dnode_address_nat);
	} else if (!strcmp(field, "protocol")) {
		flow->protocol = atoi(value);
	} else if (!strcmp(field, "adv_stats.from_data_total")) {
		char *end = NULL;
		flow->from_data_total = strtoull(value, &end, 10);
		flow->has_from_data_total = end && end != value;
	} else if (!strcmp(field, "adv_stats.to_data_total")) {
		char *end = NULL;
		flow->to_data_total = strtoull(value, &end, 10);
		(void)end;
	}
}

static bool parse_nss_ecm_state_line(const char *line, char *serial,
				     size_t serial_size, char *field,
				     size_t field_size, char *value,
				     size_t value_size)
{
	char buffer[NSS_ECM_STATE_LINE_MAX];
	char *eq;
	char *raw_value;

	if (!line || !serial || !field || !value)
		return false;

	snprintf(buffer, sizeof(buffer), "%s", line);
	eq = strchr(buffer, '=');
	if (!eq)
		return false;
	*eq = '\0';
	raw_value = eq + 1;
	raw_value[strcspn(raw_value, "\r\n")] = '\0';

	if (!parse_nss_ecm_state_key(buffer, serial, serial_size,
				     field, field_size))
		return false;
	snprintf(value, value_size, "%s", raw_value);
	return true;
}

static bool add_nss_ecm_direct_flow_to_samples(struct conntrack_client_sample *samples,
					       size_t *sample_count,
					       size_t max_samples,
					       const struct arp_entry *arp_entries,
					       size_t arp_count,
					       const struct nss_ecm_direct_flow *flow,
					       uint64_t now_ms,
					       struct nss_ecm_direct_stats *stats)
{
	struct flow_lan_endpoint src;
	struct flow_lan_endpoint dst;
	const char *src_mac;
	const char *dst_mac;
	bool has_src;
	bool has_dst;

	if (!flow || (!flow->has_sip_address && !flow->has_sip_address_nat) ||
	    !flow->has_from_data_total)
		return false;

	src_mac = valid_mac_address(flow->snode_address) ?
		flow->snode_address : flow->snode_address_nat;
	dst_mac = valid_mac_address(flow->dnode_address) ?
		flow->dnode_address : flow->dnode_address_nat;
	has_src = nss_ecm_direct_endpoint_lookup(arp_entries, arp_count,
						 flow->sip_address,
						 flow->sip_address_nat,
						 src_mac,
						 FLOW_ENDPOINT_ORIG_SRC, &src);
	has_dst = nss_ecm_direct_endpoint_lookup(arp_entries, arp_count,
						 flow->dip_address,
						 flow->dip_address_nat,
						 dst_mac,
						 FLOW_ENDPOINT_ORIG_DST, &dst);

	if (has_src && has_dst) {
		if (stats)
			stats->both_lan_flows++;
		return true;
	}
	if (!has_src && !has_dst) {
		if (stats) {
			stats->skipped_no_arp++;
			stats->no_lan_flows++;
		}
		return true;
	}

	if (has_src)
		return nss_ecm_direct_flow_add_endpoint(samples, sample_count, max_samples,
							src.arp, FLOW_ENDPOINT_ORIG_SRC,
							flow, now_ms, stats);

	return nss_ecm_direct_flow_add_endpoint(samples, sample_count, max_samples,
						dst.arp, FLOW_ENDPOINT_ORIG_DST,
						flow, now_ms, stats);
}

static bool nss_ecm_state_open_path(const char *path, FILE **file, int *err_out)
{
	FILE *fp;
	int fd;

	*file = NULL;
	if (err_out)
		*err_out = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (err_out)
			*err_out = errno;
		return false;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		if (err_out)
			*err_out = errno;
		close(fd);
		return false;
	}

	*file = fp;
	return true;
}

bool nss_ecm_state_open(FILE **file, char *source_path,
			size_t source_path_size, int *err_out,
			unsigned int *major_out)
{
	FILE *major_file;
	unsigned int major = 0;

	if (major_out)
		*major_out = 0;
	if (nss_ecm_state_open_path(NSS_ECM_STATE_DEV_PATH, file, err_out)) {
		snprintf(source_path, source_path_size, "%s", NSS_ECM_STATE_DEV_PATH);
		return true;
	}

	major_file = fopen(NSS_ECM_STATE_DEV_MAJOR_PATH, "r");
	if (!major_file)
		return false;
	if (fscanf(major_file, "%u", &major) != 1 || major == 0) {
		fclose(major_file);
		if (err_out)
			*err_out = EINVAL;
		return false;
	}
	fclose(major_file);
	if (major_out)
		*major_out = major;

	unlink(NSS_ECM_STATE_TMP_DEV_PATH);
	if (mknod(NSS_ECM_STATE_TMP_DEV_PATH, S_IFCHR | 0600, makedev(major, 0)) != 0) {
		if (err_out)
			*err_out = errno;
		return false;
	}

	if (!nss_ecm_state_open_path(NSS_ECM_STATE_TMP_DEV_PATH, file, err_out)) {
		unlink(NSS_ECM_STATE_TMP_DEV_PATH);
		return false;
	}
	unlink(NSS_ECM_STATE_TMP_DEV_PATH);

	snprintf(source_path, source_path_size, "%s", NSS_ECM_STATE_TMP_DEV_PATH);
	return true;
}

bool read_nss_ecm_direct_snapshot(struct conntrack_client_sample *samples,
				  size_t *sample_count, size_t max_samples,
				  uint64_t now_ms, struct json_object *warnings,
				  struct nss_ecm_direct_stats *stats)
{
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	size_t arp_count;
	FILE *file = NULL;
	char line[NSS_ECM_STATE_LINE_MAX];
	struct nss_ecm_direct_flow active_flow;
	char active_serial[32] = "";
	bool have_active = false;

	*sample_count = 0;
	memset(stats, 0, sizeof(*stats));
	stats->state_attempted = true;

	arp_count = load_lan_identity_table(arp_entries, ARRAY_SIZE(arp_entries), warnings);
	if (arp_count == 0) {
		nss_add_warning(warnings, "skip_nss_ecm_direct_flow_without_lan_identity");
		return false;
	}

	if (!nss_ecm_state_open(&file, stats->source_path,
				sizeof(stats->source_path), &stats->state_errno,
				&stats->state_major)) {
		nss_add_warning(warnings, "nss_ecm_direct_unavailable");
		return false;
	}

	stats->state_read = true;
	nss_ecm_direct_flow_reset(&active_flow, NULL);
	while (fgets(line, sizeof(line), file)) {
		char serial[32];
		char field[96];
		char value[NSS_ECM_STATE_LINE_MAX];

		if (!parse_nss_ecm_state_line(line, serial, sizeof(serial),
					      field, sizeof(field),
					      value, sizeof(value))) {
			stats->malformed_lines++;
			continue;
		}

		if (active_serial[0] && strcmp(active_serial, serial)) {
			stats->entries_seen++;
			add_nss_ecm_direct_flow_to_samples(samples, sample_count,
							   max_samples,
							   arp_entries, arp_count,
							   &active_flow, now_ms,
							   stats);
			nss_ecm_direct_flow_reset(&active_flow, serial);
			snprintf(active_serial, sizeof(active_serial), "%s", serial);
		} else if (!active_serial[0]) {
			nss_ecm_direct_flow_reset(&active_flow, serial);
			snprintf(active_serial, sizeof(active_serial), "%s", serial);
		}

		nss_ecm_direct_flow_apply_field(&active_flow, field, value);
		have_active = true;
	}

	if (have_active) {
		stats->entries_seen++;
		add_nss_ecm_direct_flow_to_samples(samples, sample_count,
						   max_samples, arp_entries,
						   arp_count, &active_flow,
						   now_ms, stats);
	}

	fclose(file);
	stats->current_clients = *sample_count;
	if (stats->malformed_lines)
		nss_add_warning(warnings, "nss_ecm_direct_parse_errors");
	if (stats->skipped_no_arp)
		nss_add_warning(warnings, "skip_nss_ecm_direct_flow_without_lan_identity");
	if (*sample_count == 0) {
		nss_add_warning(warnings, "nss_direct_no_data");
		return false;
	}
	return true;
}
