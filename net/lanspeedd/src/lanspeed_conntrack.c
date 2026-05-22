/* SPDX-License-Identifier: Apache-2.0 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libmnl/libmnl.h>

#include "lanspeed_conntrack.h"

static void conntrack_add_warning(struct json_object *warnings, const char *warning)
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

static bool ip_address_is_ipv6(const char *ip)
{
	return ip && strchr(ip, ':') != NULL;
}

void flow_endpoint_stats_add(bool source_side, const struct arp_entry *arp,
			     size_t *src_lan_flows, size_t *dst_lan_flows,
			     size_t *ipv4_lan_flows, size_t *ipv6_lan_flows)
{
	if (source_side)
		(*src_lan_flows)++;
	else
		(*dst_lan_flows)++;
	if (arp && ip_address_is_ipv6(arp->ip))
		(*ipv6_lan_flows)++;
	else
		(*ipv4_lan_flows)++;
}

static bool parse_conntrack_procfs_line(const char *line,
					struct conntrack_flow_sample *flow)
{
	char buffer[CONNTRACK_LINE_MAX];
	char *saveptr = NULL;
	char *token;
	int src_index = 0;
	int dst_index = 0;
	int sport_index = 0;
	int dport_index = 0;
	int bytes_index = 0;
	int token_index = 0;

	if (!line || !flow)
		return false;

	memset(flow, 0, sizeof(*flow));
	snprintf(buffer, sizeof(buffer), "%s", line);

	for (token = strtok_r(buffer, " \t\r\n", &saveptr); token;
	     token = strtok_r(NULL, " \t\r\n", &saveptr)) {
		if (token_index == 2) {
			snprintf(flow->protocol, sizeof(flow->protocol), "%s", token);
			flow->is_tcp = (strcmp(token, "tcp") == 0);
			flow->is_udp = (strcmp(token, "udp") == 0);
		}

		if (token_index == 5 && flow->is_tcp)
			snprintf(flow->tcp_state, sizeof(flow->tcp_state), "%s", token);

		if (!strncmp(token, "src=", 4)) {
			if (src_index == 0) {
				snprintf(flow->orig_src, sizeof(flow->orig_src), "%s", token + 4);
				flow->has_orig_src = true;
			} else if (src_index == 1) {
				snprintf(flow->reply_src, sizeof(flow->reply_src), "%s", token + 4);
				flow->has_reply_src = true;
			}
			src_index++;
		} else if (!strncmp(token, "dst=", 4)) {
			if (dst_index == 0) {
				snprintf(flow->orig_dst, sizeof(flow->orig_dst), "%s", token + 4);
				flow->has_orig_dst = true;
			} else if (dst_index == 1) {
				snprintf(flow->reply_dst, sizeof(flow->reply_dst), "%s", token + 4);
				flow->has_reply_dst = true;
			}
			dst_index++;
		} else if (!strncmp(token, "sport=", 6)) {
			char *end = NULL;
			unsigned long value = strtoul(token + 6, &end, 10);

			if (end != token + 6 && value <= UINT16_MAX) {
				if (sport_index == 0)
					flow->orig_sport = (uint16_t)value;
				else if (sport_index == 1)
					flow->reply_sport = (uint16_t)value;
			}
			sport_index++;
		} else if (!strncmp(token, "dport=", 6)) {
			char *end = NULL;
			unsigned long value = strtoul(token + 6, &end, 10);

			if (end != token + 6 && value <= UINT16_MAX) {
				if (dport_index == 0)
					flow->orig_dport = (uint16_t)value;
				else if (dport_index == 1)
					flow->reply_dport = (uint16_t)value;
			}
			dport_index++;
		} else if (!strncmp(token, "bytes=", 6)) {
			char *end = NULL;
			uint64_t value = strtoull(token + 6, &end, 10);

			if (end == token + 6) {
				token_index++;
				continue;
			}
			if (bytes_index == 0) {
				flow->orig_bytes = value;
				flow->has_orig_bytes = true;
			} else if (bytes_index == 1)
				flow->reply_bytes = value;
			bytes_index++;
		} else if (!strcmp(token, "[ASSURED]")) {
			flow->assured = true;
		}

		token_index++;
	}

	flow->udp_is_dns = flow->is_udp &&
		(flow->orig_sport == 53 || flow->orig_dport == 53 ||
		 flow->reply_sport == 53 || flow->reply_dport == 53);

	return flow->has_orig_src && flow->has_orig_bytes;
}

struct conntrack_client_sample *find_conntrack_client_sample(
	struct conntrack_client_sample *samples, size_t count,
	const char *identity_key)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcmp(samples[i].identity_key, identity_key))
			return &samples[i];
	}

	return NULL;
}

void add_client_ip_unique(struct conntrack_client_sample *sample, const char *ip)
{
	size_t i;

	if (!sample || !ip || !ip[0])
		return;

	for (i = 0; i < sample->ip_count; i++) {
		if (!strcmp(sample->ips[i], ip))
			return;
	}

	if (sample->ip_count >= MAX_CLIENT_IPS)
		return;

	snprintf(sample->ips[sample->ip_count], sizeof(sample->ips[sample->ip_count]), "%s", ip);
	sample->ip_count++;
}

bool add_endpoint_sample_bytes(struct conntrack_client_sample *samples,
			       size_t *sample_count, size_t max_samples,
			       const struct arp_entry *arp,
			       const char *mac_override,
			       uint64_t tx_bytes, uint64_t rx_bytes,
			       uint64_t now_ms, uint32_t protocol,
			       bool count_connections)
{
	struct conntrack_client_sample *sample;
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];

	if (!arp)
		return false;
	if (valid_mac_address(mac_override))
		snprintf(mac, sizeof(mac), "%s", mac_override);
	else
		snprintf(mac, sizeof(mac), "%s", arp->mac);
	normalize_mac_address(mac);

	snprintf(identity_key, sizeof(identity_key), "%s@%s", mac, arp->zone);
	sample = find_conntrack_client_sample(samples, *sample_count, identity_key);
	if (!sample) {
		if (*sample_count >= max_samples)
			return true;
		sample = &samples[*sample_count];
		memset(sample, 0, sizeof(*sample));
		snprintf(sample->mac, sizeof(sample->mac), "%s", mac);
		snprintf(sample->identity_key, sizeof(sample->identity_key), "%s", identity_key);
		snprintf(sample->zone, sizeof(sample->zone), "%s", arp->zone);
		snprintf(sample->ifname, sizeof(sample->ifname), "%s", arp->ifname);
		(*sample_count)++;
	}

	add_client_ip_unique(sample, arp->ip);
	sample->tx_bytes += tx_bytes;
	sample->rx_bytes += rx_bytes;
	sample->last_seen_ms = now_ms;

	if (count_connections) {
		if (protocol == 6)
			sample->tcp_conns++;
		else if (protocol == 17)
			sample->udp_conns++;
	}

	return true;
}

static void conntrack_sample_add_conn_counts(struct conntrack_client_sample *sample,
					     const struct conntrack_flow_sample *flow)
{
	if (!sample || !flow)
		return;
	if (flow->is_tcp && strcmp(flow->tcp_state, "ESTABLISHED") == 0 && flow->assured)
		sample->tcp_conns++;
	else if (flow->is_udp) {
		sample->udp_conns++;
		if (flow->udp_is_dns)
			sample->udp_dns_conns++;
		else
			sample->udp_other_conns++;
	}
}

static struct conntrack_client_sample *find_or_add_endpoint_sample(
	struct conntrack_client_sample *samples, size_t *sample_count,
	size_t max_samples, const struct arp_entry *arp)
{
	struct conntrack_client_sample *sample;
	char identity_key[IDENTITY_KEY_STR_LEN];

	if (!arp)
		return NULL;
	snprintf(identity_key, sizeof(identity_key), "%s@%s", arp->mac, arp->zone);
	sample = find_conntrack_client_sample(samples, *sample_count, identity_key);
	if (sample)
		return sample;
	if (*sample_count >= max_samples)
		return NULL;

	sample = &samples[*sample_count];
	memset(sample, 0, sizeof(*sample));
	snprintf(sample->mac, sizeof(sample->mac), "%s", arp->mac);
	snprintf(sample->identity_key, sizeof(sample->identity_key), "%s", identity_key);
	snprintf(sample->zone, sizeof(sample->zone), "%s", arp->zone);
	snprintf(sample->ifname, sizeof(sample->ifname), "%s", arp->ifname);
	(*sample_count)++;
	return sample;
}

static bool conntrack_flow_add_single_endpoint(struct conntrack_client_sample *samples,
					       size_t *sample_count,
					       size_t max_samples,
					       const struct arp_entry *arp,
					       bool original_source_side,
					       const struct conntrack_flow_sample *flow,
					       uint64_t now_ms,
					       struct conntrack_collect_stats *stats)
{
	struct conntrack_client_sample *sample;
	uint64_t tx_bytes = original_source_side ? flow->orig_bytes : flow->reply_bytes;
	uint64_t rx_bytes = original_source_side ? flow->reply_bytes : flow->orig_bytes;

	sample = find_or_add_endpoint_sample(samples, sample_count, max_samples, arp);
	if (!sample)
		return true;

	add_client_ip_unique(sample, arp->ip);
	sample->tx_bytes += tx_bytes;
	sample->rx_bytes += rx_bytes;
	sample->last_seen_ms = now_ms;
	conntrack_sample_add_conn_counts(sample, flow);

	if (stats) {
		stats->entries_matched++;
		flow_endpoint_stats_add(original_source_side, arp,
					&stats->src_lan_flows,
					&stats->dst_lan_flows,
					&stats->ipv4_lan_flows,
					&stats->ipv6_lan_flows);
	}
	return true;
}

static bool conntrack_flow_add_endpoint(struct conntrack_client_sample *samples,
					size_t *sample_count,
					size_t max_samples,
					const struct arp_entry *arp_entries,
					size_t arp_count,
					const struct conntrack_flow_sample *flow,
					uint64_t now_ms,
					struct conntrack_collect_stats *stats)
{
	struct flow_lan_endpoint orig_src;
	struct flow_lan_endpoint orig_dst;
	struct flow_lan_endpoint reply_src;
	struct flow_lan_endpoint reply_dst;
	bool has_orig_src;
	bool has_orig_dst;
	bool has_reply_src;
	bool has_reply_dst;

	has_orig_src = flow_endpoint_lookup(arp_entries, arp_count, flow->orig_src,
					    FLOW_ENDPOINT_ORIG_SRC, &orig_src);
	has_orig_dst = flow_endpoint_lookup(arp_entries, arp_count, flow->orig_dst,
					    FLOW_ENDPOINT_ORIG_DST, &orig_dst);
	has_reply_src = flow_endpoint_lookup(arp_entries, arp_count, flow->reply_src,
					     FLOW_ENDPOINT_REPLY_SRC, &reply_src);
	has_reply_dst = flow_endpoint_lookup(arp_entries, arp_count, flow->reply_dst,
					     FLOW_ENDPOINT_REPLY_DST, &reply_dst);

	if ((has_orig_src && has_orig_dst) || (has_reply_src && has_reply_dst)) {
		if (stats)
			stats->both_lan_flows++;
		return true;
	}
	if (has_orig_src)
		return conntrack_flow_add_single_endpoint(samples, sample_count, max_samples,
							  orig_src.arp, true, flow,
							  now_ms, stats);
	if (has_orig_dst)
		return conntrack_flow_add_single_endpoint(samples, sample_count, max_samples,
							  orig_dst.arp, false, flow,
							  now_ms, stats);
	if (has_reply_src)
		return conntrack_flow_add_single_endpoint(samples, sample_count, max_samples,
							  reply_src.arp, false, flow,
							  now_ms, stats);
	if (has_reply_dst)
		return conntrack_flow_add_single_endpoint(samples, sample_count, max_samples,
							  reply_dst.arp, true, flow,
							  now_ms, stats);

	if (stats) {
		stats->skipped_no_arp++;
		stats->no_lan_flows++;
	}
	return true;
}

static bool add_conntrack_flow_to_samples(struct conntrack_client_sample *samples,
					  size_t *sample_count, size_t max_samples,
					  const struct arp_entry *arp_entries, size_t arp_count,
					  const struct conntrack_flow_sample *flow,
					  uint64_t now_ms, struct conntrack_collect_stats *stats)
{
	if (!flow || !flow->has_orig_src || !flow->has_orig_bytes)
		return false;

	return conntrack_flow_add_endpoint(samples, sample_count, max_samples,
					   arp_entries, arp_count, flow,
					   now_ms, stats);
}

static bool open_conntrack_procfs(FILE **file, char *source_path, size_t source_path_size)
{
	*file = fopen(CONNTRACK_PROCFS_PATH, "r");
	if (*file) {
		snprintf(source_path, source_path_size, "%s", CONNTRACK_PROCFS_PATH);
		return true;
	}

	*file = fopen(CONNTRACK_LEGACY_PROCFS_PATH, "r");
	if (*file) {
		snprintf(source_path, source_path_size, "%s", CONNTRACK_LEGACY_PROCFS_PATH);
		return true;
	}

	return false;
}

static uint64_t be64_to_host(uint64_t value)
{
	const uint8_t *p = (const uint8_t *)&value;

	return ((uint64_t)p[0] << 56) |
	       ((uint64_t)p[1] << 48) |
	       ((uint64_t)p[2] << 40) |
	       ((uint64_t)p[3] << 32) |
	       ((uint64_t)p[4] << 24) |
	       ((uint64_t)p[5] << 16) |
	       ((uint64_t)p[6] << 8) |
	       (uint64_t)p[7];
}

struct conntrack_attr_table {
	struct nlattr **tb;
	uint16_t max;
};

static int conntrack_store_attr_cb(const struct nlattr *attr, void *data)
{
	struct conntrack_attr_table *table = data;
	uint16_t type = mnl_attr_get_type(attr);

	type &= NLA_TYPE_MASK;
	if (type <= table->max)
		table->tb[type] = (struct nlattr *)attr;
	return MNL_CB_OK;
}

static bool conntrack_netlink_parse_tuple(const struct nlattr *attr,
					  struct conntrack_flow_sample *flow,
					  bool original)
{
	struct nlattr *tuple[CTA_TUPLE_MAX + 1];
	struct nlattr *ip[CTA_IP_MAX + 1];
	struct nlattr *proto[CTA_PROTO_MAX + 1];
	struct conntrack_attr_table tuple_table = { tuple, CTA_TUPLE_MAX };
	struct conntrack_attr_table ip_table = { ip, CTA_IP_MAX };
	struct conntrack_attr_table proto_table = { proto, CTA_PROTO_MAX };
	uint8_t proto_num;

	memset(tuple, 0, sizeof(tuple));
	memset(ip, 0, sizeof(ip));
	memset(proto, 0, sizeof(proto));
	if (mnl_attr_parse_nested(attr, conntrack_store_attr_cb, &tuple_table) < 0)
		return false;
	if (!tuple[CTA_TUPLE_IP] || !tuple[CTA_TUPLE_PROTO])
		return false;
	if (mnl_attr_parse_nested(tuple[CTA_TUPLE_IP], conntrack_store_attr_cb, &ip_table) < 0)
		return false;
	if (mnl_attr_parse_nested(tuple[CTA_TUPLE_PROTO], conntrack_store_attr_cb, &proto_table) < 0)
		return false;

	if (original) {
		if (ip[CTA_IP_V4_SRC]) {
			struct in_addr addr;
			memcpy(&addr, mnl_attr_get_payload(ip[CTA_IP_V4_SRC]), sizeof(addr));
			if (!inet_ntop(AF_INET, &addr, flow->orig_src, sizeof(flow->orig_src)))
				return false;
			flow->has_orig_src = true;
		} else if (ip[CTA_IP_V6_SRC]) {
			struct in6_addr addr6;
			memcpy(&addr6, mnl_attr_get_payload(ip[CTA_IP_V6_SRC]), sizeof(addr6));
			if (!inet_ntop(AF_INET6, &addr6, flow->orig_src, sizeof(flow->orig_src)))
				return false;
			flow->has_orig_src = true;
		}
		if (ip[CTA_IP_V4_DST]) {
			struct in_addr addr;
			memcpy(&addr, mnl_attr_get_payload(ip[CTA_IP_V4_DST]), sizeof(addr));
			if (!inet_ntop(AF_INET, &addr, flow->orig_dst, sizeof(flow->orig_dst)))
				return false;
			flow->has_orig_dst = true;
		} else if (ip[CTA_IP_V6_DST]) {
			struct in6_addr addr6;
			memcpy(&addr6, mnl_attr_get_payload(ip[CTA_IP_V6_DST]), sizeof(addr6));
			if (!inet_ntop(AF_INET6, &addr6, flow->orig_dst, sizeof(flow->orig_dst)))
				return false;
			flow->has_orig_dst = true;
		}
	} else {
		if (ip[CTA_IP_V4_SRC]) {
			struct in_addr addr;
			memcpy(&addr, mnl_attr_get_payload(ip[CTA_IP_V4_SRC]), sizeof(addr));
			if (!inet_ntop(AF_INET, &addr, flow->reply_src, sizeof(flow->reply_src)))
				return false;
			flow->has_reply_src = true;
		} else if (ip[CTA_IP_V6_SRC]) {
			struct in6_addr addr6;
			memcpy(&addr6, mnl_attr_get_payload(ip[CTA_IP_V6_SRC]), sizeof(addr6));
			if (!inet_ntop(AF_INET6, &addr6, flow->reply_src, sizeof(flow->reply_src)))
				return false;
			flow->has_reply_src = true;
		}
		if (ip[CTA_IP_V4_DST]) {
			struct in_addr addr;
			memcpy(&addr, mnl_attr_get_payload(ip[CTA_IP_V4_DST]), sizeof(addr));
			if (!inet_ntop(AF_INET, &addr, flow->reply_dst, sizeof(flow->reply_dst)))
				return false;
			flow->has_reply_dst = true;
		} else if (ip[CTA_IP_V6_DST]) {
			struct in6_addr addr6;
			memcpy(&addr6, mnl_attr_get_payload(ip[CTA_IP_V6_DST]), sizeof(addr6));
			if (!inet_ntop(AF_INET6, &addr6, flow->reply_dst, sizeof(flow->reply_dst)))
				return false;
			flow->has_reply_dst = true;
		}
	}

	if (proto[CTA_PROTO_NUM]) {
		proto_num = mnl_attr_get_u8(proto[CTA_PROTO_NUM]);
		if (proto_num == IPPROTO_TCP) {
			snprintf(flow->protocol, sizeof(flow->protocol), "tcp");
			flow->is_tcp = true;
		} else if (proto_num == IPPROTO_UDP) {
			snprintf(flow->protocol, sizeof(flow->protocol), "udp");
			flow->is_udp = true;
		} else {
			snprintf(flow->protocol, sizeof(flow->protocol), "%u", proto_num);
		}
	}

	if (proto[CTA_PROTO_SRC_PORT]) {
		uint16_t port = ntohs(mnl_attr_get_u16(proto[CTA_PROTO_SRC_PORT]));
		if (original)
			flow->orig_sport = port;
		else
			flow->reply_sport = port;
	}
	if (proto[CTA_PROTO_DST_PORT]) {
		uint16_t port = ntohs(mnl_attr_get_u16(proto[CTA_PROTO_DST_PORT]));
		if (original)
			flow->orig_dport = port;
		else
			flow->reply_dport = port;
	}

	return true;
}

static bool conntrack_netlink_parse_counters(const struct nlattr *attr,
					     uint64_t *bytes)
{
	struct nlattr *counters[CTA_COUNTERS_MAX + 1];
	struct conntrack_attr_table counters_table = { counters, CTA_COUNTERS_MAX };

	memset(counters, 0, sizeof(counters));
	if (mnl_attr_parse_nested(attr, conntrack_store_attr_cb, &counters_table) < 0)
		return false;
	if (counters[CTA_COUNTERS_BYTES]) {
		*bytes = be64_to_host(mnl_attr_get_u64(counters[CTA_COUNTERS_BYTES]));
		return true;
	}
	if (counters[CTA_COUNTERS32_BYTES]) {
		*bytes = ntohl(mnl_attr_get_u32(counters[CTA_COUNTERS32_BYTES]));
		return true;
	}
	return false;
}

static void conntrack_tcp_state_name(uint8_t state, char *buffer, size_t size)
{
	const char *name = "";

	switch (state) {
	case TCP_CONNTRACK_ESTABLISHED:
		name = "ESTABLISHED";
		break;
	case TCP_CONNTRACK_SYN_SENT:
		name = "SYN_SENT";
		break;
	case TCP_CONNTRACK_SYN_RECV:
		name = "SYN_RECV";
		break;
	case TCP_CONNTRACK_FIN_WAIT:
		name = "FIN_WAIT";
		break;
	case TCP_CONNTRACK_CLOSE_WAIT:
		name = "CLOSE_WAIT";
		break;
	case TCP_CONNTRACK_LAST_ACK:
		name = "LAST_ACK";
		break;
	case TCP_CONNTRACK_TIME_WAIT:
		name = "TIME_WAIT";
		break;
	case TCP_CONNTRACK_CLOSE:
		name = "CLOSE";
		break;
	default:
		name = "";
		break;
	}

	snprintf(buffer, size, "%s", name);
}

static bool conntrack_netlink_parse_protoinfo(const struct nlattr *attr,
					      struct conntrack_flow_sample *flow)
{
	struct nlattr *protoinfo[CTA_PROTOINFO_MAX + 1];
	struct nlattr *tcp[CTA_PROTOINFO_TCP_MAX + 1];
	struct conntrack_attr_table protoinfo_table = { protoinfo, CTA_PROTOINFO_MAX };
	struct conntrack_attr_table tcp_table = { tcp, CTA_PROTOINFO_TCP_MAX };

	memset(protoinfo, 0, sizeof(protoinfo));
	memset(tcp, 0, sizeof(tcp));
	if (mnl_attr_parse_nested(attr, conntrack_store_attr_cb, &protoinfo_table) < 0)
		return false;
	if (!protoinfo[CTA_PROTOINFO_TCP])
		return true;
	if (mnl_attr_parse_nested(protoinfo[CTA_PROTOINFO_TCP], conntrack_store_attr_cb, &tcp_table) < 0)
		return false;
	if (tcp[CTA_PROTOINFO_TCP_STATE])
		conntrack_tcp_state_name(mnl_attr_get_u8(tcp[CTA_PROTOINFO_TCP_STATE]),
					 flow->tcp_state, sizeof(flow->tcp_state));
	return true;
}

struct conntrack_netlink_dump_ctx {
	struct conntrack_client_sample *samples;
	size_t *sample_count;
	size_t max_samples;
	const struct arp_entry *arp_entries;
	size_t arp_count;
	uint64_t now_ms;
	struct conntrack_collect_stats *stats;
};

static int conntrack_netlink_data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct conntrack_netlink_dump_ctx *ctx = data;
	struct nlattr *tb[CTA_MAX + 1];
	struct conntrack_attr_table tb_table = { tb, CTA_MAX };
	struct conntrack_flow_sample flow;

	memset(tb, 0, sizeof(tb));
	memset(&flow, 0, sizeof(flow));
	if (mnl_attr_parse(nlh, sizeof(struct nfgenmsg), conntrack_store_attr_cb, &tb_table) < 0) {
		ctx->stats->malformed_lines++;
		return MNL_CB_OK;
	}

	ctx->stats->entries_seen++;
	if (!tb[CTA_TUPLE_ORIG] || !tb[CTA_COUNTERS_ORIG]) {
		ctx->stats->malformed_lines++;
		return MNL_CB_OK;
	}

	if (!conntrack_netlink_parse_tuple(tb[CTA_TUPLE_ORIG], &flow, true)) {
		ctx->stats->malformed_lines++;
		return MNL_CB_OK;
	}
	if (tb[CTA_TUPLE_REPLY])
		conntrack_netlink_parse_tuple(tb[CTA_TUPLE_REPLY], &flow, false);
	if (!conntrack_netlink_parse_counters(tb[CTA_COUNTERS_ORIG], &flow.orig_bytes)) {
		ctx->stats->malformed_lines++;
		return MNL_CB_OK;
	}
	flow.has_orig_bytes = true;
	if (tb[CTA_COUNTERS_REPLY])
		conntrack_netlink_parse_counters(tb[CTA_COUNTERS_REPLY], &flow.reply_bytes);
	if (tb[CTA_STATUS])
		flow.assured = (ntohl(mnl_attr_get_u32(tb[CTA_STATUS])) & IPS_ASSURED) != 0;
	if (tb[CTA_PROTOINFO])
		conntrack_netlink_parse_protoinfo(tb[CTA_PROTOINFO], &flow);
	if (flow.is_tcp && flow.tcp_state[0] == '\0')
		conntrack_tcp_state_name(TCP_CONNTRACK_ESTABLISHED,
					 flow.tcp_state, sizeof(flow.tcp_state));
	flow.udp_is_dns = flow.is_udp &&
		(flow.orig_sport == 53 || flow.orig_dport == 53 ||
		 flow.reply_sport == 53 || flow.reply_dport == 53);

	add_conntrack_flow_to_samples(ctx->samples, ctx->sample_count,
				      ctx->max_samples, ctx->arp_entries,
				      ctx->arp_count, &flow, ctx->now_ms,
				      ctx->stats);
	return MNL_CB_OK;
}

static bool read_conntrack_netlink_snapshot(struct conntrack_client_sample *samples,
					    size_t *sample_count, size_t max_samples,
					    uint64_t now_ms, struct json_object *warnings,
					    struct conntrack_collect_stats *stats)
{
	char sndbuf[MNL_SOCKET_BUFFER_SIZE];
	char rcvbuf[MNL_SOCKET_DUMP_SIZE];
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	struct conntrack_netlink_dump_ctx dump_ctx;
	unsigned int seq = (unsigned int)time(NULL);
	unsigned int portid;
	ssize_t ret;
	int cb_ret = MNL_CB_OK;
	size_t arp_count;

	*sample_count = 0;
	memset(stats, 0, sizeof(*stats));
	stats->netlink_attempted = true;
	snprintf(stats->source_path, sizeof(stats->source_path), "%s",
		 CONNTRACK_NETLINK_SOURCE_PATH);

	arp_count = load_lan_identity_table(arp_entries, DEFAULT_MAX_CLIENTS, warnings);
	if (arp_count == 0)
		return false;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!nl) {
		stats->netlink_errno = errno;
		return false;
	}
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		stats->netlink_errno = errno;
		mnl_socket_close(nl);
		return false;
	}
	portid = mnl_socket_get_portid(nl);

	memset(sndbuf, 0, sizeof(sndbuf));
	nlh = mnl_nlmsg_put_header(sndbuf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		stats->netlink_errno = errno;
		mnl_socket_close(nl);
		return false;
	}

	memset(&dump_ctx, 0, sizeof(dump_ctx));
	dump_ctx.samples = samples;
	dump_ctx.sample_count = sample_count;
	dump_ctx.max_samples = max_samples;
	dump_ctx.arp_entries = arp_entries;
	dump_ctx.arp_count = arp_count;
	dump_ctx.now_ms = now_ms;
	dump_ctx.stats = stats;

	while ((ret = mnl_socket_recvfrom(nl, rcvbuf, sizeof(rcvbuf))) > 0) {
		cb_ret = mnl_cb_run(rcvbuf, (size_t)ret, seq, portid,
				    conntrack_netlink_data_cb, &dump_ctx);
		if (cb_ret <= MNL_CB_STOP)
			break;
	}
	if (ret < 0) {
		stats->netlink_errno = errno;
		mnl_socket_close(nl);
		return false;
	}
	if (cb_ret < 0) {
		stats->netlink_errno = errno;
		mnl_socket_close(nl);
		return false;
	}

	mnl_socket_close(nl);
	stats->netlink_read = true;
	stats->current_clients = *sample_count;
	return true;
}

static bool read_conntrack_procfs_snapshot(struct conntrack_client_sample *samples,
					   size_t *sample_count, size_t max_samples,
					   uint64_t now_ms, struct json_object *warnings,
					   struct conntrack_collect_stats *stats)
{
	struct arp_entry arp_entries[DEFAULT_MAX_CLIENTS];
	size_t arp_count;
	FILE *file = NULL;
	char line[CONNTRACK_LINE_MAX];

	*sample_count = 0;
	memset(stats, 0, sizeof(*stats));
	arp_count = load_lan_identity_table(arp_entries, DEFAULT_MAX_CLIENTS, warnings);
	if (arp_count == 0)
		return false;

	if (!open_conntrack_procfs(&file, stats->source_path, sizeof(stats->source_path))) {
		conntrack_add_warning(warnings, "conntrack_unavailable");
		return false;
	}

	stats->procfs_read = true;
	while (fgets(line, sizeof(line), file)) {
		struct conntrack_flow_sample flow;

		stats->entries_seen++;

		if (!parse_conntrack_procfs_line(line, &flow)) {
			stats->malformed_lines++;
			continue;
		}

		add_conntrack_flow_to_samples(samples, sample_count, max_samples,
					      arp_entries, arp_count, &flow, now_ms, stats);
	}

	fclose(file);
	stats->current_clients = *sample_count;
	return true;
}

bool read_conntrack_snapshot(struct conntrack_client_sample *samples,
			     size_t *sample_count, size_t max_samples,
			     uint64_t now_ms, struct json_object *warnings,
			     struct conntrack_collect_stats *stats)
{
	return read_conntrack_snapshot_mode(samples, sample_count, max_samples,
					    now_ms, warnings, stats, COLLECTOR_MODE_AUTO);
}

bool read_conntrack_snapshot_mode(struct conntrack_client_sample *samples,
				  size_t *sample_count, size_t max_samples,
				  uint64_t now_ms, struct json_object *warnings,
				  struct conntrack_collect_stats *stats,
				  enum collector_mode_setting mode)
{
	struct conntrack_collect_stats netlink_stats;
	struct conntrack_collect_stats procfs_stats;

	if (mode == COLLECTOR_MODE_CONNTRACK_PROCFS) {
		if (read_conntrack_procfs_snapshot(samples, sample_count, max_samples,
						   now_ms, warnings, &procfs_stats)) {
			*stats = procfs_stats;
			return true;
		}
		*stats = procfs_stats;
		return false;
	}

	if (read_conntrack_netlink_snapshot(samples, sample_count, max_samples,
					    now_ms, warnings, &netlink_stats)) {
		*stats = netlink_stats;
		return true;
	}

	if (mode == COLLECTOR_MODE_CONNTRACK_NETLINK) {
		*stats = netlink_stats;
		return false;
	}

	if (read_conntrack_procfs_snapshot(samples, sample_count, max_samples,
					   now_ms, warnings, &procfs_stats)) {
		procfs_stats.netlink_attempted = netlink_stats.netlink_attempted;
		procfs_stats.netlink_errno = netlink_stats.netlink_errno;
		*stats = procfs_stats;
		return true;
	}

	*stats = netlink_stats.netlink_attempted ? netlink_stats : procfs_stats;
	return false;
}
