/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_CONNTRACK_H
#define LANSPEED_CONNTRACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <json-c/json.h>

#include "lanspeed_config.h"
#include "lanspeed_identity.h"

#define CONNTRACK_NETLINK_SOURCE_PATH "netlink:ctnetlink"
#define CONNTRACK_LEGACY_SOURCE "conntrack"
#define CONNTRACK_PROCFS_PATH "/proc/net/nf_conntrack"
#define CONNTRACK_LEGACY_PROCFS_PATH "/proc/net/ip_conntrack"
#define CONNTRACK_LINE_MAX 1024
#define MAX_CLIENT_IPS 4

struct conntrack_client_sample {
	char mac[MAC_STR_LEN];
	char identity_key[IDENTITY_KEY_STR_LEN];
	char zone[ZONE_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char ips[MAX_CLIENT_IPS][IP_STR_LEN];
	size_t ip_count;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t last_seen_ms;
	uint32_t tcp_conns;
	uint32_t udp_conns;
	uint32_t udp_dns_conns;
	uint32_t udp_other_conns;
};

struct conntrack_flow_sample {
	char orig_src[IP_STR_LEN];
	char orig_dst[IP_STR_LEN];
	char reply_src[IP_STR_LEN];
	char reply_dst[IP_STR_LEN];
	uint64_t orig_bytes;
	uint64_t reply_bytes;
	uint16_t orig_sport;
	uint16_t orig_dport;
	uint16_t reply_sport;
	uint16_t reply_dport;
	bool has_orig_src;
	bool has_orig_dst;
	bool has_reply_src;
	bool has_reply_dst;
	bool has_orig_bytes;
	char protocol[8];
	char tcp_state[16];
	bool assured;
	bool is_tcp;
	bool is_udp;
	bool udp_is_dns;
};

struct conntrack_collect_stats {
	char source_path[PATH_MAX];
	bool netlink_attempted;
	bool netlink_read;
	bool procfs_read;
	bool snapshot_pending;
	int netlink_errno;
	size_t current_clients;
	size_t emitted_clients;
	size_t skipped_no_arp;
	size_t no_lan_flows;
	size_t both_lan_flows;
	size_t src_lan_flows;
	size_t dst_lan_flows;
	size_t ipv4_lan_flows;
	size_t ipv6_lan_flows;
	size_t malformed_lines;
	size_t entries_seen;
	size_t entries_matched;
};

struct conntrack_client_sample *find_conntrack_client_sample(
	struct conntrack_client_sample *samples, size_t count,
	const char *identity_key);
void add_client_ip_unique(struct conntrack_client_sample *sample, const char *ip);
void flow_endpoint_stats_add(bool source_side, const struct arp_entry *arp,
			     size_t *src_lan_flows, size_t *dst_lan_flows,
			     size_t *ipv4_lan_flows, size_t *ipv6_lan_flows);
bool add_endpoint_sample_bytes(struct conntrack_client_sample *samples,
			       size_t *sample_count, size_t max_samples,
			       const struct arp_entry *arp,
			       const char *mac_override,
			       uint64_t tx_bytes, uint64_t rx_bytes,
			       uint64_t now_ms, uint32_t protocol,
			       bool count_connections);
bool read_conntrack_snapshot(struct conntrack_client_sample *samples,
			     size_t *sample_count, size_t max_samples,
			     uint64_t now_ms, struct json_object *warnings,
			     struct conntrack_collect_stats *stats);
bool read_conntrack_snapshot_mode(struct conntrack_client_sample *samples,
				  size_t *sample_count, size_t max_samples,
				  uint64_t now_ms, struct json_object *warnings,
				  struct conntrack_collect_stats *stats,
				  enum collector_mode_setting mode);

#endif
