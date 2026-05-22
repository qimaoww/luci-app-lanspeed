/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LANSPEED_IDENTITY_H
#define LANSPEED_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

#include <json-c/json.h>

#define ARP_PROCFS_PATH "/proc/net/arp"
#define NEIGHBOR_NETLINK_SOURCE "netlink:rtnetlink_neigh"
#define IP_STR_LEN 46
#define MAC_STR_LEN 18
#define IFNAME_STR_LEN 32
#define ZONE_STR_LEN 32
#define IDENTITY_KEY_STR_LEN 80

struct arp_entry {
	char ip[IP_STR_LEN];
	char mac[MAC_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	char zone[ZONE_STR_LEN];
};

enum flow_endpoint_role {
	FLOW_ENDPOINT_ORIG_SRC,
	FLOW_ENDPOINT_ORIG_DST,
	FLOW_ENDPOINT_REPLY_SRC,
	FLOW_ENDPOINT_REPLY_DST
};

struct flow_lan_endpoint {
	const struct arp_entry *arp;
	enum flow_endpoint_role role;
	bool matched;
};

bool valid_mac_address(const char *mac);
void normalize_mac_address(char *mac);
bool normalize_ip_address(const char *ip, char *out, size_t out_size);
void derive_zone_from_ifname(const char *ifname, char *zone, size_t zone_size);
bool ifname_is_excluded_identity_source(const char *ifname);

size_t load_arp_table(struct arp_entry *entries, size_t max_entries,
		      struct json_object *warnings);
bool read_neighbor_table(struct arp_entry *entries, size_t *count,
			 size_t max_entries);
size_t load_lan_identity_table(struct arp_entry *entries, size_t max_entries,
			       struct json_object *warnings);

const struct arp_entry *find_arp_entry(const struct arp_entry *entries,
				       size_t count, const char *ip);
const struct arp_entry *find_lan_identity_by_mac(const struct arp_entry *entries,
						 size_t count, const char *mac);
bool flow_endpoint_lookup(const struct arp_entry *entries, size_t count,
			  const char *ip, enum flow_endpoint_role role,
			  struct flow_lan_endpoint *endpoint);
bool nss_ecm_direct_endpoint_lookup(const struct arp_entry *entries,
				    size_t count, const char *ip,
				    const char *nat_ip, const char *mac,
				    enum flow_endpoint_role role,
				    struct flow_lan_endpoint *endpoint);

#endif
