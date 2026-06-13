/* SPDX-License-Identifier: Apache-2.0 */
#include <arpa/inet.h>
#include <ctype.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <uci.h>

#include "lanspeed_identity.h"

#define LANSPEED_IDENTITY_FILTER_IFACE_MAX 32
#define LANSPEED_IDENTITY_FILTER_PREFIX_MAX 64

struct lan_identity_prefix {
	char ifname[IFNAME_STR_LEN];
	int family;
	unsigned int prefix_len;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;
};

struct lan_identity_filter {
	bool enabled;
	char ifnames[LANSPEED_IDENTITY_FILTER_IFACE_MAX][IFNAME_STR_LEN];
	size_t ifname_count;
	struct lan_identity_prefix prefixes[LANSPEED_IDENTITY_FILTER_PREFIX_MAX];
	size_t prefix_count;
};

struct address_attr_table {
	struct nlattr **tb;
	uint16_t max;
};

struct addr_dump_ctx {
	struct lan_identity_filter *filter;
};

static void identity_add_warning(struct json_object *warnings, const char *warning)
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

bool ifname_is_excluded_identity_source(const char *ifname)
{
	if (!ifname || !ifname[0])
		return false;

	return !strcmp(ifname, "dae0") || !strcmp(ifname, "dae0peer") ||
	       !strncmp(ifname, "tun", 3) || !strncmp(ifname, "ppp", 3) ||
	       !strncmp(ifname, "wg", 2);
}

bool valid_mac_address(const char *mac)
{
	bool any_non_zero = false;
	bool any_not_ff = false;
	char first_octet[3];
	unsigned long mac_first_octet;
	size_t i;

	if (!mac || strlen(mac) != 17)
		return false;
	if (!isxdigit((unsigned char)mac[0]) ||
	    !isxdigit((unsigned char)mac[1]))
		return false;

	first_octet[0] = mac[0];
	first_octet[1] = mac[1];
	first_octet[2] = '\0';
	mac_first_octet = strtoul(first_octet, NULL, 16);
	if ((mac_first_octet & 0x01) != 0)
		return false;

	for (i = 0; i < 17; i++) {
		if ((i + 1) % 3 == 0) {
			if (mac[i] != ':')
				return false;
			continue;
		}

		if (!isxdigit((unsigned char)mac[i]))
			return false;
		if (mac[i] != '0')
			any_non_zero = true;
		if (tolower((unsigned char)mac[i]) != 'f')
			any_not_ff = true;
	}

	return any_non_zero && any_not_ff;
}

void normalize_mac_address(char *mac)
{
	size_t i;

	for (i = 0; mac && mac[i]; i++)
		mac[i] = (char)tolower((unsigned char)mac[i]);
}

bool normalize_ip_address(const char *ip, char *out, size_t out_size)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (!ip || !out || !out_size)
		return false;
	if (inet_pton(AF_INET, ip, &addr4) == 1)
		return inet_ntop(AF_INET, &addr4, out, out_size) != NULL;
	if (inet_pton(AF_INET6, ip, &addr6) == 1)
		return inet_ntop(AF_INET6, &addr6, out, out_size) != NULL;

	snprintf(out, out_size, "%s", ip);
	return out[0] != '\0';
}

void derive_zone_from_ifname(const char *ifname, char *zone, size_t zone_size)
{
	if (!zone || !zone_size)
		return;

	if (ifname && (!strncmp(ifname, "br-lan", 6) || !strncmp(ifname, "lan", 3) ||
	    !strncmp(ifname, "wlan", 4)))
		snprintf(zone, zone_size, "lan");
	else if (ifname && ifname[0])
		snprintf(zone, zone_size, "%s", ifname);
	else
		snprintf(zone, zone_size, "lan");
}

static bool lan_identity_filter_has_ifname(const struct lan_identity_filter *filter,
					   const char *ifname)
{
	size_t i;

	if (!filter || !ifname || !ifname[0])
		return false;

	for (i = 0; i < filter->ifname_count; i++) {
		if (!strcmp(filter->ifnames[i], ifname))
			return true;
	}

	return false;
}

static void lan_identity_filter_add_ifname(struct lan_identity_filter *filter,
					   const char *ifname)
{
	size_t len;

	if (!filter || !ifname || !ifname[0])
		return;
	if (ifname_is_excluded_identity_source(ifname))
		return;
	if (lan_identity_filter_has_ifname(filter, ifname))
		return;
	if (filter->ifname_count >= LANSPEED_IDENTITY_FILTER_IFACE_MAX)
		return;

	len = strlen(ifname);
	if (len >= IFNAME_STR_LEN)
		return;

	snprintf(filter->ifnames[filter->ifname_count],
		 sizeof(filter->ifnames[0]), "%s", ifname);
	filter->ifname_count++;
}

static void lan_identity_filter_add_ifname_words(struct lan_identity_filter *filter,
						 const char *value)
{
	char buffer[256];
	char *saveptr = NULL;
	char *token;

	if (!value)
		return;

	snprintf(buffer, sizeof(buffer), "%s", value);
	for (token = strtok_r(buffer, " \t\r\n,", &saveptr); token;
	     token = strtok_r(NULL, " \t\r\n,", &saveptr))
		lan_identity_filter_add_ifname(filter, token);
}

static void load_lan_identity_filter_option(struct uci_context *uci,
					    struct lan_identity_filter *filter,
					    char *path)
{
	struct uci_ptr ptr;
	struct uci_element *e;

	if (!uci || !filter || !path)
		return;

	if (uci_lookup_ptr(uci, &ptr, path, true) || !ptr.o)
		return;

	if (ptr.o->type == UCI_TYPE_LIST) {
		uci_foreach_element(&ptr.o->v.list, e) {
			lan_identity_filter_add_ifname(filter, e->name);
		}
	} else if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
		lan_identity_filter_add_ifname_words(filter, ptr.o->v.string);
	}
}

static void lan_identity_filter_add_prefix(struct lan_identity_filter *filter,
					   const char *ifname, int family,
					   unsigned int prefix_len,
					   const void *addr)
{
	struct lan_identity_prefix *prefix;

	if (!filter || !ifname || !addr)
		return;
	if (!lan_identity_filter_has_ifname(filter, ifname))
		return;
	if (filter->prefix_count >= LANSPEED_IDENTITY_FILTER_PREFIX_MAX)
		return;
	if (family == AF_INET && prefix_len > 32)
		return;
	if (family == AF_INET6 && prefix_len > 128)
		return;
	if (family != AF_INET && family != AF_INET6)
		return;

	prefix = &filter->prefixes[filter->prefix_count];
	memset(prefix, 0, sizeof(*prefix));
	snprintf(prefix->ifname, sizeof(prefix->ifname), "%s", ifname);
	prefix->family = family;
	prefix->prefix_len = prefix_len;
	if (family == AF_INET)
		memcpy(&prefix->addr.v4, addr, sizeof(prefix->addr.v4));
	else
		memcpy(&prefix->addr.v6, addr, sizeof(prefix->addr.v6));
	filter->prefix_count++;
}

static int address_attr_cb(const struct nlattr *attr, void *data)
{
	struct address_attr_table *table = data;
	uint16_t type = mnl_attr_get_type(attr);

	type &= NLA_TYPE_MASK;
	if (type <= table->max)
		table->tb[type] = (struct nlattr *)attr;
	return MNL_CB_OK;
}

static int address_netlink_data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct addr_dump_ctx *ctx = data;
	struct nlattr *tb[IFA_MAX + 1];
	struct address_attr_table table = { tb, IFA_MAX };
	struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct nlattr *addr_attr;
	char ifname[IFNAME_STR_LEN];
	size_t expected_len;
	const void *addr;

	if (nlh->nlmsg_type != RTM_NEWADDR)
		return MNL_CB_OK;
	if (!ctx || !ctx->filter || !ifa || ifa->ifa_index == 0)
		return MNL_CB_OK;
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return MNL_CB_OK;
	if (!if_indextoname((unsigned int)ifa->ifa_index, ifname))
		return MNL_CB_OK;
	if (!lan_identity_filter_has_ifname(ctx->filter, ifname))
		return MNL_CB_OK;

	memset(tb, 0, sizeof(tb));
	if (mnl_attr_parse(nlh, sizeof(*ifa), address_attr_cb, &table) < 0)
		return MNL_CB_OK;

	addr_attr = tb[IFA_LOCAL] ? tb[IFA_LOCAL] : tb[IFA_ADDRESS];
	if (!addr_attr)
		return MNL_CB_OK;

	expected_len = ifa->ifa_family == AF_INET ?
		sizeof(struct in_addr) : sizeof(struct in6_addr);
	if (mnl_attr_get_payload_len(addr_attr) < expected_len)
		return MNL_CB_OK;

	addr = mnl_attr_get_payload(addr_attr);
	lan_identity_filter_add_prefix(ctx->filter, ifname, ifa->ifa_family,
				       ifa->ifa_prefixlen, addr);
	return MNL_CB_OK;
}

static bool read_selected_interface_prefixes(struct lan_identity_filter *filter)
{
	char sndbuf[MNL_SOCKET_BUFFER_SIZE];
	char rcvbuf[MNL_SOCKET_DUMP_SIZE];
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	struct addr_dump_ctx dump_ctx;
	unsigned int seq = (unsigned int)time(NULL);
	unsigned int portid;
	ssize_t ret;
	int cb_ret = MNL_CB_OK;

	if (!filter || filter->ifname_count == 0)
		return false;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl)
		return false;
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(nl);
		return false;
	}
	portid = mnl_socket_get_portid(nl);

	memset(sndbuf, 0, sizeof(sndbuf));
	nlh = mnl_nlmsg_put_header(sndbuf);
	nlh->nlmsg_type = RTM_GETADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
	memset(ifa, 0, sizeof(*ifa));
	ifa->ifa_family = AF_UNSPEC;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		mnl_socket_close(nl);
		return false;
	}

	memset(&dump_ctx, 0, sizeof(dump_ctx));
	dump_ctx.filter = filter;

	while ((ret = mnl_socket_recvfrom(nl, rcvbuf, sizeof(rcvbuf))) > 0) {
		cb_ret = mnl_cb_run(rcvbuf, (size_t)ret, seq, portid,
				    address_netlink_data_cb, &dump_ctx);
		if (cb_ret <= MNL_CB_STOP)
			break;
	}

	mnl_socket_close(nl);
	return ret >= 0 && cb_ret >= 0 && filter->prefix_count > 0;
}

static void load_lan_identity_filter(struct lan_identity_filter *filter)
{
	struct uci_context *uci;
	char ifname_path[] = "lanspeed.main.ifname";
	char include_path[] = "lanspeed.main.interface_include";

	if (!filter)
		return;

	memset(filter, 0, sizeof(*filter));
	uci = uci_alloc_context();
	if (!uci)
		return;

	load_lan_identity_filter_option(uci, filter, ifname_path);
	load_lan_identity_filter_option(uci, filter, include_path);
	uci_free_context(uci);

	if (read_selected_interface_prefixes(filter))
		filter->enabled = true;
}

static bool ipv4_prefix_match(const struct in_addr *ip,
			      const struct lan_identity_prefix *prefix)
{
	uint32_t ip_value;
	uint32_t prefix_value;
	uint32_t mask;

	if (!ip || !prefix || prefix->family != AF_INET || prefix->prefix_len > 32)
		return false;

	ip_value = ntohl(ip->s_addr);
	prefix_value = ntohl(prefix->addr.v4.s_addr);
	mask = prefix->prefix_len == 0 ? 0 :
		(UINT32_MAX << (32 - prefix->prefix_len));

	return (ip_value & mask) == (prefix_value & mask);
}

static bool ipv6_prefix_match(const struct in6_addr *ip,
			      const struct lan_identity_prefix *prefix)
{
	unsigned int full_bytes;
	unsigned int remain_bits;
	uint8_t mask;

	if (!ip || !prefix || prefix->family != AF_INET6 || prefix->prefix_len > 128)
		return false;

	full_bytes = prefix->prefix_len / 8;
	remain_bits = prefix->prefix_len % 8;
	if (full_bytes > 0 &&
	    memcmp(ip->s6_addr, prefix->addr.v6.s6_addr, full_bytes))
		return false;
	if (remain_bits == 0)
		return true;

	mask = (uint8_t)(0xffU << (8 - remain_bits));
	return (ip->s6_addr[full_bytes] & mask) ==
	       (prefix->addr.v6.s6_addr[full_bytes] & mask);
}

static bool identity_entry_allowed_by_collected_interface(
	const struct arp_entry *entry, const struct lan_identity_filter *filter)
{
	struct in_addr addr4;
	struct in6_addr addr6;
	size_t i;
	int family;

	if (!filter || !filter->enabled)
		return true;
	if (!entry || !lan_identity_filter_has_ifname(filter, entry->ifname))
		return false;

	if (inet_pton(AF_INET, entry->ip, &addr4) == 1)
		family = AF_INET;
	else if (inet_pton(AF_INET6, entry->ip, &addr6) == 1)
		family = AF_INET6;
	else
		return false;

	for (i = 0; i < filter->prefix_count; i++) {
		const struct lan_identity_prefix *prefix = &filter->prefixes[i];

		if (strcmp(prefix->ifname, entry->ifname) || prefix->family != family)
			continue;
		if (family == AF_INET && ipv4_prefix_match(&addr4, prefix))
			return true;
		if (family == AF_INET6 && ipv6_prefix_match(&addr6, prefix))
			return true;
	}

	return false;
}

static size_t load_arp_table_filtered(struct arp_entry *entries, size_t max_entries,
				      struct json_object *warnings,
				      const struct lan_identity_filter *filter)
{
	FILE *file;
	char line[256];
	size_t count = 0;

	file = fopen(ARP_PROCFS_PATH, "r");
	if (!file) {
		identity_add_warning(warnings, "conntrack_unavailable");
		return 0;
	}

	if (!fgets(line, sizeof(line), file)) {
		fclose(file);
		identity_add_warning(warnings, "conntrack_unavailable");
		return 0;
	}

	while (count < max_entries && fgets(line, sizeof(line), file)) {
		char ip[IP_STR_LEN];
		char hw_type[16];
		char flags[16];
		char mac[MAC_STR_LEN];
		char mask[32];
		char ifname[IFNAME_STR_LEN];
		unsigned long flag_value;
		struct arp_entry entry;

		if (sscanf(line, "%45s %15s %15s %17s %31s %31s",
		           ip, hw_type, flags, mac, mask, ifname) != 6)
			continue;

		flag_value = strtoul(flags, NULL, 0);
		if (flag_value == 0 || !valid_mac_address(mac))
			continue;
		if (ifname_is_excluded_identity_source(ifname))
			continue;

		normalize_mac_address(mac);
		memset(&entry, 0, sizeof(entry));
		if (!normalize_ip_address(ip, entry.ip, sizeof(entry.ip)))
			continue;
		snprintf(entry.mac, sizeof(entry.mac), "%s", mac);
		snprintf(entry.ifname, sizeof(entry.ifname), "%s", ifname);
		derive_zone_from_ifname(ifname, entry.zone, sizeof(entry.zone));
		if (!identity_entry_allowed_by_collected_interface(&entry, filter))
			continue;
		entries[count++] = entry;
	}

	fclose(file);
	return count;
}

size_t load_arp_table(struct arp_entry *entries, size_t max_entries,
		      struct json_object *warnings)
{
	return load_arp_table_filtered(entries, max_entries, warnings, NULL);
}

struct neigh_dump_ctx {
	struct arp_entry *entries;
	size_t max_entries;
	size_t count;
	const struct lan_identity_filter *filter;
};

struct neighbor_attr_table {
	struct nlattr **tb;
	uint16_t max;
};

static bool add_neighbor_entry(struct arp_entry *entries, size_t *count,
			       size_t max_entries, const char *ip,
			       const char *mac, const char *ifname,
			       const struct lan_identity_filter *filter)
{
	struct arp_entry entry;
	size_t i;

	if (!entries || !count || *count >= max_entries || !ip || !mac || !ifname)
		return false;
	if (!valid_mac_address(mac) || ifname_is_excluded_identity_source(ifname))
		return false;
	memset(&entry, 0, sizeof(entry));
	if (!normalize_ip_address(ip, entry.ip, sizeof(entry.ip)))
		return false;
	snprintf(entry.mac, sizeof(entry.mac), "%s", mac);
	normalize_mac_address(entry.mac);
	snprintf(entry.ifname, sizeof(entry.ifname), "%s", ifname);
	derive_zone_from_ifname(ifname, entry.zone, sizeof(entry.zone));
	if (!identity_entry_allowed_by_collected_interface(&entry, filter))
		return true;

	for (i = 0; i < *count; i++) {
		if (!strcmp(entries[i].ip, entry.ip))
			return true;
	}

	entries[*count] = entry;
	(*count)++;
	return true;
}

static int neighbor_attr_cb(const struct nlattr *attr, void *data)
{
	struct neighbor_attr_table *table = data;
	uint16_t type = mnl_attr_get_type(attr);

	type &= NLA_TYPE_MASK;
	if (type <= table->max)
		table->tb[type] = (struct nlattr *)attr;
	return MNL_CB_OK;
}

static int neighbor_netlink_data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct neigh_dump_ctx *ctx = data;
	struct nlattr *tb[NDA_MAX + 1];
	struct neighbor_attr_table table = { tb, NDA_MAX };
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	char ip[IP_STR_LEN];
	char mac[MAC_STR_LEN];
	char ifname[IFNAME_STR_LEN];
	const void *dst;
	const unsigned char *lladdr;

	if (nlh->nlmsg_type != RTM_NEWNEIGH)
		return MNL_CB_OK;
	if (!ctx || ctx->count >= ctx->max_entries)
		return MNL_CB_OK;
	if (!ndm || ndm->ndm_family != AF_INET6 || ndm->ndm_ifindex <= 0)
		return MNL_CB_OK;
	if (ndm->ndm_state == NUD_FAILED || ndm->ndm_state == NUD_NONE ||
	    ndm->ndm_state == NUD_NOARP)
		return MNL_CB_OK;

	memset(tb, 0, sizeof(tb));
	if (mnl_attr_parse(nlh, sizeof(*ndm), neighbor_attr_cb, &table) < 0)
		return MNL_CB_OK;
	if (!tb[NDA_DST] || !tb[NDA_LLADDR])
		return MNL_CB_OK;
	if (mnl_attr_get_payload_len(tb[NDA_DST]) < sizeof(struct in6_addr) ||
	    mnl_attr_get_payload_len(tb[NDA_LLADDR]) < 6)
		return MNL_CB_OK;

	dst = mnl_attr_get_payload(tb[NDA_DST]);
	if (!inet_ntop(AF_INET6, dst, ip, sizeof(ip)))
		return MNL_CB_OK;
	lladdr = mnl_attr_get_payload(tb[NDA_LLADDR]);
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 lladdr[0], lladdr[1], lladdr[2],
		 lladdr[3], lladdr[4], lladdr[5]);
	if (!if_indextoname((unsigned int)ndm->ndm_ifindex, ifname))
		snprintf(ifname, sizeof(ifname), "if%d", ndm->ndm_ifindex);

	add_neighbor_entry(ctx->entries, &ctx->count, ctx->max_entries,
			   ip, mac, ifname, ctx->filter);
	return MNL_CB_OK;
}

static bool read_neighbor_table_filtered(struct arp_entry *entries, size_t *count,
					 size_t max_entries,
					 const struct lan_identity_filter *filter)
{
	char sndbuf[MNL_SOCKET_BUFFER_SIZE];
	char rcvbuf[MNL_SOCKET_DUMP_SIZE];
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	struct neigh_dump_ctx dump_ctx;
	unsigned int seq = (unsigned int)time(NULL);
	unsigned int portid;
	ssize_t ret;
	int cb_ret = MNL_CB_OK;

	if (!entries || !count || *count >= max_entries)
		return false;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl)
		return false;
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(nl);
		return false;
	}
	portid = mnl_socket_get_portid(nl);

	memset(sndbuf, 0, sizeof(sndbuf));
	nlh = mnl_nlmsg_put_header(sndbuf);
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
	memset(ndm, 0, sizeof(*ndm));
	ndm->ndm_family = AF_INET6;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		mnl_socket_close(nl);
		return false;
	}

	memset(&dump_ctx, 0, sizeof(dump_ctx));
	dump_ctx.entries = entries;
	dump_ctx.max_entries = max_entries;
	dump_ctx.count = *count;
	dump_ctx.filter = filter;

	while ((ret = mnl_socket_recvfrom(nl, rcvbuf, sizeof(rcvbuf))) > 0) {
		cb_ret = mnl_cb_run(rcvbuf, (size_t)ret, seq, portid,
				    neighbor_netlink_data_cb, &dump_ctx);
		if (cb_ret <= MNL_CB_STOP)
			break;
	}

	mnl_socket_close(nl);
	if (ret < 0 || cb_ret < 0)
		return false;

	*count = dump_ctx.count;
	return true;
}

bool read_neighbor_table(struct arp_entry *entries, size_t *count,
			 size_t max_entries)
{
	return read_neighbor_table_filtered(entries, count, max_entries, NULL);
}

size_t load_lan_identity_table(struct arp_entry *entries, size_t max_entries,
			       struct json_object *warnings)
{
	struct lan_identity_filter filter;
	size_t count;

	load_lan_identity_filter(&filter);
	count = load_arp_table_filtered(entries, max_entries, warnings, &filter);
	(void)read_neighbor_table_filtered(entries, &count, max_entries, &filter);
	return count;
}

const struct arp_entry *find_arp_entry(const struct arp_entry *entries,
				       size_t count, const char *ip)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcmp(entries[i].ip, ip))
			return &entries[i];
	}

	return NULL;
}

const struct arp_entry *find_lan_identity_by_mac(const struct arp_entry *entries,
						 size_t count, const char *mac)
{
	char normalized_mac[MAC_STR_LEN];
	size_t i;

	if (!entries || !valid_mac_address(mac))
		return NULL;

	snprintf(normalized_mac, sizeof(normalized_mac), "%s", mac);
	normalize_mac_address(normalized_mac);

	for (i = 0; i < count; i++) {
		if (!strcmp(entries[i].mac, normalized_mac))
			return &entries[i];
	}

	return NULL;
}

bool flow_endpoint_lookup(const struct arp_entry *entries, size_t count,
			  const char *ip, enum flow_endpoint_role role,
			  struct flow_lan_endpoint *endpoint)
{
	char normalized_ip[IP_STR_LEN];
	const struct arp_entry *arp;

	if (endpoint) {
		memset(endpoint, 0, sizeof(*endpoint));
		endpoint->role = role;
	}
	if (!entries || !ip || !ip[0])
		return false;
	if (!normalize_ip_address(ip, normalized_ip, sizeof(normalized_ip)))
		return false;

	arp = find_arp_entry(entries, count, normalized_ip);
	if (!arp)
		return false;
	if (endpoint) {
		endpoint->arp = arp;
		endpoint->matched = true;
	}
	return true;
}

bool nss_ecm_direct_endpoint_lookup(const struct arp_entry *entries,
				    size_t count, const char *ip,
				    const char *nat_ip, const char *mac,
				    enum flow_endpoint_role role,
				    struct flow_lan_endpoint *endpoint)
{
	const struct arp_entry *arp;

	if (flow_endpoint_lookup(entries, count, ip, role, endpoint))
		return true;
	if (flow_endpoint_lookup(entries, count, nat_ip, role, endpoint))
		return true;

	arp = find_lan_identity_by_mac(entries, count, mac);
	if (!arp)
		return false;

	if (endpoint) {
		memset(endpoint, 0, sizeof(*endpoint));
		endpoint->role = role;
		endpoint->arp = arp;
		endpoint->matched = true;
	}
	return true;
}
