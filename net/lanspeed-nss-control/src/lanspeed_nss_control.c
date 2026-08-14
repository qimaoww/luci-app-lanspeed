// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stage and publish a LAN Speed-owned IFB as a QCA NSS ingress-shaper node.
 * Userspace builds and verifies NSSHTB before this module atomically publishes
 * the physical-interface or Wi-Fi peer nexthop. Keeping the NSS transaction here
 * avoids the half-published window in the vendor nssmirred action. Rate policy and client
 * identity stay in lanspeedd; this module only owns the NSS redirect lifecycle.
 */

#include <linux/if.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_dscpremark_ext.h>
#include <net/sch_generic.h>
#include <nss_api_if.h>
#include <nss_dynamic_interface.h>
#include <nss_if.h>
#include <nss_igs.h>

enum lanspeed_igs_state {
	LANSPEED_IGS_STAGED,
	LANSPEED_IGS_PUBLISHED,
	/* SET_IGS_NODE succeeded, but the nexthop is not currently active. */
	LANSPEED_IGS_DEGRADED,
};

#define LANSPEED_MAX_WIFI_PEERS 64

struct lanspeed_igs_entry {
	struct list_head list;
	struct net_device *dev;
	struct net_device *edge;
	int if_num;
	enum lanspeed_igs_state state;
	u16 peer_count;
	u8 peers[LANSPEED_MAX_WIFI_PEERS][ETH_ALEN];
};

#define LANSPEED_MAX_TAG_ADDRESSES 64
#define LANSPEED_MAX_LOCAL_PREFIXES 64
#define LANSPEED_MAX_EDGE_DEVICES 64

struct lanspeed_tag_address {
	u8 family;
	union {
		__be32 v4;
		struct in6_addr v6;
	} address;
	u16 qos_tag;
};

struct lanspeed_local_prefix {
	u8 family;
	u8 length;
	union {
		__be32 v4;
		struct in6_addr v6;
	} address;
};

struct lanspeed_tag_config {
	u16 address_count;
	u16 prefix_count;
	struct lanspeed_tag_address addresses[LANSPEED_MAX_TAG_ADDRESSES];
	struct lanspeed_local_prefix prefixes[LANSPEED_MAX_LOCAL_PREFIXES];
};

struct lanspeed_peer_config {
	char ifb[IFNAMSIZ];
	u16 count;
	u8 peers[LANSPEED_MAX_WIFI_PEERS][ETH_ALEN];
};

static LIST_HEAD(lanspeed_igs_entries);
static DEFINE_MUTEX(lanspeed_igs_lock);
static DECLARE_COMPLETION(lanspeed_igs_completion);
static enum nss_cmn_response lanspeed_igs_response;
static DECLARE_COMPLETION(lanspeed_wifi_completion);
static enum nss_cmn_response lanspeed_wifi_response;
static DEFINE_SPINLOCK(lanspeed_tag_lock);
static struct lanspeed_tag_config lanspeed_tags;
static struct net_device *lanspeed_edges[LANSPEED_MAX_EDGE_DEVICES];
static u16 lanspeed_edge_count;

static struct lanspeed_igs_entry *lanspeed_igs_find_edge(struct net_device *edge);

/*
 * NSS VAPs use the Wi-Fi vdev nexthop message, not the generic interface
 * message used by wired edges.  Detect the dynamic type from the driver's
 * Wi-Fi context so edge selection stays dynamic and covers every VAP name.
 */
static bool lanspeed_edge_is_vap(int32_t edge_if_num)
{
	return nss_dynamic_interface_get_type(nss_wifili_get_context(),
					      edge_if_num) == NSS_DYNAMIC_INTERFACE_TYPE_VAP;
}

static void lanspeed_wifi_callback(void *app_data, struct nss_cmn_msg *message)
{
	lanspeed_wifi_response = message->response;
	complete(&lanspeed_wifi_completion);
}

static nss_tx_status_t lanspeed_wifi_set_nexthop(int32_t edge_if_num,
						  int32_t igs_if_num)
{
	struct nss_wifi_vdev_msg *message;
	nss_tx_status_t status;

	message = kzalloc(sizeof(*message), GFP_KERNEL);
	if (!message)
		return NSS_TX_FAILURE;
	message->msg.next_hop.ifnumber = igs_if_num;
	reinit_completion(&lanspeed_wifi_completion);
	lanspeed_wifi_response = NSS_CMN_RESPONSE_LAST;
	nss_cmn_msg_init(&message->cm, edge_if_num,
			 NSS_WIFI_VDEV_SET_NEXT_HOP,
			 sizeof(message->msg.next_hop),
			 lanspeed_wifi_callback, NULL);
	status = nss_wifi_vdev_tx_msg(nss_wifili_get_context(), message);
	if (status == NSS_TX_SUCCESS &&
	    !wait_for_completion_timeout(&lanspeed_wifi_completion,
					 msecs_to_jiffies(NSS_IF_TX_TIMEOUT)))
		status = NSS_TX_FAILURE;
	if (status == NSS_TX_SUCCESS &&
	    lanspeed_wifi_response != NSS_CMN_RESPONSE_ACK)
		status = NSS_TX_FAILURE;
	kfree(message);
	return status;
}

static nss_tx_status_t lanspeed_wifi_set_peer_nexthop(int32_t edge_if_num,
						       const u8 peer[ETH_ALEN],
						       int32_t next_hop_if_num)
{
	struct nss_wifi_vdev_set_peer_next_hop_msg *next_hop;
	struct nss_wifi_vdev_msg *message;
	nss_tx_status_t status;

	message = kzalloc(sizeof(*message), GFP_KERNEL);
	if (!message)
		return NSS_TX_FAILURE;
	next_hop = &message->msg.vdev_set_peer_next_hp;
	ether_addr_copy(next_hop->peer_mac_addr, peer);
	next_hop->if_num = next_hop_if_num;
	reinit_completion(&lanspeed_wifi_completion);
	lanspeed_wifi_response = NSS_CMN_RESPONSE_LAST;
	nss_cmn_msg_init(&message->cm, edge_if_num,
			 NSS_WIFI_VDEV_SET_PEER_NEXT_HOP,
			 sizeof(*next_hop), lanspeed_wifi_callback, NULL);
	status = nss_wifi_vdev_tx_msg(nss_wifili_get_context(), message);
	if (status == NSS_TX_SUCCESS &&
	    !wait_for_completion_timeout(&lanspeed_wifi_completion,
					 msecs_to_jiffies(NSS_IF_TX_TIMEOUT)))
		status = NSS_TX_FAILURE;
	if (status == NSS_TX_SUCCESS &&
	    lanspeed_wifi_response != NSS_CMN_RESPONSE_ACK)
		status = NSS_TX_FAILURE;
	kfree(message);
	return status;
}

static nss_tx_status_t lanspeed_set_nexthop(int32_t edge_if_num,
					    int32_t igs_if_num)
{
	if (lanspeed_edge_is_vap(edge_if_num)) {
		/* Keep the VAP default path unchanged. Only peers selected by
		 * peer_sync may enter the LAN Speed IGS node; sending the IGS
		 * interface here would redirect every station on the VAP. */
		return lanspeed_wifi_set_nexthop(edge_if_num, NSS_ETH_RX_INTERFACE);
	}
	return nss_if_set_nexthop(nss_igs_get_context(), edge_if_num, igs_if_num);
}

static nss_tx_status_t lanspeed_reset_nexthop(int32_t edge_if_num)
{
	if (lanspeed_edge_is_vap(edge_if_num))
		return nss_if_reset_nexthop(nss_wifili_get_context(), edge_if_num);
	return nss_if_reset_nexthop(nss_igs_get_context(), edge_if_num);
}

static bool lanspeed_edge_add(struct net_device *edge)
{
	u16 index;

	spin_lock_bh(&lanspeed_tag_lock);
	for (index = 0; index < lanspeed_edge_count; index++) {
		if (lanspeed_edges[index] == edge) {
			spin_unlock_bh(&lanspeed_tag_lock);
			return true;
		}
	}
	if (lanspeed_edge_count >= LANSPEED_MAX_EDGE_DEVICES) {
		spin_unlock_bh(&lanspeed_tag_lock);
		return false;
	}
	lanspeed_edges[lanspeed_edge_count++] = edge;
	spin_unlock_bh(&lanspeed_tag_lock);
	return true;
}

static void lanspeed_edge_del(struct net_device *edge)
{
	u16 index;

	spin_lock_bh(&lanspeed_tag_lock);
	for (index = 0; index < lanspeed_edge_count; index++) {
		if (lanspeed_edges[index] != edge)
			continue;
		lanspeed_edges[index] = lanspeed_edges[--lanspeed_edge_count];
		break;
	}
	spin_unlock_bh(&lanspeed_tag_lock);
}

static bool lanspeed_edge_published(struct net_device *edge)
{
	u16 index;
	bool found = false;

	spin_lock_bh(&lanspeed_tag_lock);
	for (index = 0; index < lanspeed_edge_count; index++) {
		if (lanspeed_edges[index] == edge) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&lanspeed_tag_lock);
	return found;
}

static int lanspeed_netdev_event(struct notifier_block *notifier,
				unsigned long event, void *data);

static struct notifier_block lanspeed_netdev_notifier = {
	.notifier_call = lanspeed_netdev_event,
};

static bool lanspeed_v4_prefix_equal(__be32 address, __be32 network, u8 length)
{
	__be32 mask;

	if (!length)
		return true;
	mask = htonl(~0U << (32 - length));
	return (address & mask) == (network & mask);
}

static bool lanspeed_local_v4(__be32 address,
			      const struct lanspeed_tag_config *config)
{
	u16 index;

	for (index = 0; index < config->prefix_count; index++) {
		const struct lanspeed_local_prefix *prefix = &config->prefixes[index];

		if (prefix->family == AF_INET &&
		    lanspeed_v4_prefix_equal(address, prefix->address.v4,
					     prefix->length))
			return true;
	}
	return false;
}

static bool lanspeed_local_v6(const struct in6_addr *address,
			      const struct lanspeed_tag_config *config)
{
	u16 index;

	for (index = 0; index < config->prefix_count; index++) {
		const struct lanspeed_local_prefix *prefix = &config->prefixes[index];

		if (prefix->family == AF_INET6 &&
		    ipv6_prefix_equal(address, &prefix->address.v6, prefix->length))
			return true;
	}
	return false;
}

static u16 lanspeed_tag_v4(__be32 address,
			   const struct lanspeed_tag_config *config)
{
	u16 index;

	for (index = 0; index < config->address_count; index++) {
		const struct lanspeed_tag_address *entry = &config->addresses[index];

		if (entry->family == AF_INET && entry->address.v4 == address)
			return entry->qos_tag;
	}
	return 0;
}

static u16 lanspeed_tag_v6(const struct in6_addr *address,
			   const struct lanspeed_tag_config *config)
{
	u16 index;

	for (index = 0; index < config->address_count; index++) {
		const struct lanspeed_tag_address *entry = &config->addresses[index];

		if (entry->family == AF_INET6 &&
		    ipv6_addr_equal(&entry->address.v6, address))
			return entry->qos_tag;
	}
	return 0;
}

static void lanspeed_apply_qos_tag(struct sk_buff *skb, u16 qos_tag)
{
	struct nf_ct_dscpremark_ext *extension;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	if (!qos_tag)
		return;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return;
	extension = nf_ct_dscpremark_ext_find(ct);
	if (!extension)
		return;
	spin_lock_bh(&ct->lock);
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
		extension->igs_flow_qos_tag = qos_tag;
	else
		extension->igs_reply_qos_tag = qos_tag;
	spin_unlock_bh(&ct->lock);
}

static unsigned int lanspeed_tag_hook(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	u16 qos_tag = 0;

	spin_lock_bh(&lanspeed_tag_lock);
	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ip_hdr(skb);
		if (!lanspeed_local_v4(header->daddr, &lanspeed_tags))
			qos_tag = lanspeed_tag_v4(header->saddr, &lanspeed_tags);
	} else if (state->pf == NFPROTO_IPV6) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ipv6_hdr(skb);
		if (!lanspeed_local_v6(&header->daddr, &lanspeed_tags))
			qos_tag = lanspeed_tag_v6(&header->saddr, &lanspeed_tags);
	}
unlock:
	spin_unlock_bh(&lanspeed_tag_lock);
	lanspeed_apply_qos_tag(skb, qos_tag);
	return NF_ACCEPT;
}

static unsigned int lanspeed_bridge_tag_hook(void *priv, struct sk_buff *skb,
					     const struct nf_hook_state *state)
{
	__be16 protocol;
	u16 qos_tag = 0;

	/* Only dynamically published LAN edges may establish client identity.
	 * This keeps spoofed client addresses arriving from WAN out of the tag
	 * path while allowing the actual Wi-Fi and wired NSS ingress edges.
	 */
	if (!state->in || !lanspeed_edge_published(state->in))
		return NF_ACCEPT;

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP)) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			return NF_ACCEPT;
		header = ip_hdr(skb);
		spin_lock_bh(&lanspeed_tag_lock);
		if (!lanspeed_local_v4(header->daddr, &lanspeed_tags))
			qos_tag = lanspeed_tag_v4(header->saddr, &lanspeed_tags);
		spin_unlock_bh(&lanspeed_tag_lock);
	} else if (protocol == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			return NF_ACCEPT;
		header = ipv6_hdr(skb);
		spin_lock_bh(&lanspeed_tag_lock);
		if (!lanspeed_local_v6(&header->daddr, &lanspeed_tags))
			qos_tag = lanspeed_tag_v6(&header->saddr, &lanspeed_tags);
		spin_unlock_bh(&lanspeed_tag_lock);
	}

	lanspeed_apply_qos_tag(skb, qos_tag);
	return NF_ACCEPT;
}

static struct nf_hook_ops lanspeed_tag_hooks[] = {
	{
		.hook = lanspeed_tag_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 2,
	},
	{
		.hook = lanspeed_tag_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 2,
	},
	{
		.hook = lanspeed_bridge_tag_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 2,
	},
};

static struct lanspeed_igs_entry *lanspeed_igs_find(const char *name)
{
	struct lanspeed_igs_entry *entry;

	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (!strcmp(entry->dev->name, name))
			return entry;
	}
	return NULL;
}

static struct lanspeed_igs_entry *lanspeed_igs_find_edge(struct net_device *edge)
{
	struct lanspeed_igs_entry *entry;

	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (entry->edge == edge)
			return entry;
	}
	return NULL;
}

static int lanspeed_ifname(const char *value, char name[IFNAMSIZ])
{
	size_t length = strcspn(value, "\n");

	if (!length || length >= IFNAMSIZ ||
	    (value[length] && (value[length] != '\n' || value[length + 1])))
		return -EINVAL;
	memcpy(name, value, length);
	name[length] = '\0';
	return 0;
}

static void lanspeed_igs_config_callback(void *app_data,
					struct nss_if_msg *message)
{
	lanspeed_igs_response = message->cm.response;
	complete(&lanspeed_igs_completion);
}

static int lanspeed_pair(const char *value, char ifb[IFNAMSIZ],
			  char edge[IFNAMSIZ])
{
	char input[IFNAMSIZ * 2 + 2];
	char *cursor = input;
	char *ifb_name;
	char *edge_name;
	size_t length;

	length = strnlen(value, sizeof(input));
	if (!length || length >= sizeof(input))
		return -EINVAL;
	memcpy(input, value, length);
	input[length] = '\0';
	if (input[length - 1] == '\n')
		input[length - 1] = '\0';
	ifb_name = strsep(&cursor, " \t");
	edge_name = strsep(&cursor, " \t");
	if (!ifb_name || !edge_name || !*ifb_name || !*edge_name || cursor ||
	    strpbrk(edge_name, " \t\n"))
		return -EINVAL;
	if (strscpy(ifb, ifb_name, IFNAMSIZ) < 0 ||
	    strscpy(edge, edge_name, IFNAMSIZ) < 0)
		return -EINVAL;
	return 0;
}

static bool lanspeed_peer_contains(const u8 peers[][ETH_ALEN], u16 count,
				   const u8 peer[ETH_ALEN])
{
	u16 index;

	for (index = 0; index < count; index++) {
		if (ether_addr_equal(peers[index], peer))
			return true;
	}
	return false;
}

static int lanspeed_peer_config_parse(const char *value,
				       struct lanspeed_peer_config *config)
{
	char *input;
	char *cursor;
	char *field;
	int error = -EINVAL;

	input = kstrndup(value, PAGE_SIZE, GFP_KERNEL);
	if (!input)
		return -ENOMEM;
	cursor = strim(input);
	field = strsep(&cursor, " \t");
	if (!field || strcmp(field, "v1"))
		goto out;
	do {
		field = strsep(&cursor, " \t");
	} while (field && !*field);
	if (!field || strscpy(config->ifb, field, IFNAMSIZ) < 0)
		goto out;
	while (cursor) {
		field = strsep(&cursor, " \t");
		if (!field || !*field)
			continue;
		if (config->count >= LANSPEED_MAX_WIFI_PEERS ||
		    !mac_pton(field, config->peers[config->count]) ||
		    !is_valid_ether_addr(config->peers[config->count]) ||
		    lanspeed_peer_contains(config->peers, config->count,
					    config->peers[config->count]))
			goto out;
		config->count++;
	}
	error = 0;
out:
	kfree(input);
	return error;
}

static bool lanspeed_tag_address_duplicate(const struct lanspeed_tag_config *config,
					    const struct lanspeed_tag_address *entry)
{
	u16 index;

	for (index = 0; index < config->address_count; index++) {
		const struct lanspeed_tag_address *existing = &config->addresses[index];

		if (existing->family != entry->family)
			continue;
		if (entry->family == AF_INET && existing->address.v4 == entry->address.v4)
			return true;
		if (entry->family == AF_INET6 &&
		    ipv6_addr_equal(&existing->address.v6, &entry->address.v6))
			return true;
	}
	return false;
}

static bool lanspeed_prefix_duplicate(const struct lanspeed_tag_config *config,
				       const struct lanspeed_local_prefix *prefix)
{
	u16 index;

	for (index = 0; index < config->prefix_count; index++) {
		const struct lanspeed_local_prefix *existing = &config->prefixes[index];

		if (existing->family != prefix->family || existing->length != prefix->length)
			continue;
		if (prefix->family == AF_INET && existing->address.v4 == prefix->address.v4)
			return true;
		if (prefix->family == AF_INET6 &&
		    ipv6_addr_equal(&existing->address.v6, &prefix->address.v6))
			return true;
	}
	return false;
}

static int lanspeed_tag_record(struct lanspeed_tag_config *config, char *record)
{
	struct lanspeed_tag_address address = {};
	struct lanspeed_local_prefix prefix = {};
	char *kind;
	char *value;
	char *number;
	u16 parsed;

	kind = strsep(&record, ",");
	value = strsep(&record, ",");
	number = strsep(&record, ",");
	if (!kind || !value || !number || record || !*value || !*number)
		return -EINVAL;
	if (!strcmp(kind, "C4") || !strcmp(kind, "C6")) {
		if (config->address_count >= LANSPEED_MAX_TAG_ADDRESSES ||
		    kstrtou16(number, 10, &parsed) || !parsed)
			return -EINVAL;
		address.family = !strcmp(kind, "C4") ? AF_INET : AF_INET6;
		address.qos_tag = parsed;
		if (address.family == AF_INET) {
			if (!in4_pton(value, -1, (u8 *)&address.address.v4, -1, NULL))
				return -EINVAL;
		} else if (!in6_pton(value, -1, address.address.v6.s6_addr, -1, NULL)) {
			return -EINVAL;
		}
		if (lanspeed_tag_address_duplicate(config, &address))
			return -EINVAL;
		config->addresses[config->address_count++] = address;
		return 0;
	}
	if (strcmp(kind, "L4") && strcmp(kind, "L6"))
		return -EINVAL;
	if (config->prefix_count >= LANSPEED_MAX_LOCAL_PREFIXES ||
	    kstrtou16(number, 10, &parsed))
		return -EINVAL;
	prefix.family = !strcmp(kind, "L4") ? AF_INET : AF_INET6;
	if ((prefix.family == AF_INET && parsed > 32) ||
	    (prefix.family == AF_INET6 && parsed > 128))
		return -EINVAL;
	prefix.length = parsed;
	if (prefix.family == AF_INET) {
		if (!in4_pton(value, -1, (u8 *)&prefix.address.v4, -1, NULL))
			return -EINVAL;
	} else if (!in6_pton(value, -1, prefix.address.v6.s6_addr, -1, NULL)) {
		return -EINVAL;
	}
	if (lanspeed_prefix_duplicate(config, &prefix))
		return -EINVAL;
	config->prefixes[config->prefix_count++] = prefix;
	return 0;
}

static int lanspeed_tag_config_set(const char *value,
				    const struct kernel_param *kp)
{
	struct lanspeed_tag_config *config;
	char *input;
	char *cursor;
	char *record;
	int error = 0;

	input = kstrndup(value, PAGE_SIZE, GFP_KERNEL);
	if (!input)
		return -ENOMEM;
	cursor = strim(input);
	record = strsep(&cursor, ";");
	if (!record || strcmp(record, "v1")) {
		error = -EINVAL;
		goto free_input;
	}
	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config) {
		error = -ENOMEM;
		goto free_input;
	}
	while (cursor) {
		record = strsep(&cursor, ";");
		if (!record || !*record || lanspeed_tag_record(config, record)) {
			error = -EINVAL;
			goto free_config;
		}
	}
	spin_lock_bh(&lanspeed_tag_lock);
	lanspeed_tags = *config;
	spin_unlock_bh(&lanspeed_tag_lock);
free_config:
	kfree(config);
free_input:
	kfree(input);
	return error;
}

static int lanspeed_tag_config_get(char *buffer, const struct kernel_param *kp)
{
	struct lanspeed_tag_config *config;
	int length = 0;
	u16 index;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;
	spin_lock_bh(&lanspeed_tag_lock);
	*config = lanspeed_tags;
	spin_unlock_bh(&lanspeed_tag_lock);
	length += scnprintf(buffer + length, PAGE_SIZE - length, "v1");
	for (index = 0; index < config->prefix_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_local_prefix *prefix = &config->prefixes[index];

		if (prefix->family == AF_INET)
			length += scnprintf(buffer + length, PAGE_SIZE - length,
					    ";L4,%pI4,%u", &prefix->address.v4,
					    prefix->length);
		else
			length += scnprintf(buffer + length, PAGE_SIZE - length,
					    ";L6,%pI6c,%u", &prefix->address.v6,
					    prefix->length);
	}
	for (index = 0; index < config->address_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_tag_address *address = &config->addresses[index];

		if (address->family == AF_INET)
			length += scnprintf(buffer + length, PAGE_SIZE - length,
					    ";C4,%pI4,%u", &address->address.v4,
					    address->qos_tag);
		else
			length += scnprintf(buffer + length, PAGE_SIZE - length,
					    ";C6,%pI6c,%u", &address->address.v6,
					    address->qos_tag);
	}
	length += scnprintf(buffer + length, PAGE_SIZE - length, "\n");
	kfree(config);
	return length;
}

static void lanspeed_igs_event(void *if_ctx, struct nss_cmn_msg *message)
{
	struct net_device *dev = if_ctx;
	struct nss_igs_msg *igs = (struct nss_igs_msg *)message;
	struct nss_igs_stats_sync_msg *sync;
	struct pcpu_sw_netstats stats = {};
	struct nss_cmn_node_stats *node;

	if (!dev || message->type != NSS_IGS_MSG_SYNC_STATS)
		return;
	sync = &igs->msg.stats;
	node = &sync->node_stats;
	u64_stats_init(&stats.syncp);
	u64_stats_update_begin(&stats.syncp);
	u64_stats_set(&stats.rx_packets, node->tx_packets);
	u64_stats_set(&stats.tx_packets, node->tx_packets);
	u64_stats_set(&stats.rx_bytes, node->tx_bytes);
	u64_stats_set(&stats.tx_bytes, node->tx_bytes);
	dev->stats.rx_dropped = sync->igs_stats.tx_dropped;
	dev->stats.tx_dropped = sync->igs_stats.tx_dropped;
	u64_stats_update_end(&stats.syncp);
	ifb_update_offload_stats(dev, &stats);
}

static void lanspeed_igs_unregister(struct lanspeed_igs_entry *entry)
{
	nss_igs_unregister_if(entry->if_num);
	nss_dynamic_interface_dealloc_node(entry->if_num,
					   NSS_DYNAMIC_INTERFACE_TYPE_IGS);
	dev_put(entry->dev);
	if (entry->edge)
		dev_put(entry->edge);
	list_del(&entry->list);
	kfree(entry);
}

static int lanspeed_igs_config(struct net_device *edge, u32 type,
				       int32_t igs_num)
{
	struct nss_if_msg message;
	int32_t edge_if_num;
	nss_tx_status_t status;

	edge_if_num = nss_cmn_get_interface_number_by_dev(edge);
	if (edge_if_num < 0)
		return -ENODEV;
	/* nss_cmn_msg_sync_init leaves the callback NULL.  NSS therefore never
	 * completes its wait for SET/CLEAR_IGS_NODE.  Use the same callback-driven
	 * synchronous transaction as the vendor nssmirred IFB helper. */
	reinit_completion(&lanspeed_igs_completion);
	lanspeed_igs_response = NSS_CMN_RESPONSE_LAST;
	nss_cmn_msg_init(&message.cm, edge_if_num, type,
				 sizeof(struct nss_if_igs_config),
				 lanspeed_igs_config_callback, NULL);
	message.msg.config_igs.igs_num = igs_num;
	status = nss_if_tx_msg(nss_igs_get_context(), &message);
	if (status != NSS_TX_SUCCESS)
		return -EIO;
	if (!wait_for_completion_timeout(&lanspeed_igs_completion,
					msecs_to_jiffies(NSS_IF_TX_TIMEOUT)))
		return -ETIMEDOUT;
	if (lanspeed_igs_response != NSS_CMN_RESPONSE_ACK)
		return -EIO;
	return 0;
}

static int lanspeed_peer_config_apply(struct lanspeed_igs_entry *entry,
				       const struct lanspeed_peer_config *desired)
{
	int32_t edge_if_num;
	u16 index;
	u16 rollback;

	if (entry->state != LANSPEED_IGS_PUBLISHED || !entry->edge)
		return -EINVAL;
	edge_if_num = nss_cmn_get_interface_number_by_dev(entry->edge);
	if (edge_if_num < 0 || !lanspeed_edge_is_vap(edge_if_num))
		return -ENODEV;

	/* Reassert every desired peer even when it is cached locally. A station
	 * reconnect deletes and recreates the NSS peer without recreating the VAP
	 * netdevice, so a cached peer binding alone is not proof of ownership. */
	for (index = 0; index < desired->count; index++) {
		if (lanspeed_wifi_set_peer_nexthop(edge_if_num,
				desired->peers[index], entry->if_num) == NSS_TX_SUCCESS)
			continue;
		for (rollback = 0; rollback < index; rollback++) {
			if (!lanspeed_peer_contains(entry->peers, entry->peer_count,
						    desired->peers[rollback]))
				lanspeed_wifi_set_peer_nexthop(edge_if_num,
					desired->peers[rollback], NSS_ETH_RX_INTERFACE);
		}
		return -EIO;
	}

	for (index = 0; index < entry->peer_count; index++) {
		if (lanspeed_peer_contains(desired->peers, desired->count,
					    entry->peers[index]))
			continue;
		if (lanspeed_wifi_set_peer_nexthop(edge_if_num, entry->peers[index],
						    NSS_ETH_RX_INTERFACE) == NSS_TX_SUCCESS)
			continue;
		for (rollback = 0; rollback < entry->peer_count; rollback++)
			lanspeed_wifi_set_peer_nexthop(edge_if_num, entry->peers[rollback],
						 entry->if_num);
		for (rollback = 0; rollback < desired->count; rollback++) {
			if (!lanspeed_peer_contains(entry->peers, entry->peer_count,
						    desired->peers[rollback]))
				lanspeed_wifi_set_peer_nexthop(edge_if_num,
					desired->peers[rollback], NSS_ETH_RX_INTERFACE);
		}
		return -EIO;
	}

	entry->peer_count = desired->count;
	memcpy(entry->peers, desired->peers,
	       desired->count * sizeof(desired->peers[0]));
	return 0;
}

static int lanspeed_peer_config_reset(struct lanspeed_igs_entry *entry)
{
	int32_t edge_if_num;
	u16 index;
	bool failed = false;

	if (!entry->peer_count)
		return 0;
	if (!entry->edge)
		return -ENODEV;
	edge_if_num = nss_cmn_get_interface_number_by_dev(entry->edge);
	if (edge_if_num < 0 || !lanspeed_edge_is_vap(edge_if_num))
		return -ENODEV;
	for (index = 0; index < entry->peer_count; index++) {
		if (lanspeed_wifi_set_peer_nexthop(edge_if_num, entry->peers[index],
						    NSS_ETH_RX_INTERFACE) != NSS_TX_SUCCESS)
			failed = true;
	}
	if (failed)
		return -EIO;
	entry->peer_count = 0;
	return 0;
}

static int lanspeed_igs_publish_entry(struct lanspeed_igs_entry *entry,
					      struct net_device *edge)
{
	int error;
	nss_tx_status_t status;

	if (netif_is_ifb_dev(edge) || edge == entry->dev)
		return -EINVAL;
	if (nss_cmn_get_interface_number_by_dev(edge) < 0)
		return -ENODEV;
	error = lanspeed_igs_config(edge, NSS_IF_SET_IGS_NODE, entry->if_num);
	if (error)
		return error;
	/* Retain the edge and expose a degraded state until both messages commit. */
	entry->edge = edge;
	entry->state = LANSPEED_IGS_DEGRADED;
	status = lanspeed_set_nexthop(nss_cmn_get_interface_number_by_dev(edge),
			entry->if_num);
	if (status != NSS_TX_SUCCESS) {
		/* Clear the first message. If that fails, keep DEGRADED so a later
		 * observe/reload can retry the precise cleanup instead of claiming staged. */
		if (!lanspeed_igs_config(edge, NSS_IF_CLEAR_IGS_NODE, entry->if_num)) {
			entry->edge = NULL;
			entry->state = LANSPEED_IGS_STAGED;
		}
		return -EIO;
	}
	if (!lanspeed_edge_add(edge)) {
		lanspeed_reset_nexthop(nss_cmn_get_interface_number_by_dev(edge));
		if (!lanspeed_igs_config(edge, NSS_IF_CLEAR_IGS_NODE,
					 entry->if_num)) {
			entry->edge = NULL;
			entry->state = LANSPEED_IGS_STAGED;
			return -ENOSPC;
		}
		return -EIO;
	}
	entry->state = LANSPEED_IGS_PUBLISHED;
	return 0;
}

static int lanspeed_igs_unpublish_entry(struct lanspeed_igs_entry *entry)
{
	int32_t edge_if_num;
	int error;

	if (entry->state == LANSPEED_IGS_STAGED)
		return 0;
	if (!entry->edge)
		return -ENODEV;
	edge_if_num = nss_cmn_get_interface_number_by_dev(entry->edge);
	if (edge_if_num < 0)
		return -ENODEV;
	if (lanspeed_peer_config_reset(entry))
		return -EIO;
	if (entry->state == LANSPEED_IGS_PUBLISHED &&
	    lanspeed_reset_nexthop(edge_if_num) !=
	    NSS_TX_SUCCESS)
		return -EIO;
	error = lanspeed_igs_config(entry->edge, NSS_IF_CLEAR_IGS_NODE,
					    entry->if_num);
	if (error) {
		entry->state = LANSPEED_IGS_DEGRADED;
		return error;
	}
	lanspeed_edge_del(entry->edge);
	dev_put(entry->edge);
	entry->edge = NULL;
	entry->state = LANSPEED_IGS_STAGED;
	module_put(THIS_MODULE);
	return 0;
}

static void lanspeed_igs_forget_edge(struct lanspeed_igs_entry *entry)
{
	int32_t edge_if_num;

	if (entry->state == LANSPEED_IGS_STAGED || !entry->edge)
		return;
	edge_if_num = nss_cmn_get_interface_number_by_dev(entry->edge);
	if (edge_if_num >= 0) {
		lanspeed_peer_config_reset(entry);
		if (entry->state == LANSPEED_IGS_PUBLISHED)
			lanspeed_reset_nexthop(edge_if_num);
		lanspeed_igs_config(entry->edge, NSS_IF_CLEAR_IGS_NODE,
					    entry->if_num);
	}
	entry->peer_count = 0;
	lanspeed_edge_del(entry->edge);
	dev_put(entry->edge);
	entry->edge = NULL;
	entry->state = LANSPEED_IGS_STAGED;
	module_put(THIS_MODULE);
}

static int lanspeed_netdev_event(struct notifier_block *notifier,
				unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct lanspeed_igs_entry *entry;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (entry->edge == dev) {
			lanspeed_igs_forget_edge(entry);
			break;
		}
		if (entry->dev == dev) {
			lanspeed_igs_forget_edge(entry);
			lanspeed_igs_unregister(entry);
			break;
		}
	}
	mutex_unlock(&lanspeed_igs_lock);
	return NOTIFY_DONE;
}

static int lanspeed_stage_set(const char *value, const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	struct net_device *dev;
	char name[IFNAMSIZ];
	int if_num;
	int error;

	error = lanspeed_ifname(value, name);
	if (error)
		return error;
	mutex_lock(&lanspeed_igs_lock);
	if (lanspeed_igs_find(name)) {
		error = -EEXIST;
		goto out;
	}
	dev = dev_get_by_name(&init_net, name);
	if (!dev) {
		error = -ENODEV;
		goto out;
	}
	if (!netif_is_ifb_dev(dev)) {
		dev_put(dev);
		error = -EINVAL;
		goto out;
	}
	if (nss_cmn_get_interface_number_by_dev_and_type(
			dev, NSS_DYNAMIC_INTERFACE_TYPE_IGS) >= 0) {
		dev_put(dev);
		error = -EEXIST;
		goto out;
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		dev_put(dev);
		error = -ENOMEM;
		goto out;
	}
	if_num = nss_dynamic_interface_alloc_node(NSS_DYNAMIC_INTERFACE_TYPE_IGS);
	if (if_num < 0) {
		kfree(entry);
		dev_put(dev);
		error = -ENOSPC;
		goto out;
	}
	if (!nss_igs_register_if(if_num, NSS_DYNAMIC_INTERFACE_TYPE_IGS,
				 lanspeed_igs_event, dev, 0)) {
		nss_dynamic_interface_dealloc_node(if_num,
					   NSS_DYNAMIC_INTERFACE_TYPE_IGS);
		kfree(entry);
		dev_put(dev);
		error = -EIO;
		goto out;
	}
	entry->dev = dev;
	entry->if_num = if_num;
	entry->state = LANSPEED_IGS_STAGED;
	list_add_tail(&entry->list, &lanspeed_igs_entries);
	error = 0;
out:
	mutex_unlock(&lanspeed_igs_lock);
	return error;
}

static int lanspeed_publish_set(const char *value, const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	struct net_device *edge;
	char name[IFNAMSIZ];
	char edge_name[IFNAMSIZ];
	int error;

	error = lanspeed_pair(value, name, edge_name);
	if (error)
		return error;
	mutex_lock(&lanspeed_igs_lock);
	entry = lanspeed_igs_find(name);
	if (!entry) {
		error = -ENOENT;
		goto out;
	}
	if (entry->state == LANSPEED_IGS_PUBLISHED) {
		error = entry->edge && !strcmp(entry->edge->name, edge_name) ? 0 :
			-EEXIST;
		goto out;
	}
	edge = dev_get_by_name(&init_net, edge_name);
	if (!edge) {
		error = -ENODEV;
		goto out;
	}
	if (lanspeed_igs_find_edge(edge)) {
		dev_put(edge);
		error = -EEXIST;
		goto out;
	}
	if (!try_module_get(THIS_MODULE)) {
		dev_put(edge);
		error = -ENODEV;
		goto out;
	}
	error = lanspeed_igs_publish_entry(entry, edge);
	if (error && entry->state == LANSPEED_IGS_STAGED) {
		dev_put(edge);
		module_put(THIS_MODULE);
	}
out:
	mutex_unlock(&lanspeed_igs_lock);
	return error;
}

static int lanspeed_unpublish_set(const char *value,
				   const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	char name[IFNAMSIZ];
	int error;

	error = lanspeed_ifname(value, name);
	if (error)
		return error;
	mutex_lock(&lanspeed_igs_lock);
	entry = lanspeed_igs_find(name);
	if (!entry || entry->state == LANSPEED_IGS_STAGED) {
		error = -ENOENT;
		goto out;
	}
	error = lanspeed_igs_unpublish_entry(entry);
out:
	mutex_unlock(&lanspeed_igs_lock);
	return error;
}

static int lanspeed_unstage_set(const char *value,
				 const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	struct Qdisc *qdisc;
	unsigned int index;
	char name[IFNAMSIZ];
	int error;

	error = lanspeed_ifname(value, name);
	if (error)
		return error;
	/* Keep the IGS registration alive until qca_nss_qdisc has released its
	 * shaper and module references.  Unregistering first leaves the later
	 * netdevice teardown unable to destroy an NSS root safely. */
	rtnl_lock();
	mutex_lock(&lanspeed_igs_lock);
	entry = lanspeed_igs_find(name);
	if (!entry || entry->state != LANSPEED_IGS_STAGED) {
		error = -ENOENT;
		goto out;
	}
	/* A single-queue IFB exposes the attached root through dev->qdisc.
	 * qdisc_sleeping alone can still point at the default queue, so inspect
	 * both locations while RTNL makes the attachment inventory stable. */
	qdisc = rtnl_dereference(entry->dev->qdisc);
	if (qdisc && qdisc->handle) {
		error = -EBUSY;
		goto out;
	}
	for (index = 0; index < entry->dev->num_tx_queues; index++) {
		struct netdev_queue *queue = netdev_get_tx_queue(entry->dev, index);

		qdisc = rtnl_dereference(queue->qdisc_sleeping);

		if (qdisc && qdisc->handle) {
			error = -EBUSY;
			goto out;
		}
	}
	lanspeed_igs_unregister(entry);
	error = 0;
out:
	mutex_unlock(&lanspeed_igs_lock);
	rtnl_unlock();
	return error;
}

static int lanspeed_peer_sync_set(const char *value,
				   const struct kernel_param *kp)
{
	struct lanspeed_peer_config *config;
	struct lanspeed_igs_entry *entry;
	int error;

	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;
	error = lanspeed_peer_config_parse(value, config);
	if (error)
		goto out;
	mutex_lock(&lanspeed_igs_lock);
	entry = lanspeed_igs_find(config->ifb);
	if (!entry) {
		error = -ENOENT;
		goto unlock;
	}
	error = lanspeed_peer_config_apply(entry, config);
unlock:
	mutex_unlock(&lanspeed_igs_lock);
out:
	kfree(config);
	return error;
}

static int lanspeed_peer_status_get(char *buffer,
				     const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	int length = 0;
	u16 index;

	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		for (index = 0; index < entry->peer_count; index++) {
			length += scnprintf(buffer + length, PAGE_SIZE - length,
					    "%s %pM\n", entry->dev->name,
					    entry->peers[index]);
			if (length >= PAGE_SIZE - 1)
				goto out;
		}
	}
out:
	mutex_unlock(&lanspeed_igs_lock);
	return length;
}

static int lanspeed_status_get(char *buffer, const struct kernel_param *kp)
{
	struct lanspeed_igs_entry *entry;
	int length = 0;

	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		length += scnprintf(buffer + length, PAGE_SIZE - length,
				    "%s %s %d%s%s\n", entry->dev->name,
				    entry->state == LANSPEED_IGS_PUBLISHED ? "published" :
				    entry->state == LANSPEED_IGS_DEGRADED ? "degraded" : "staged",
				    entry->if_num, entry->edge ? " " : "",
				    entry->edge ? entry->edge->name : "");
		if (length >= PAGE_SIZE - 1)
			break;
	}
	mutex_unlock(&lanspeed_igs_lock);
	return length;
}

static const struct kernel_param_ops lanspeed_stage_ops = {
	.set = lanspeed_stage_set,
};
static const struct kernel_param_ops lanspeed_publish_ops = {
	.set = lanspeed_publish_set,
};
static const struct kernel_param_ops lanspeed_unpublish_ops = {
	.set = lanspeed_unpublish_set,
};
static const struct kernel_param_ops lanspeed_unstage_ops = {
	.set = lanspeed_unstage_set,
};
static const struct kernel_param_ops lanspeed_status_ops = {
	.get = lanspeed_status_get,
};
static const struct kernel_param_ops lanspeed_peer_sync_ops = {
	.set = lanspeed_peer_sync_set,
};
static const struct kernel_param_ops lanspeed_peer_status_ops = {
	.get = lanspeed_peer_status_get,
};
static const struct kernel_param_ops lanspeed_tag_config_ops = {
	.set = lanspeed_tag_config_set,
	.get = lanspeed_tag_config_get,
};

module_param_cb(stage, &lanspeed_stage_ops, NULL, 0200);
MODULE_PARM_DESC(stage, "Register an IFB as an unpublished NSS IGS node");
module_param_cb(publish, &lanspeed_publish_ops, NULL, 0200);
MODULE_PARM_DESC(publish, "Publish a staged IFB nexthop for an NSS edge");
module_param_cb(unpublish, &lanspeed_unpublish_ops, NULL, 0200);
MODULE_PARM_DESC(unpublish, "Reset and clear a published NSS edge nexthop");
module_param_cb(unstage, &lanspeed_unstage_ops, NULL, 0200);
MODULE_PARM_DESC(unstage, "Unregister an unpublished staged IGS node");
module_param_cb(status, &lanspeed_status_ops, NULL, 0400);
MODULE_PARM_DESC(status, "List staged, published, and degraded LAN Speed IGS nodes");
module_param_cb(peer_sync, &lanspeed_peer_sync_ops, NULL, 0200);
MODULE_PARM_DESC(peer_sync, "Atomically rebind LAN Speed-owned Wi-Fi peers to an IGS node");
module_param_cb(peer_status, &lanspeed_peer_status_ops, NULL, 0400);
MODULE_PARM_DESC(peer_status, "List LAN Speed-owned Wi-Fi peer nexthop bindings");
module_param_cb(tag_config, &lanspeed_tag_config_ops, NULL, 0600);
MODULE_PARM_DESC(tag_config, "Atomically replace LAN Speed ingress QoS tag ownership");

static int __init lanspeed_nss_control_init(void)
{
	int error;

	error = register_netdevice_notifier(&lanspeed_netdev_notifier);
	if (error)
		return error;
	error = nf_register_net_hooks(&init_net, lanspeed_tag_hooks,
				      ARRAY_SIZE(lanspeed_tag_hooks));
	if (error)
		unregister_netdevice_notifier(&lanspeed_netdev_notifier);
	return error;
}

static void __exit lanspeed_nss_control_exit(void)
{
	struct lanspeed_igs_entry *entry, *next;

	nf_unregister_net_hooks(&init_net, lanspeed_tag_hooks,
				ARRAY_SIZE(lanspeed_tag_hooks));
	unregister_netdevice_notifier(&lanspeed_netdev_notifier);
	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry_safe(entry, next, &lanspeed_igs_entries, list) {
			if (entry->state != LANSPEED_IGS_STAGED)
				lanspeed_igs_unpublish_entry(entry);
		if (entry->state == LANSPEED_IGS_STAGED)
			lanspeed_igs_unregister(entry);
	}
	mutex_unlock(&lanspeed_igs_lock);
}

module_init(lanspeed_nss_control_init);
module_exit(lanspeed_nss_control_exit);

MODULE_DESCRIPTION("LAN Speed transactional QCA NSS IGS control");
MODULE_AUTHOR("LAN Speed contributors");
MODULE_LICENSE("GPL");
