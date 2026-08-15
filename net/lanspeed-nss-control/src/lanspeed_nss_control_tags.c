// SPDX-License-Identifier: GPL-2.0-only

#include <linux/if_vlan.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_dscpremark_ext.h>

#include "lanspeed_nss_control.h"

#define LANSPEED_MAX_TAG_ADDRESSES 64
#define LANSPEED_MAX_LOCAL_PREFIXES 64

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
	struct rcu_head rcu;
	u16 address_count;
	u16 prefix_count;
	struct lanspeed_tag_address addresses[LANSPEED_MAX_TAG_ADDRESSES];
	struct lanspeed_local_prefix prefixes[LANSPEED_MAX_LOCAL_PREFIXES];
};

static struct lanspeed_tag_config lanspeed_empty_tags;
static struct lanspeed_tag_config __rcu *lanspeed_tags = &lanspeed_empty_tags;
static DEFINE_MUTEX(lanspeed_tag_update_lock);

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
	const struct lanspeed_tag_config *config;
	u16 qos_tag = 0;

	rcu_read_lock();
	config = rcu_dereference(lanspeed_tags);
	if (!config)
		goto unlock;
	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ip_hdr(skb);
		if (!lanspeed_local_v4(header->daddr, config))
			qos_tag = lanspeed_tag_v4(header->saddr, config);
	} else if (state->pf == NFPROTO_IPV6) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ipv6_hdr(skb);
		if (!lanspeed_local_v6(&header->daddr, config))
			qos_tag = lanspeed_tag_v6(&header->saddr, config);
	}
unlock:
	rcu_read_unlock();
	lanspeed_apply_qos_tag(skb, qos_tag);
	return NF_ACCEPT;
}

static unsigned int lanspeed_bridge_tag_hook(void *priv, struct sk_buff *skb,
					     const struct nf_hook_state *state)
{
	const struct lanspeed_tag_config *config;
	__be16 protocol;
	u16 qos_tag = 0;

	/* Only dynamically published LAN edges may establish client identity.
	 * This keeps spoofed client addresses arriving from WAN out of the tag
	 * path while allowing the actual Wi-Fi and wired NSS ingress edges.
	 */
	if (!state->in || !lanspeed_edge_published(state->in))
		return NF_ACCEPT;

	rcu_read_lock();
	config = rcu_dereference(lanspeed_tags);
	if (!config)
		goto unlock;
	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP)) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ip_hdr(skb);
		if (!lanspeed_local_v4(header->daddr, config))
			qos_tag = lanspeed_tag_v4(header->saddr, config);
	} else if (protocol == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ipv6_hdr(skb);
		if (!lanspeed_local_v6(&header->daddr, config))
			qos_tag = lanspeed_tag_v6(&header->saddr, config);
	}

	unlock:
	rcu_read_unlock();
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

static void lanspeed_tag_config_free(struct rcu_head *rcu)
{
	struct lanspeed_tag_config *config;

	config = container_of(rcu, struct lanspeed_tag_config, rcu);
	kfree(config);
}

static int lanspeed_tag_config_set(const char *value,
				    const struct kernel_param *kp)
{
	struct lanspeed_tag_config *old;
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
	mutex_lock(&lanspeed_tag_update_lock);
	old = rcu_dereference_protected(lanspeed_tags,
					lockdep_is_held(&lanspeed_tag_update_lock));
	rcu_assign_pointer(lanspeed_tags, config);
	mutex_unlock(&lanspeed_tag_update_lock);
	if (old != &lanspeed_empty_tags)
		call_rcu(&old->rcu, lanspeed_tag_config_free);
	config = NULL;
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
	rcu_read_lock();
	{
		const struct lanspeed_tag_config *active = rcu_dereference(lanspeed_tags);

		*config = *active;
	}
	rcu_read_unlock();
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

static const struct kernel_param_ops lanspeed_tag_config_ops = {
	.set = lanspeed_tag_config_set,
	.get = lanspeed_tag_config_get,
};

module_param_cb(tag_config, &lanspeed_tag_config_ops, NULL, 0600);
MODULE_PARM_DESC(tag_config, "Atomically replace LAN Speed ingress QoS tag ownership");

int lanspeed_tag_register(void)
{
	return nf_register_net_hooks(&init_net, lanspeed_tag_hooks,
				     ARRAY_SIZE(lanspeed_tag_hooks));
}

void lanspeed_tag_unregister(void)
{
	struct lanspeed_tag_config *old;

	nf_unregister_net_hooks(&init_net, lanspeed_tag_hooks,
				ARRAY_SIZE(lanspeed_tag_hooks));
	mutex_lock(&lanspeed_tag_update_lock);
	old = rcu_dereference_protected(lanspeed_tags,
					lockdep_is_held(&lanspeed_tag_update_lock));
	rcu_assign_pointer(lanspeed_tags, &lanspeed_empty_tags);
	mutex_unlock(&lanspeed_tag_update_lock);
	if (old != &lanspeed_empty_tags)
		call_rcu(&old->rcu, lanspeed_tag_config_free);
}
