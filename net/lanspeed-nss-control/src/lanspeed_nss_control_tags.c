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

struct lanspeed_client_tag_table {
	struct rcu_head rcu;
	u16 count;
	u16 v4_count;
	u16 v6_count;
	struct lanspeed_tag_address v4_addresses[LANSPEED_MAX_TAG_ADDRESSES];
	struct lanspeed_tag_address v6_addresses[LANSPEED_MAX_TAG_ADDRESSES];
};

struct lanspeed_local_prefix_table {
	struct rcu_head rcu;
	u16 count;
	u16 v4_count;
	u16 v6_count;
	struct lanspeed_local_prefix v4_prefixes[LANSPEED_MAX_LOCAL_PREFIXES];
	struct lanspeed_local_prefix v6_prefixes[LANSPEED_MAX_LOCAL_PREFIXES];
};

static struct lanspeed_client_tag_table lanspeed_empty_client_tags;
static struct lanspeed_local_prefix_table lanspeed_empty_local_prefixes;
static struct lanspeed_client_tag_table __rcu *lanspeed_client_tags =
	&lanspeed_empty_client_tags;
static struct lanspeed_local_prefix_table __rcu *lanspeed_local_prefixes =
	&lanspeed_empty_local_prefixes;
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
				      const struct lanspeed_local_prefix_table *table)
{
	u16 index;

	for (index = 0; index < table->v4_count; index++) {
		const struct lanspeed_local_prefix *prefix = &table->v4_prefixes[index];

		if (lanspeed_v4_prefix_equal(address, prefix->address.v4,
					     prefix->length))
			return true;
	}
	return false;
}

static bool lanspeed_local_v6(const struct in6_addr *address,
				      const struct lanspeed_local_prefix_table *table)
{
	u16 index;

	for (index = 0; index < table->v6_count; index++) {
		const struct lanspeed_local_prefix *prefix = &table->v6_prefixes[index];

		if (ipv6_prefix_equal(address, &prefix->address.v6, prefix->length))
			return true;
	}
	return false;
}

static u16 lanspeed_tag_v4(__be32 address,
			   const struct lanspeed_client_tag_table *table)
{
	u16 first = 0;
	u16 last = table->v4_count;

	while (first < last) {
		u16 middle = first + (last - first) / 2;
		const struct lanspeed_tag_address *entry =
			&table->v4_addresses[middle];

		if (ntohl(entry->address.v4) < ntohl(address))
			first = middle + 1;
		else
			last = middle;
	}
	if (first < table->v4_count &&
	    table->v4_addresses[first].address.v4 == address)
		return table->v4_addresses[first].qos_tag;
	return 0;
}

static u16 lanspeed_tag_v6(const struct in6_addr *address,
			   const struct lanspeed_client_tag_table *table)
{
	u16 first = 0;
	u16 last = table->v6_count;

	while (first < last) {
		u16 middle = first + (last - first) / 2;
		const struct lanspeed_tag_address *entry =
			&table->v6_addresses[middle];

		if (memcmp(entry->address.v6.s6_addr, address->s6_addr,
			   sizeof(address->s6_addr)) < 0)
			first = middle + 1;
		else
			last = middle;
	}
	if (first < table->v6_count &&
	    ipv6_addr_equal(&table->v6_addresses[first].address.v6, address))
		return table->v6_addresses[first].qos_tag;
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
	const struct lanspeed_client_tag_table *clients;
	const struct lanspeed_local_prefix_table *prefixes;
	u16 qos_tag = 0;

	if (!state->in || !lanspeed_trusted_ingress_contains(state->in))
		return NF_ACCEPT;

	rcu_read_lock();
	clients = rcu_dereference(lanspeed_client_tags);
	prefixes = rcu_dereference(lanspeed_local_prefixes);
	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ip_hdr(skb);
		if (!lanspeed_local_v4(header->daddr, prefixes))
			qos_tag = lanspeed_tag_v4(header->saddr, clients);
	} else if (state->pf == NFPROTO_IPV6) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ipv6_hdr(skb);
		if (!lanspeed_local_v6(&header->daddr, prefixes))
			qos_tag = lanspeed_tag_v6(&header->saddr, clients);
	}
unlock:
	rcu_read_unlock();
	lanspeed_apply_qos_tag(skb, qos_tag);
	return NF_ACCEPT;
}

static unsigned int lanspeed_bridge_tag_hook(void *priv, struct sk_buff *skb,
					     const struct nf_hook_state *state)
{
	const struct lanspeed_client_tag_table *clients;
	const struct lanspeed_local_prefix_table *prefixes;
	__be16 protocol;
	u16 qos_tag = 0;

	/* Only dynamically published LAN edges may establish client identity.
	 * This keeps spoofed client addresses arriving from WAN out of the tag
	 * path while allowing the actual Wi-Fi and wired NSS ingress edges.
	 */
	if (!state->in || !lanspeed_trusted_ingress_contains(state->in))
		return NF_ACCEPT;

	rcu_read_lock();
	clients = rcu_dereference(lanspeed_client_tags);
	prefixes = rcu_dereference(lanspeed_local_prefixes);
	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP)) {
		const struct iphdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ip_hdr(skb);
		if (!lanspeed_local_v4(header->daddr, prefixes))
			qos_tag = lanspeed_tag_v4(header->saddr, clients);
	} else if (protocol == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *header;

		if (!pskb_network_may_pull(skb, sizeof(*header)))
			goto unlock;
		header = ipv6_hdr(skb);
		if (!lanspeed_local_v6(&header->daddr, prefixes))
			qos_tag = lanspeed_tag_v6(&header->saddr, clients);
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

static int lanspeed_tag_v4_insert(struct lanspeed_client_tag_table *table,
					  const struct lanspeed_tag_address *entry)
{
	u16 first = 0;
	u16 last = table->v4_count;

	while (first < last) {
		u16 middle = first + (last - first) / 2;
		if (ntohl(table->v4_addresses[middle].address.v4) <
		    ntohl(entry->address.v4))
			first = middle + 1;
		else
			last = middle;
	}
	if (first < table->v4_count &&
	    table->v4_addresses[first].address.v4 == entry->address.v4)
		return -EEXIST;
	if (table->v4_count >= LANSPEED_MAX_TAG_ADDRESSES)
		return -ENOSPC;
	memmove(&table->v4_addresses[first + 1], &table->v4_addresses[first],
		(table->v4_count - first) * sizeof(table->v4_addresses[0]));
	table->v4_addresses[first] = *entry;
	table->v4_count++;
	table->count++;
	return 0;
}

static int lanspeed_tag_v6_insert(struct lanspeed_client_tag_table *table,
					  const struct lanspeed_tag_address *entry)
{
	u16 first = 0;
	u16 last = table->v6_count;

	while (first < last) {
		u16 middle = first + (last - first) / 2;
		if (memcmp(table->v6_addresses[middle].address.v6.s6_addr,
			   entry->address.v6.s6_addr,
			   sizeof(entry->address.v6.s6_addr)) < 0)
			first = middle + 1;
		else
			last = middle;
	}
	if (first < table->v6_count &&
	    ipv6_addr_equal(&table->v6_addresses[first].address.v6,
				&entry->address.v6))
		return -EEXIST;
	if (table->v6_count >= LANSPEED_MAX_TAG_ADDRESSES)
		return -ENOSPC;
	memmove(&table->v6_addresses[first + 1], &table->v6_addresses[first],
		(table->v6_count - first) * sizeof(table->v6_addresses[0]));
	table->v6_addresses[first] = *entry;
	table->v6_count++;
	table->count++;
	return 0;
}

static int lanspeed_prefix_v4_insert(struct lanspeed_local_prefix_table *table,
					     const struct lanspeed_local_prefix *prefix)
{
	u16 index;

	for (index = 0; index < table->v4_count; index++) {
		const struct lanspeed_local_prefix *existing = &table->v4_prefixes[index];

		if (existing->length == prefix->length &&
		    existing->address.v4 == prefix->address.v4)
			return -EEXIST;
	}
	if (table->v4_count >= LANSPEED_MAX_LOCAL_PREFIXES)
		return -ENOSPC;
	table->v4_prefixes[table->v4_count++] = *prefix;
	table->count++;
	return 0;
}

static int lanspeed_prefix_v6_insert(struct lanspeed_local_prefix_table *table,
					     const struct lanspeed_local_prefix *prefix)
{
	u16 index;

	for (index = 0; index < table->v6_count; index++) {
		const struct lanspeed_local_prefix *existing = &table->v6_prefixes[index];

		if (existing->length == prefix->length &&
		    ipv6_addr_equal(&existing->address.v6, &prefix->address.v6))
			return -EEXIST;
	}
	if (table->v6_count >= LANSPEED_MAX_LOCAL_PREFIXES)
		return -ENOSPC;
	table->v6_prefixes[table->v6_count++] = *prefix;
	table->count++;
	return 0;
}

static int lanspeed_tag_record(struct lanspeed_client_tag_table *clients,
				       struct lanspeed_local_prefix_table *prefixes,
				       char *record)
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
		if (clients->count >= LANSPEED_MAX_TAG_ADDRESSES ||
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
		return address.family == AF_INET
			? lanspeed_tag_v4_insert(clients, &address)
			: lanspeed_tag_v6_insert(clients, &address);
	}
	if (strcmp(kind, "L4") && strcmp(kind, "L6"))
		return -EINVAL;
	if (prefixes->count >= LANSPEED_MAX_LOCAL_PREFIXES ||
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
	return prefix.family == AF_INET
		? lanspeed_prefix_v4_insert(prefixes, &prefix)
		: lanspeed_prefix_v6_insert(prefixes, &prefix);
}

static void lanspeed_client_tag_table_free(struct rcu_head *rcu)
{
	struct lanspeed_client_tag_table *table;

	table = container_of(rcu, struct lanspeed_client_tag_table, rcu);
	kfree(table);
}

static void lanspeed_local_prefix_table_free(struct rcu_head *rcu)
{
	struct lanspeed_local_prefix_table *table;

	table = container_of(rcu, struct lanspeed_local_prefix_table, rcu);
	kfree(table);
}

static int lanspeed_tag_config_set(const char *value,
				    const struct kernel_param *kp)
{
	struct lanspeed_client_tag_table *old_clients;
	struct lanspeed_local_prefix_table *old_prefixes;
	struct lanspeed_client_tag_table *clients = NULL;
	struct lanspeed_local_prefix_table *prefixes = NULL;
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
	clients = kzalloc(sizeof(*clients), GFP_KERNEL);
	prefixes = kzalloc(sizeof(*prefixes), GFP_KERNEL);
	if (!clients || !prefixes) {
		error = -ENOMEM;
		goto free_tables;
	}
	while (cursor) {
		record = strsep(&cursor, ";");
		if (!record || !*record ||
		    lanspeed_tag_record(clients, prefixes, record)) {
			error = -EINVAL;
			goto free_tables;
		}
	}
	mutex_lock(&lanspeed_tag_update_lock);
	old_clients = rcu_dereference_protected(lanspeed_client_tags,
					lockdep_is_held(&lanspeed_tag_update_lock));
	old_prefixes = rcu_dereference_protected(lanspeed_local_prefixes,
					lockdep_is_held(&lanspeed_tag_update_lock));
	rcu_assign_pointer(lanspeed_client_tags, clients);
	rcu_assign_pointer(lanspeed_local_prefixes, prefixes);
	mutex_unlock(&lanspeed_tag_update_lock);
	if (old_clients != &lanspeed_empty_client_tags)
		call_rcu(&old_clients->rcu, lanspeed_client_tag_table_free);
	if (old_prefixes != &lanspeed_empty_local_prefixes)
		call_rcu(&old_prefixes->rcu, lanspeed_local_prefix_table_free);
	clients = NULL;
	prefixes = NULL;
	goto free_tables;
free_tables:
	kfree(clients);
	kfree(prefixes);
free_input:
	kfree(input);
	return error;
}

int lanspeed_tag_replace(const char *value)
{
	return lanspeed_tag_config_set(value, NULL);
}

static int lanspeed_tag_config_get(char *buffer, const struct kernel_param *kp)
{
	const struct lanspeed_client_tag_table *clients;
	const struct lanspeed_local_prefix_table *prefixes;
	int length = 0;
	u16 index;

	rcu_read_lock();
	clients = rcu_dereference(lanspeed_client_tags);
	prefixes = rcu_dereference(lanspeed_local_prefixes);
	length += scnprintf(buffer + length, PAGE_SIZE - length, "v1");
	for (index = 0; index < prefixes->v4_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_local_prefix *prefix = &prefixes->v4_prefixes[index];

		length += scnprintf(buffer + length, PAGE_SIZE - length,
				    ";L4,%pI4,%u", &prefix->address.v4,
				    prefix->length);
	}
	for (index = 0; index < prefixes->v6_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_local_prefix *prefix = &prefixes->v6_prefixes[index];

		length += scnprintf(buffer + length, PAGE_SIZE - length,
				    ";L6,%pI6c,%u", &prefix->address.v6,
				    prefix->length);
	}
	for (index = 0; index < clients->v4_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_tag_address *address = &clients->v4_addresses[index];

		length += scnprintf(buffer + length, PAGE_SIZE - length,
				    ";C4,%pI4,%u", &address->address.v4,
				    address->qos_tag);
	}
	for (index = 0; index < clients->v6_count && length < PAGE_SIZE - 1; index++) {
		const struct lanspeed_tag_address *address = &clients->v6_addresses[index];

		length += scnprintf(buffer + length, PAGE_SIZE - length,
				    ";C6,%pI6c,%u", &address->address.v6,
				    address->qos_tag);
	}
	length += scnprintf(buffer + length, PAGE_SIZE - length, "\n");
	rcu_read_unlock();
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
	struct lanspeed_client_tag_table *old_clients;
	struct lanspeed_local_prefix_table *old_prefixes;

	nf_unregister_net_hooks(&init_net, lanspeed_tag_hooks,
				ARRAY_SIZE(lanspeed_tag_hooks));
	mutex_lock(&lanspeed_tag_update_lock);
	old_clients = rcu_dereference_protected(lanspeed_client_tags,
					lockdep_is_held(&lanspeed_tag_update_lock));
	old_prefixes = rcu_dereference_protected(lanspeed_local_prefixes,
					lockdep_is_held(&lanspeed_tag_update_lock));
	rcu_assign_pointer(lanspeed_client_tags, &lanspeed_empty_client_tags);
	rcu_assign_pointer(lanspeed_local_prefixes, &lanspeed_empty_local_prefixes);
	mutex_unlock(&lanspeed_tag_update_lock);
	if (old_clients != &lanspeed_empty_client_tags)
		call_rcu(&old_clients->rcu, lanspeed_client_tag_table_free);
	if (old_prefixes != &lanspeed_empty_local_prefixes)
		call_rcu(&old_prefixes->rcu, lanspeed_local_prefix_table_free);
}
