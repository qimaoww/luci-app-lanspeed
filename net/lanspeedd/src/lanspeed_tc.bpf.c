// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

/* LAN client cardinality: each client takes two entries (tx and rx).
 * 2048 keys ≈ 1024 distinct MAC+zone clients, which covers large homes
 * with VLANs, guest SSIDs and many IoT devices.  Override with
 * -DLANSPEED_MAX_CLIENTS=N at build time if needed. */
#ifndef LANSPEED_MAX_CLIENTS
#define LANSPEED_MAX_CLIENTS 2048
#endif
#define LANSPEED_DIR_TX 1
#define LANSPEED_DIR_RX 2

struct lanspeed_key {
	__u32 ifindex;
	__u16 vlan_or_zone;
	__u8 direction;
	__u8 reserved;
	__u8 mac[ETH_ALEN];
};

struct lanspeed_counters {
	__u64 bytes;
	__u64 packets;
	__u64 last_seen;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LANSPEED_MAX_CLIENTS);
	__type(key, struct lanspeed_key);
	__type(value, struct lanspeed_counters);
} lanspeed_clients SEC(".maps");

static __always_inline int account_frame(struct __sk_buff *skb, __u8 direction)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct lanspeed_counters initial = {};
	struct lanspeed_counters *counters;
	struct lanspeed_key key = {};

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	key.ifindex = skb->ifindex;
	key.vlan_or_zone = skb->vlan_tci & 0x0fff;
	key.direction = direction;
	if (direction == LANSPEED_DIR_TX)
		__builtin_memcpy(key.mac, eth->h_source, ETH_ALEN);
	else
		__builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);

	counters = bpf_map_lookup_elem(&lanspeed_clients, &key);
	if (!counters) {
		initial.bytes = skb->len;
		initial.packets = 1;
		initial.last_seen = bpf_ktime_get_ns();
		if (bpf_map_update_elem(&lanspeed_clients, &key, &initial, BPF_NOEXIST))
			return TC_ACT_OK;
		return TC_ACT_OK;
	}

	__sync_fetch_and_add(&counters->bytes, skb->len);
	__sync_fetch_and_add(&counters->packets, 1);
	counters->last_seen = bpf_ktime_get_ns();

	return TC_ACT_OK;
}

SEC("tc/ingress")
int lanspeed_ingress(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_TX);
}

SEC("tc/egress")
int lanspeed_egress(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_RX);
}

char LICENSE[] SEC("license") = "Apache-2.0";
