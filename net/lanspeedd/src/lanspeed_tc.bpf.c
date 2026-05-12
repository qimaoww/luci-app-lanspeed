// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* LAN client cardinality: each client takes two entries (tx and rx).
 * 2048 keys ≈ 1024 distinct MAC+zone clients, which covers large homes
 * with VLANs, guest SSIDs and many IoT devices.  Override with
 * -DLANSPEED_MAX_CLIENTS=N at build time if needed. */
#ifndef LANSPEED_MAX_CLIENTS
#define LANSPEED_MAX_CLIENTS 2048
#endif
#define LANSPEED_DIR_TX 1
#define LANSPEED_DIR_RX 2

/* Max tracked unique connections for dedup */
#ifndef LANSPEED_MAX_CONN_TUPLES
#define LANSPEED_MAX_CONN_TUPLES 8192
#endif

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
	__u32 tcp_conns;
	__u32 udp_conns;
};

/* Key for connection dedup map: identifies a unique conntrack tuple */
struct lanspeed_conn_key {
	__u8 mac[ETH_ALEN];
	__u8 proto;
	__u8 family;       /* AF_INET=2, AF_INET6=10 */
	__be16 sport;
	__be16 dport;
	__u8 dst_ip[16];   /* IPv4 in first 4 bytes, rest zero */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LANSPEED_MAX_CLIENTS);
	__type(key, struct lanspeed_key);
	__type(value, struct lanspeed_counters);
} lanspeed_clients SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LANSPEED_MAX_CONN_TUPLES);
	__type(key, struct lanspeed_conn_key);
	__type(value, __u8);
} lanspeed_seen_conns SEC(".maps");

/* kfunc declarations for conntrack lookup (Linux 6.1+) */
struct nf_conn;

struct bpf_ct_opts___local {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
};

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *,
					 struct bpf_sock_tuple *, __u32,
					 struct bpf_ct_opts___local *, __u32) __ksym __weak;
extern void bpf_ct_release(struct nf_conn *) __ksym __weak;

static __always_inline void try_count_connection(struct __sk_buff *skb,
						 struct lanspeed_counters *counters,
						 __u8 *src_mac, void *data,
						 void *data_end,
						 struct ethhdr *eth)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_ct_opts___local opts = { .netns_id = -1 };
	struct lanspeed_conn_key conn_key = {};
	struct nf_conn *ct;
	__u16 eth_proto;
	__u8 l4proto = 0;
	__u32 tuple_sz;
	__u8 dummy = 1;

	/* bpf_skb_ct_lookup may not be available on older kernels */
	if (!bpf_skb_ct_lookup)
		return;

	eth_proto = bpf_ntohs(eth->h_proto);

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end)
			return;
		l4proto = iph->protocol;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			return;

		tuple.ipv4.saddr = iph->saddr;
		tuple.ipv4.daddr = iph->daddr;
		tuple_sz = sizeof(tuple.ipv4);

		if (l4proto == IPPROTO_TCP) {
			struct tcphdr *th = (void *)iph + (iph->ihl * 4);
			if ((void *)(th + 1) > data_end)
				return;
			tuple.ipv4.sport = th->source;
			tuple.ipv4.dport = th->dest;
		} else {
			struct udphdr *uh = (void *)iph + (iph->ihl * 4);
			if ((void *)(uh + 1) > data_end)
				return;
			tuple.ipv4.sport = uh->source;
			tuple.ipv4.dport = uh->dest;
		}

		/* Build conn_key for dedup */
		__builtin_memcpy(conn_key.mac, src_mac, ETH_ALEN);
		conn_key.proto = l4proto;
		conn_key.family = 2; /* AF_INET */
		conn_key.sport = tuple.ipv4.sport;
		conn_key.dport = tuple.ipv4.dport;
		__builtin_memcpy(conn_key.dst_ip, &iph->daddr, 4);

	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end)
			return;
		l4proto = ip6h->nexthdr;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			return;

		__builtin_memcpy(tuple.ipv6.saddr, &ip6h->saddr, 16);
		__builtin_memcpy(tuple.ipv6.daddr, &ip6h->daddr, 16);
		tuple_sz = sizeof(tuple.ipv6);

		if (l4proto == IPPROTO_TCP) {
			struct tcphdr *th = (void *)(ip6h + 1);
			if ((void *)(th + 1) > data_end)
				return;
			tuple.ipv6.sport = th->source;
			tuple.ipv6.dport = th->dest;
		} else {
			struct udphdr *uh = (void *)(ip6h + 1);
			if ((void *)(uh + 1) > data_end)
				return;
			tuple.ipv6.sport = uh->source;
			tuple.ipv6.dport = uh->dest;
		}

		/* Build conn_key for dedup */
		__builtin_memcpy(conn_key.mac, src_mac, ETH_ALEN);
		conn_key.proto = l4proto;
		conn_key.family = 10; /* AF_INET6 */
		conn_key.sport = tuple.ipv6.sport;
		conn_key.dport = tuple.ipv6.dport;
		__builtin_memcpy(conn_key.dst_ip, &ip6h->daddr, 16);
	} else {
		return;
	}

	/* Check if we already counted this connection */
	if (bpf_map_lookup_elem(&lanspeed_seen_conns, &conn_key))
		return;

	/* Do conntrack lookup to verify it's a real tracked connection */
	opts.l4proto = l4proto;
	ct = bpf_skb_ct_lookup(skb, &tuple, tuple_sz, &opts, sizeof(opts));
	if (!ct)
		return;

	/* For TCP: only count ESTABLISHED (status bit IP_CT_ESTABLISHED = 3,
	 * but we simplify: if ct_lookup succeeds for TCP, the connection is
	 * tracked and active enough to count). */
	bpf_ct_release(ct);

	/* Mark as seen and increment counter */
	bpf_map_update_elem(&lanspeed_seen_conns, &conn_key, &dummy, BPF_NOEXIST);

	if (l4proto == IPPROTO_TCP)
		__sync_fetch_and_add(&counters->tcp_conns, 1);
	else
		__sync_fetch_and_add(&counters->udp_conns, 1);
}

static __always_inline int account_frame(struct __sk_buff *skb, __u8 direction,
					 int action)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct lanspeed_counters initial = {};
	struct lanspeed_counters *counters;
	struct lanspeed_key key = {};

	if ((void *)(eth + 1) > data_end)
		return action;

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
			return action;
		counters = bpf_map_lookup_elem(&lanspeed_clients, &key);
		if (!counters)
			return action;
	} else {
		__sync_fetch_and_add(&counters->bytes, skb->len);
		__sync_fetch_and_add(&counters->packets, 1);
		counters->last_seen = bpf_ktime_get_ns();
	}

	/* Only count connections on ingress (TX = client-originated packets)
	 * to avoid double-counting the same connection on both directions. */
	if (direction == LANSPEED_DIR_TX)
		try_count_connection(skb, counters, key.mac, data, data_end, eth);

	return action;
}

SEC("tc/ingress")
int lanspeed_ingress(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_TX, TC_ACT_OK);
}

SEC("tc/egress")
int lanspeed_egress(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_RX, TC_ACT_OK);
}

SEC("tc")
int lanspeed_ingress_early(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_TX, TC_ACT_UNSPEC);
}

SEC("tc")
int lanspeed_egress_early(struct __sk_buff *skb)
{
	return account_frame(skb, LANSPEED_DIR_RX, TC_ACT_UNSPEC);
}

char LICENSE[] SEC("license") = "Apache-2.0";
