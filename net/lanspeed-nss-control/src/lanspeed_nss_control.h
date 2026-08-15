/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LANSPEED_NSS_CONTROL_H
#define __LANSPEED_NSS_CONTROL_H

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

#include <nss_api_if.h>

struct kernel_param;
struct lanspeed_ack_txn;
struct nss_cmn_msg;

#define LANSPEED_MAX_WIFI_PEERS 64

enum lanspeed_igs_state {
	LANSPEED_IGS_STAGED,
	LANSPEED_IGS_PUBLISHED,
	/* SET_IGS_NODE succeeded, but the nexthop is not currently active. */
	LANSPEED_IGS_DEGRADED,
};

struct lanspeed_igs_entry {
	struct list_head list;
	struct net_device *dev;
	struct net_device *edge;
	int if_num;
	enum lanspeed_igs_state state;
	u16 peer_count;
	u8 peers[LANSPEED_MAX_WIFI_PEERS][ETH_ALEN];
};

struct lanspeed_peer_config {
	char ifb[IFNAMSIZ];
	u16 count;
	u8 peers[LANSPEED_MAX_WIFI_PEERS][ETH_ALEN];
};

extern struct mutex lanspeed_igs_lock;
extern struct list_head lanspeed_igs_entries;

u64 lanspeed_ack_started(void);
void lanspeed_ack_complete(u64 started_ns, bool acknowledged);
void lanspeed_ack_timeout_event(void);
void lanspeed_ack_late_event(void);
int lanspeed_ack_stats_get(char *buffer, const struct kernel_param *kp);

struct lanspeed_ack_txn *lanspeed_ack_alloc(void);
void lanspeed_ack_put(struct lanspeed_ack_txn *txn);
void lanspeed_ack_bind_message(struct lanspeed_ack_txn *txn, void *message);
void lanspeed_ack_abort(struct lanspeed_ack_txn *txn);
int lanspeed_ack_wait(struct lanspeed_ack_txn *txn);
void lanspeed_ack_callback(void *app_data, struct nss_cmn_msg *message);

void lanspeed_telemetry_igs_sync(u64 bytes, u64 packets, u64 drops);
void lanspeed_telemetry_peer_apply(u16 count);
void lanspeed_telemetry_peer_reset(void);
void lanspeed_telemetry_control_event(void);
int lanspeed_telemetry_get(char *buffer, const struct kernel_param *kp);

int lanspeed_tag_register(void);
void lanspeed_tag_unregister(void);
bool lanspeed_edge_published(struct net_device *edge);
bool lanspeed_edge_add(struct net_device *edge);
bool lanspeed_edge_del(struct net_device *edge);
void lanspeed_trusted_ingress_cleanup(void);

nss_tx_status_t lanspeed_set_nexthop(int32_t edge_if_num, int32_t igs_if_num);
nss_tx_status_t lanspeed_reset_nexthop(int32_t edge_if_num);
bool lanspeed_edge_is_vap(int32_t edge_if_num);
nss_tx_status_t lanspeed_wifi_set_peer_nexthop(int32_t edge_if_num,
						const u8 peer[ETH_ALEN],
						int32_t next_hop_if_num);
int lanspeed_igs_config(struct net_device *edge, u32 type, int32_t igs_num);

struct lanspeed_igs_entry *lanspeed_igs_find(const char *name);
struct lanspeed_igs_entry *lanspeed_igs_find_edge(struct net_device *edge);
int lanspeed_ifname(const char *value, char name[IFNAMSIZ]);
int lanspeed_pair(const char *value, char ifb[IFNAMSIZ], char edge[IFNAMSIZ]);
int lanspeed_peer_config_parse(const char *value,
				       struct lanspeed_peer_config *config);
int lanspeed_peer_config_apply(struct lanspeed_igs_entry *entry,
				       const struct lanspeed_peer_config *desired);
int lanspeed_peer_config_reset(struct lanspeed_igs_entry *entry);
void lanspeed_igs_unregister(struct lanspeed_igs_entry *entry);
void lanspeed_igs_cleanup(void);
int lanspeed_igs_register_notifier(void);
void lanspeed_igs_unregister_notifier(void);

#endif
