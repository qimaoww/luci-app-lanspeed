/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LANSPEED_NSS_CONTROL_H
#define __LANSPEED_NSS_CONTROL_H

#include <linux/atomic.h>
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
#define LANSPEED_MAX_IGS 64
#define LANSPEED_MAX_CLIENT_TAGS 64

#define LANSPEED_NSS_GENL_NAME "LANSPEED_NSS"
#define LANSPEED_NSS_GENL_VERSION 1

enum lanspeed_nss_genl_command {
	LANSPEED_NSS_CMD_UNSPEC,
	LANSPEED_NSS_CMD_GET_CAPS,
	LANSPEED_NSS_CMD_GET_STATE,
	LANSPEED_NSS_CMD_GET_STATS,
	LANSPEED_NSS_CMD_GET_HEALTH,
	LANSPEED_NSS_CMD_IGS_STAGE,
	LANSPEED_NSS_CMD_IGS_PUBLISH,
	LANSPEED_NSS_CMD_IGS_UNPUBLISH,
	LANSPEED_NSS_CMD_IGS_DELETE,
	LANSPEED_NSS_CMD_PEER_REPLACE,
	LANSPEED_NSS_CMD_TAG_REPLACE,
	LANSPEED_NSS_CMD_TRUSTED_INGRESS_REPLACE,
	__LANSPEED_NSS_CMD_MAX,
};

#define LANSPEED_NSS_CMD_MAX (__LANSPEED_NSS_CMD_MAX - 1)

enum lanspeed_nss_genl_attribute {
	LANSPEED_NSS_A_UNSPEC,
	LANSPEED_NSS_A_ABI_VERSION,
	LANSPEED_NSS_A_FEATURE_BITS,
	LANSPEED_NSS_A_MAX_IGS,
	LANSPEED_NSS_A_MAX_PEERS,
	LANSPEED_NSS_A_MAX_CLIENT_TAGS,
	LANSPEED_NSS_A_SUPPORTS_WIFI_PEER,
	LANSPEED_NSS_A_SUPPORTS_IGS_STATS,
	LANSPEED_NSS_A_SUPPORTS_PEER_QUERY,
	LANSPEED_NSS_A_IGS_STAGED,
	LANSPEED_NSS_A_IGS_PUBLISHED,
	LANSPEED_NSS_A_IGS_DEGRADED,
	LANSPEED_NSS_A_CONTROL_GENERATION,
	LANSPEED_NSS_A_HARDWARE_GENERATION,
	LANSPEED_NSS_A_PEER_GENERATION,
	LANSPEED_NSS_A_IGS_SYNC_COUNT,
	LANSPEED_NSS_A_IGS_LAST_SYNC_NS,
	LANSPEED_NSS_A_IGS_BYTES,
	LANSPEED_NSS_A_IGS_PACKETS,
	LANSPEED_NSS_A_IGS_DROPS,
	LANSPEED_NSS_A_ACK_LATENCY_LAST_NS,
	LANSPEED_NSS_A_ACK_LATENCY_MAX_NS,
	LANSPEED_NSS_A_ACK_RECEIVED,
	LANSPEED_NSS_A_ACK_TIMEOUT,
	LANSPEED_NSS_A_ACK_LATE,
	LANSPEED_NSS_A_HEALTHY,
	LANSPEED_NSS_A_PEER_REASSERT_COUNT,
	LANSPEED_NSS_A_IFB_NAME,
	LANSPEED_NSS_A_EDGE_NAME,
	LANSPEED_NSS_A_CONFIG,
	LANSPEED_NSS_A_IGS_CADENCE_SAMPLES,
	LANSPEED_NSS_A_IGS_CADENCE_LAST_NS,
	LANSPEED_NSS_A_IGS_CADENCE_MIN_NS,
	LANSPEED_NSS_A_IGS_CADENCE_MAX_NS,
	LANSPEED_NSS_A_IGS_ACTIVE_NODES,
	__LANSPEED_NSS_A_MAX,
};

#define LANSPEED_NSS_A_MAX (__LANSPEED_NSS_A_MAX - 1)

#define LANSPEED_NSS_FEATURE_IGS (1U << 0)
#define LANSPEED_NSS_FEATURE_WIFI_PEER (1U << 1)
#define LANSPEED_NSS_FEATURE_IGS_STATS (1U << 2)
#define LANSPEED_NSS_FEATURE_PEER_QUERY (1U << 3)
#define LANSPEED_NSS_FEATURE_RCU_TAGS (1U << 4)
#define LANSPEED_NSS_FEATURE_TRUSTED_INGRESS (1U << 5)
#define LANSPEED_NSS_FEATURE_IGS_CADENCE (1U << 6)

struct lanspeed_telemetry_snapshot {
	u64 igs_sync_count;
	u64 igs_last_sync_ns;
	u64 igs_bytes;
	u64 igs_packets;
	u64 igs_drops;
	u64 igs_cadence_samples;
	u64 igs_cadence_last_ns;
	u64 igs_cadence_min_ns;
	u64 igs_cadence_max_ns;
	u32 igs_active_nodes;
	u64 peer_generation;
	u64 peer_reassert_count;
	u64 ack_latency_last_ns;
	u64 ack_latency_max_ns;
	u64 ack_received;
	u64 ack_timeout;
	u64 ack_late;
	u64 control_generation;
	u64 hardware_generation;
};

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
	atomic64_t stats_last_sync_ns;
	atomic64_t stats_bytes;
	atomic64_t stats_packets;
	atomic64_t stats_drops;
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

void lanspeed_telemetry_igs_sync(struct net_device *dev,
				 u64 bytes, u64 packets, u64 drops);
void lanspeed_telemetry_peer_apply(u16 count);
void lanspeed_telemetry_peer_reset(void);
void lanspeed_telemetry_control_event(void);
void lanspeed_telemetry_snapshot(struct lanspeed_telemetry_snapshot *snapshot);
int lanspeed_telemetry_get(char *buffer, const struct kernel_param *kp);
int lanspeed_telemetry_cadence_get(char *buffer,
				   const struct kernel_param *kp);

int lanspeed_igs_stage(const char *value);
int lanspeed_igs_publish(const char *value);
int lanspeed_igs_unpublish(const char *value);
int lanspeed_igs_delete(const char *value);
int lanspeed_peer_replace(const char *value);
int lanspeed_tag_replace(const char *value);
int lanspeed_trusted_ingress_replace(const char *value);

int lanspeed_genl_register(void);
void lanspeed_genl_unregister(void);

int lanspeed_tag_register(void);
void lanspeed_tag_unregister(void);
bool lanspeed_edge_published(struct net_device *edge);
bool lanspeed_trusted_ingress_contains(struct net_device *edge);
bool lanspeed_edge_add(struct net_device *edge);
bool lanspeed_edge_del(struct net_device *edge);
void lanspeed_published_edges_cleanup(void);
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
