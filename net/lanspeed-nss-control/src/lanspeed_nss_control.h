/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LANSPEED_NSS_CONTROL_H
#define __LANSPEED_NSS_CONTROL_H

#include <linux/types.h>

struct kernel_param;
struct lanspeed_ack_txn;
struct nss_cmn_msg;

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

#endif
