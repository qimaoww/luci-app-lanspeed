// SPDX-License-Identifier: GPL-2.0-only

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <nss_api_if.h>
#include <nss_dynamic_interface.h>
#include <nss_if.h>
#include <nss_igs.h>

#include "lanspeed_nss_control.h"

/*
 * NSS VAPs use the Wi-Fi vdev nexthop message, not the generic interface
 * message used by wired edges.  Detect the dynamic type from the driver's
 * Wi-Fi context so edge selection stays dynamic and covers every VAP name.
 */
bool lanspeed_edge_is_vap(int32_t edge_if_num)
{
	return nss_dynamic_interface_get_type(nss_wifili_get_context(),
					      edge_if_num) == NSS_DYNAMIC_INTERFACE_TYPE_VAP;
}
static nss_tx_status_t lanspeed_wifi_set_nexthop(int32_t edge_if_num,
						  int32_t igs_if_num)
{
	struct nss_wifi_vdev_msg *message;
	struct lanspeed_ack_txn *txn;
	nss_tx_status_t status;

	message = kzalloc(sizeof(*message), GFP_KERNEL);
	if (!message)
		return NSS_TX_FAILURE;
	txn = lanspeed_ack_alloc();
	if (!txn) {
		kfree(message);
		return NSS_TX_FAILURE;
	}
	lanspeed_ack_bind_message(txn, message);
	message->msg.next_hop.ifnumber = igs_if_num;
	nss_cmn_msg_init(&message->cm, edge_if_num,
			 NSS_WIFI_VDEV_SET_NEXT_HOP,
			 sizeof(message->msg.next_hop),
			 lanspeed_ack_callback, txn);
	status = nss_wifi_vdev_tx_msg(nss_wifili_get_context(), message);
	if (status != NSS_TX_SUCCESS) {
		lanspeed_ack_abort(txn);
		status = NSS_TX_FAILURE;
	} else if (lanspeed_ack_wait(txn)) {
		status = NSS_TX_FAILURE;
	}
	lanspeed_ack_put(txn);
	return status;
}

nss_tx_status_t lanspeed_wifi_set_peer_nexthop(int32_t edge_if_num,
						       const u8 peer[ETH_ALEN],
						       int32_t next_hop_if_num)
{
	struct nss_wifi_vdev_set_peer_next_hop_msg *next_hop;
	struct nss_wifi_vdev_msg *message;
	struct lanspeed_ack_txn *txn;
	nss_tx_status_t status;

	message = kzalloc(sizeof(*message), GFP_KERNEL);
	if (!message)
		return NSS_TX_FAILURE;
	txn = lanspeed_ack_alloc();
	if (!txn) {
		kfree(message);
		return NSS_TX_FAILURE;
	}
	lanspeed_ack_bind_message(txn, message);
	next_hop = &message->msg.vdev_set_peer_next_hp;
	ether_addr_copy(next_hop->peer_mac_addr, peer);
	next_hop->if_num = next_hop_if_num;
	nss_cmn_msg_init(&message->cm, edge_if_num,
			 NSS_WIFI_VDEV_SET_PEER_NEXT_HOP,
			 sizeof(*next_hop), lanspeed_ack_callback, txn);
	status = nss_wifi_vdev_tx_msg(nss_wifili_get_context(), message);
	if (status != NSS_TX_SUCCESS) {
		lanspeed_ack_abort(txn);
		status = NSS_TX_FAILURE;
	} else if (lanspeed_ack_wait(txn)) {
		status = NSS_TX_FAILURE;
	}
	lanspeed_ack_put(txn);
	return status;
}

nss_tx_status_t lanspeed_set_nexthop(int32_t edge_if_num,
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

nss_tx_status_t lanspeed_reset_nexthop(int32_t edge_if_num)
{
	if (lanspeed_edge_is_vap(edge_if_num))
		return nss_if_reset_nexthop(nss_wifili_get_context(), edge_if_num);
	return nss_if_reset_nexthop(nss_igs_get_context(), edge_if_num);
}

int lanspeed_igs_config(struct net_device *edge, u32 type,
				       int32_t igs_num)
{
	struct nss_if_msg *message;
	struct lanspeed_ack_txn *txn;
	int32_t edge_if_num;
	nss_tx_status_t status;

	edge_if_num = nss_cmn_get_interface_number_by_dev(edge);
	if (edge_if_num < 0)
		return -ENODEV;
	txn = lanspeed_ack_alloc();
	if (!txn)
		return -ENOMEM;
	message = kzalloc(sizeof(*message), GFP_KERNEL);
	if (!message) {
		lanspeed_ack_abort(txn);
		lanspeed_ack_put(txn);
		return -ENOMEM;
	}
	lanspeed_ack_bind_message(txn, message);
	/* nss_cmn_msg_sync_init leaves the callback NULL.  NSS therefore never
	 * completes its wait for SET/CLEAR_IGS_NODE.  Use the same callback-driven
	 * synchronous transaction as the vendor nssmirred IFB helper. */
	nss_cmn_msg_init(&message->cm, edge_if_num, type,
			 sizeof(struct nss_if_igs_config),
			 lanspeed_ack_callback, txn);
	message->msg.config_igs.igs_num = igs_num;
	status = nss_if_tx_msg(nss_igs_get_context(), message);
	if (status != NSS_TX_SUCCESS) {
		lanspeed_ack_abort(txn);
		lanspeed_ack_put(txn);
		return -EIO;
	}
	status = lanspeed_ack_wait(txn);
	if (status) {
		lanspeed_ack_put(txn);
		return status;
	}
	lanspeed_ack_put(txn);
	return 0;
}
