// SPDX-License-Identifier: GPL-2.0-only

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <nss_api_if.h>
#include <nss_dynamic_interface.h>
#include <nss_if.h>

#include "lanspeed_nss_control.h"

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

int lanspeed_peer_config_parse(const char *value,
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

int lanspeed_peer_config_apply(struct lanspeed_igs_entry *entry,
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
	lanspeed_telemetry_peer_apply(desired->count);
	return 0;
}

int lanspeed_peer_config_reset(struct lanspeed_igs_entry *entry)
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
	lanspeed_telemetry_peer_reset();
	return 0;
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

int lanspeed_peer_replace(const char *value)
{
	return lanspeed_peer_sync_set(value, NULL);
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

static const struct kernel_param_ops lanspeed_peer_sync_ops = {
	.set = lanspeed_peer_sync_set,
};
static const struct kernel_param_ops lanspeed_peer_status_ops = {
	.get = lanspeed_peer_status_get,
};
module_param_cb(peer_sync, &lanspeed_peer_sync_ops, NULL, 0200);
MODULE_PARM_DESC(peer_sync, "Atomically rebind LAN Speed-owned Wi-Fi peers to an IGS node");
module_param_cb(peer_status, &lanspeed_peer_status_ops, NULL, 0400);
MODULE_PARM_DESC(peer_status, "List LAN Speed-owned Wi-Fi peer nexthop bindings");
