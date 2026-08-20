// SPDX-License-Identifier: GPL-2.0-only

#include <linux/if.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <net/sch_generic.h>

#include <nss_api_if.h>
#include <nss_dynamic_interface.h>
#include <nss_if.h>
#include <nss_igs.h>

#include "lanspeed_nss_control.h"

static int lanspeed_netdev_event(struct notifier_block *notifier,
				unsigned long event, void *data);

static struct notifier_block lanspeed_netdev_notifier = {
	.notifier_call = lanspeed_netdev_event,
};

struct lanspeed_igs_entry *lanspeed_igs_find(const char *name)
{
	struct lanspeed_igs_entry *entry;

	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (!strcmp(entry->dev->name, name))
			return entry;
	}
	return NULL;
}

struct lanspeed_igs_entry *lanspeed_igs_find_edge(struct net_device *edge)
{
	struct lanspeed_igs_entry *entry;

	list_for_each_entry(entry, &lanspeed_igs_entries, list) {
		if (entry->edge == edge)
			return entry;
	}
	return NULL;
}

int lanspeed_ifname(const char *value, char name[IFNAMSIZ])
{
	size_t length = strcspn(value, "\n");

	if (!length || length >= IFNAMSIZ ||
	    (value[length] && (value[length] != '\n' || value[length + 1])))
		return -EINVAL;
	memcpy(name, value, length);
	name[length] = '\0';
	return 0;
}

int lanspeed_pair(const char *value, char ifb[IFNAMSIZ],
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
	lanspeed_telemetry_igs_sync(dev, node->tx_bytes, node->tx_packets,
				    sync->igs_stats.tx_dropped);
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

void lanspeed_igs_unregister(struct lanspeed_igs_entry *entry)
{
	nss_igs_unregister_if(entry->if_num);
	nss_dynamic_interface_dealloc_node(entry->if_num,
					   NSS_DYNAMIC_INTERFACE_TYPE_IGS);
	list_del_rcu(&entry->list);
	synchronize_rcu();
	dev_put(entry->dev);
	if (entry->edge)
		dev_put(entry->edge);
	kfree(entry);
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
	lanspeed_telemetry_control_event();
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
	/* A Wi-Fi station may disappear between the last peer_sync and a
	 * transaction teardown. NSS then rejects the per-peer reset because the
	 * station no longer exists, although the IGS edge itself is still fully
	 * reclaimable. Do not strand the edge in PUBLISHED/DEGRADED state for that
	 * stale peer: forget the cached bindings and continue the ordered edge
	 * reset/IGS clear below. */
	if (lanspeed_peer_config_reset(entry)) {
		entry->peer_count = 0;
		lanspeed_telemetry_peer_reset();
	}
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
	if (!lanspeed_edge_del(entry->edge)) {
		entry->state = LANSPEED_IGS_DEGRADED;
		return -ENOMEM;
	}
	dev_put(entry->edge);
	entry->edge = NULL;
	entry->state = LANSPEED_IGS_STAGED;
	lanspeed_telemetry_control_event();
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
	if (!lanspeed_edge_del(entry->edge))
		return;
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
	entry->dev = dev;
	entry->if_num = if_num;
	entry->state = LANSPEED_IGS_STAGED;
	atomic64_set(&entry->stats_last_sync_ns, 0);
	atomic64_set(&entry->stats_bytes, 0);
	atomic64_set(&entry->stats_packets, 0);
	atomic64_set(&entry->stats_drops, 0);
	if (!nss_igs_register_if(if_num, NSS_DYNAMIC_INTERFACE_TYPE_IGS,
				 lanspeed_igs_event, dev, 0)) {
		nss_dynamic_interface_dealloc_node(if_num,
					   NSS_DYNAMIC_INTERFACE_TYPE_IGS);
		kfree(entry);
		dev_put(dev);
		error = -EIO;
		goto out;
	}
	list_add_tail_rcu(&entry->list, &lanspeed_igs_entries);
	lanspeed_telemetry_control_event();
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
	lanspeed_telemetry_control_event();
	error = 0;
out:
	mutex_unlock(&lanspeed_igs_lock);
	rtnl_unlock();
	return error;
}

int lanspeed_igs_stage(const char *value)
{
	return lanspeed_stage_set(value, NULL);
}

int lanspeed_igs_publish(const char *value)
{
	return lanspeed_publish_set(value, NULL);
}

int lanspeed_igs_unpublish(const char *value)
{
	return lanspeed_unpublish_set(value, NULL);
}

int lanspeed_igs_delete(const char *value)
{
	return lanspeed_unstage_set(value, NULL);
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
int lanspeed_igs_register_notifier(void)
{
	return register_netdevice_notifier(&lanspeed_netdev_notifier);
}

void lanspeed_igs_unregister_notifier(void)
{
	unregister_netdevice_notifier(&lanspeed_netdev_notifier);
}

void lanspeed_igs_cleanup(void)
{
	struct lanspeed_igs_entry *entry, *next;

	mutex_lock(&lanspeed_igs_lock);
	list_for_each_entry_safe(entry, next, &lanspeed_igs_entries, list) {
		if (entry->state != LANSPEED_IGS_STAGED)
			lanspeed_igs_unpublish_entry(entry);
		if (entry->state == LANSPEED_IGS_STAGED)
			lanspeed_igs_unregister(entry);
	}
	mutex_unlock(&lanspeed_igs_lock);
}
